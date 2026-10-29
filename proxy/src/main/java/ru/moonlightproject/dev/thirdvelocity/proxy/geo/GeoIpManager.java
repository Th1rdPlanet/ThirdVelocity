/*
 * Copyright (C) 2026 Velocity Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package ru.moonlightproject.dev.thirdvelocity.proxy.geo;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.maxmind.db.CHMCache;
import com.maxmind.db.Reader;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.YearMonth;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;
import ru.moonlightproject.dev.thirdvelocity.api.geo.DatabaseStatus;
import ru.moonlightproject.dev.thirdvelocity.api.geo.GeoInfo;
import ru.moonlightproject.dev.thirdvelocity.api.geo.GeoIpService;
import ru.moonlightproject.dev.thirdvelocity.proxy.ThirdVelocityCore;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.ConfigNode;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.Downloader;

/**
 * Local MaxMind-format databases with scheduled downloads. Database roles come from the config
 * key: {@code country}, {@code asn} and {@code city}.
 */
public final class GeoIpManager implements GeoIpService {

  private static final Logger LOGGER = LogManager.getLogger("ThirdVelocity");

  private record Source(String name, boolean enabled, String url, Downloader.Format format,
      String entrySuffix, Path file, boolean maxmindAuth) {
  }

  private static final class State {
    volatile @Nullable Reader reader;
    volatile @Nullable Instant buildTime;
    volatile long entries = -1;
    volatile @Nullable Instant lastAttempt;
    volatile @Nullable String lastError;
  }

  private final ThirdVelocityCore core;
  private final Map<String, State> states = new ConcurrentHashMap<>();
  private volatile Map<String, Source> sources = Map.of();
  private volatile boolean enabled;
  private volatile Duration updateInterval = Duration.ofDays(7);
  private volatile @Nullable String basicAuth;
  private volatile Cache<InetAddress, GeoInfo> cache = Caffeine.newBuilder().maximumSize(1).build();

  /**
   * Creates the manager.
   *
   * @param core core
   */
  public GeoIpManager(ThirdVelocityCore core) {
    this.core = core;
  }

  /**
   * Applies the {@code geoip} section and opens databases already on disk.
   *
   * @param config section
   */
  public void apply(ConfigNode config) {
    enabled = config.bool("enabled", true);
    updateInterval = config.duration("update-interval", Duration.ofDays(7));
    // Environment variables win so the key never has to be written into the config file.
    String account = firstNonBlank(System.getenv("MAXMIND_ACCOUNT_ID"), config.string("maxmind-account-id", "")).trim();
    String key = firstNonBlank(System.getenv("MAXMIND_LICENSE_KEY"), config.string("maxmind-license-key", "")).trim();
    basicAuth = account.isEmpty() || key.isEmpty() ? null : account + ":" + key;
    Path dir = core.directory().resolve(config.string("directory", "geoip"));
    Map<String, Source> parsed = new LinkedHashMap<>();
    ConfigNode databases = config.section("databases");
    for (String name : databases.keys()) {
      ConfigNode db = databases.section(name);
      if (!List.of("country", "asn", "city").contains(name)) {
        throw new ConfigNode.ConfigException("geoip.databases." + name + ": allowed names are country, asn, city");
      }
      parsed.put(name, new Source(name, db.bool("enabled", true), db.string("url", ""),
          db.enumValue("format", Downloader.Format.GZIP), db.string("archive-entry-suffix", ".mmdb"),
          dir.resolve(db.string("file", name + ".mmdb")), db.bool("maxmind-auth", false)));
    }
    sources = parsed;
    cache = Caffeine.newBuilder()
        .maximumSize(config.integer("cache-size", 50_000, 100, 10_000_000))
        .expireAfterWrite(1, TimeUnit.HOURS)
        .build();
    for (Source source : parsed.values()) {
      State state = states.computeIfAbsent(source.name(), n -> new State());
      if (!enabled || !source.enabled()) {
        swap(state, null);
        continue;
      }
      if (Files.isRegularFile(source.file())) {
        try {
          swap(state, open(source.file()));
        } catch (IOException e) {
          state.lastError = "Cannot open " + source.file() + ": " + e.getMessage();
          LOGGER.warn(ru.moonlightproject.dev.thirdvelocity.proxy.util.Ansi.line("[x] geoip    » {}"), state.lastError);
        }
      }
    }
    states.keySet().retainAll(parsed.keySet());
  }

  private static String firstNonBlank(@Nullable String first, String second) {
    return first != null && !first.isBlank() ? first : second;
  }

  private static Reader open(Path file) throws IOException {
    Reader reader = new Reader(file.toFile(), Reader.FileMode.MEMORY_MAPPED, new CHMCache());
    reader.get(InetAddress.getByName("1.1.1.1"), Map.class);
    return reader;
  }

  private void swap(State state, @Nullable Reader next) {
    Reader previous = state.reader;
    state.reader = next;
    if (next != null) {
      state.buildTime = next.getMetadata().buildTime();
      state.entries = next.getMetadata().nodeCount();
      state.lastError = null;
    } else {
      state.entries = -1;
    }
    cache.invalidateAll();
    if (previous != null && previous != next) {
      // Lookups in flight may still use the old reader; close it a bit later.
      core.scheduler().schedule(() -> {
        try {
          previous.close();
        } catch (IOException ignored) {
          // Nothing to do.
        }
      }, 30, TimeUnit.SECONDS);
    }
  }

  /**
   * Downloads databases whose file is missing or older than the update interval.
   */
  public void updateIfStale() {
    if (!enabled) {
      return;
    }
    for (Source source : sources.values()) {
      if (!source.enabled() || source.url().isBlank()) {
        continue;
      }
      if (isStale(source.file())) {
        core.worker().execute(() -> download(source));
      }
    }
  }

  private boolean isStale(Path file) {
    try {
      return !Files.isRegularFile(file)
          || Files.getLastModifiedTime(file).toInstant().isBefore(Instant.now().minus(updateInterval));
    } catch (IOException e) {
      return true;
    }
  }

  private synchronized void download(Source source) {
    State state = states.computeIfAbsent(source.name(), n -> new State());
    state.lastAttempt = Instant.now();
    String auth = source.maxmindAuth() ? basicAuth : null;
    if (source.maxmindAuth() && auth == null) {
      state.lastError = "maxmind-account-id and maxmind-license-key are not set";
      LOGGER.warn(ru.moonlightproject.dev.thirdvelocity.proxy.util.Ansi.line("[!] geoip    » {}: {}"), source.name(), state.lastError);
      return;
    }
    Path temp = source.file().resolveSibling(source.file().getFileName() + ".new");
    try {
      YearMonth month = Downloader.currentMonth();
      int status = 404;
      String url = source.url();
      // Monthly snapshots (DB-IP) appear during the month; fall back to the previous one.
      for (int back = 0; back < 3 && status == 404; back++) {
        url = Downloader.expand(source.url(), month.minusMonths(back));
        status = core.downloader().download(url, temp, source.format(), source.entrySuffix(), auth,
            512L * 1024 * 1024);
        if (!source.url().contains("{")) {
          break;
        }
      }
      if (status == 404) {
        throw new IOException("HTTP 404 for " + Downloader.redact(url));
      }
      Reader reader = open(temp);
      reader.close();
      Files.move(temp, source.file(), java.nio.file.StandardCopyOption.REPLACE_EXISTING,
          java.nio.file.StandardCopyOption.ATOMIC_MOVE);
      swap(state, open(source.file()));
      LOGGER.info(ru.moonlightproject.dev.thirdvelocity.proxy.util.Ansi.line("[+] geoip    » {} updated from {}  build:{}"), source.name(),
          Downloader.redact(url), state.buildTime);
    } catch (Exception e) {
      state.lastError = e.getMessage();
      LOGGER.warn(ru.moonlightproject.dev.thirdvelocity.proxy.util.Ansi.line("[x] geoip    » update failed for {}: {}"), source.name(), e.getMessage());
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
    } finally {
      try {
        Files.deleteIfExists(temp);
      } catch (IOException ignored) {
        // Best effort.
      }
    }
  }

  @Override
  public GeoInfo lookup(InetAddress address) {
    if (!enabled) {
      return GeoInfo.UNKNOWN;
    }
    return cache.get(address, this::resolve);
  }

  @SuppressWarnings("unchecked")
  private GeoInfo resolve(InetAddress address) {
    String countryCode = null;
    String countryName = null;
    String continent = null;
    String city = null;
    long asn = -1;
    String org = null;
    try {
      Map<String, Object> country = record("country", address);
      if (country == null) {
        country = record("city", address);
      }
      if (country != null) {
        Map<String, Object> c = (Map<String, Object>) country.get("country");
        if (c != null) {
          countryCode = (String) c.get("iso_code");
          countryName = name(c);
        }
        Map<String, Object> cont = (Map<String, Object>) country.get("continent");
        if (cont != null) {
          continent = (String) cont.get("code");
        }
      }
      Map<String, Object> cityRecord = record("city", address);
      if (cityRecord != null && cityRecord.get("city") instanceof Map<?, ?> cityMap) {
        city = name((Map<String, Object>) cityMap);
      }
      Map<String, Object> asnRecord = record("asn", address);
      if (asnRecord != null) {
        Object number = asnRecord.get("autonomous_system_number");
        if (number instanceof Number n) {
          asn = n.longValue();
        }
        org = (String) asnRecord.get("autonomous_system_organization");
      }
    } catch (IOException | ClassCastException e) {
      LOGGER.debug("GeoIP lookup failed for {}", address, e);
    }
    if (countryCode == null && city == null && asn < 0 && org == null) {
      return GeoInfo.UNKNOWN;
    }
    return new GeoInfo(countryCode, countryName, continent, city, asn, org);
  }

  @SuppressWarnings("unchecked")
  private @Nullable Map<String, Object> record(String role, InetAddress address) throws IOException {
    State state = states.get(role);
    Reader reader = state == null ? null : state.reader;
    if (reader == null) {
      return null;
    }
    return reader.get(address, Map.class);
  }

  @SuppressWarnings("unchecked")
  private static @Nullable String name(Map<String, Object> entity) {
    Object names = entity.get("names");
    if (names instanceof Map<?, ?> map) {
      Object en = ((Map<String, Object>) map).get("en");
      return en == null ? null : en.toString();
    }
    return null;
  }

  /**
   * Reports whether any database is loaded.
   *
   * @return true if lookups can return data
   */
  public boolean anyLoaded() {
    return states.values().stream().anyMatch(state -> state.reader != null);
  }

  @Override
  public CompletableFuture<List<DatabaseStatus>> update() {
    return CompletableFuture.supplyAsync(() -> {
      for (Source source : sources.values()) {
        if (enabled && source.enabled() && !source.url().isBlank()) {
          download(source);
        }
      }
      return status();
    }, core.worker());
  }

  @Override
  public List<DatabaseStatus> status() {
    List<DatabaseStatus> result = new ArrayList<>();
    for (Source source : sources.values()) {
      State state = states.get(source.name());
      if (state == null) {
        result.add(new DatabaseStatus(source.name(), false, -1, null, null,
            source.enabled() && enabled ? null : "disabled"));
        continue;
      }
      result.add(new DatabaseStatus(source.name(), state.reader != null, state.entries, state.buildTime,
          state.lastAttempt, !enabled || !source.enabled() ? "disabled" : state.lastError));
    }
    return result;
  }

  /** Closes all readers. */
  public void close() {
    for (State state : states.values()) {
      Reader reader = state.reader;
      state.reader = null;
      if (reader != null) {
        try {
          reader.close();
        } catch (IOException ignored) {
          // Shutting down.
        }
      }
    }
  }
}
