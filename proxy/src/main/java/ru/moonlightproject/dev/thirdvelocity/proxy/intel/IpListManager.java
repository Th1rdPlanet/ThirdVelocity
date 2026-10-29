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

package ru.moonlightproject.dev.thirdvelocity.proxy.intel;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;
import ru.moonlightproject.dev.thirdvelocity.api.geo.DatabaseStatus;
import ru.moonlightproject.dev.thirdvelocity.api.intel.IpListService;
import ru.moonlightproject.dev.thirdvelocity.api.net.IpRange;
import ru.moonlightproject.dev.thirdvelocity.proxy.ThirdVelocityCore;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.ConfigNode;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.Downloader;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.IntervalSet;

/** Downloadable and local IP lists with tags. */
public final class IpListManager implements IpListService {

  private static final Logger LOGGER = LogManager.getLogger("ThirdVelocity");
  private static final Pattern SPAMHAUS_CIDR = Pattern.compile("\"cidr\"\\s*:\\s*\"([^\"]+)\"");

  /** Line format of a list. */
  public enum Format {
    /** One IP, CIDR or IPv4 range {@code a-b} per line; {@code #} and {@code ;} start comments. */
    PLAIN,
    /** Spamhaus DROP JSON lines with a {@code cidr} field. */
    SPAMHAUS_JSON
  }

  private record Source(String name, boolean enabled, String url, Path file, Format format, Set<String> tags) {
  }

  private static final class State {
    volatile IntervalSet set = IntervalSet.EMPTY;
    volatile boolean loaded;
    volatile @Nullable Instant updated;
    volatile @Nullable Instant lastAttempt;
    volatile @Nullable String lastError;
  }

  private final ThirdVelocityCore core;
  private final Map<String, State> states = new ConcurrentHashMap<>();
  private volatile Map<String, Source> sources = Map.of();
  private volatile boolean enabled;
  private volatile Duration updateInterval = Duration.ofHours(6);

  /**
   * Creates the manager.
   *
   * @param core core
   */
  public IpListManager(ThirdVelocityCore core) {
    this.core = core;
  }

  /**
   * Applies the {@code ip-lists} section and loads lists already on disk.
   *
   * @param config section
   */
  public void apply(ConfigNode config) {
    enabled = config.bool("enabled", true);
    updateInterval = config.duration("update-interval", Duration.ofHours(6));
    Path dir = core.directory().resolve(config.string("directory", "lists"));
    Map<String, Source> parsed = new LinkedHashMap<>();
    ConfigNode lists = config.section("lists");
    for (String name : lists.keys()) {
      ConfigNode list = lists.section(name);
      if (!name.matches("[a-z0-9_-]{1,32}")) {
        throw new ConfigNode.ConfigException("ip-lists.lists." + name + ": names use a-z, 0-9, _ and -");
      }
      String file = list.string("file", name + ".txt");
      Set<String> tags = new LinkedHashSet<>();
      for (String tag : list.strings("tags")) {
        tags.add(tag.toLowerCase(Locale.ROOT));
      }
      if (tags.isEmpty()) {
        tags.add(name);
      }
      Path path = Path.of(file).isAbsolute() ? Path.of(file) : dir.resolve(file);
      parsed.put(name, new Source(name, list.bool("enabled", true), list.string("url", ""), path,
          list.enumValue("format", Format.PLAIN), Set.copyOf(tags)));
    }
    sources = parsed;
    states.keySet().retainAll(parsed.keySet());
    for (Source source : parsed.values()) {
      State state = states.computeIfAbsent(source.name(), n -> new State());
      if (!enabled || !source.enabled()) {
        state.set = IntervalSet.EMPTY;
        state.loaded = false;
        continue;
      }
      if (Files.isRegularFile(source.file())) {
        core.worker().execute(() -> load(source, state));
      }
    }
  }

  private void load(Source source, State state) {
    try {
      List<IpRange> ranges = parse(source.file(), source.format());
      state.set = IntervalSet.of(ranges);
      state.loaded = true;
      state.updated = Files.getLastModifiedTime(source.file()).toInstant();
      state.lastError = null;
      core.onIntelChanged();
    } catch (IOException e) {
      state.lastError = e.getMessage();
      LOGGER.warn(ru.moonlightproject.dev.thirdvelocity.proxy.util.Ansi.line("[x] lists    » read failed for {}: {}"), source.name(), e.getMessage());
    }
  }

  /**
   * Parses a list file.
   *
   * @param file file
   * @param format format
   * @return networks
   * @throws IOException on read errors
   */
  public static List<IpRange> parse(Path file, Format format) throws IOException {
    List<IpRange> ranges = new ArrayList<>();
    try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (format == Format.SPAMHAUS_JSON) {
          Matcher matcher = SPAMHAUS_CIDR.matcher(line);
          if (matcher.find()) {
            addQuietly(ranges, matcher.group(1));
          }
          continue;
        }
        int comment = indexOfComment(line);
        String value = (comment >= 0 ? line.substring(0, comment) : line).trim();
        if (value.isEmpty()) {
          continue;
        }
        int space = value.indexOf(' ');
        if (space > 0) {
          value = value.substring(0, space);
        }
        int dash = value.indexOf('-');
        if (dash > 0 && value.indexOf(':') < 0) {
          addRange(ranges, value.substring(0, dash), value.substring(dash + 1));
        } else {
          addQuietly(ranges, value);
        }
      }
    }
    return ranges;
  }

  private static int indexOfComment(String line) {
    int hash = line.indexOf('#');
    int semi = line.indexOf(';');
    if (hash < 0) {
      return semi;
    }
    return semi < 0 ? hash : Math.min(hash, semi);
  }

  private static void addQuietly(List<IpRange> ranges, String value) {
    try {
      ranges.add(IpRange.parse(value));
    } catch (IllegalArgumentException ignored) {
      // Skip malformed lines.
    }
  }

  /** Converts an IPv4 range {@code start-end} into CIDR blocks. */
  private static void addRange(List<IpRange> ranges, String from, String to) {
    try {
      InetAddress a = IpRange.parseLiteral(from);
      InetAddress b = IpRange.parseLiteral(to);
      byte[] ra = IpRange.canonicalBytes(a);
      byte[] rb = IpRange.canonicalBytes(b);
      if (ra.length != 4 || rb.length != 4) {
        return;
      }
      long start = ru.moonlightproject.dev.thirdvelocity.proxy.util.IpKeys.v4(ra);
      long end = ru.moonlightproject.dev.thirdvelocity.proxy.util.IpKeys.v4(rb);
      while (start <= end) {
        int size = Long.numberOfTrailingZeros(start == 0 ? 1L << 32 : start);
        size = Math.min(size, 32);
        while (size > 0 && start + (1L << size) - 1 > end) {
          size--;
        }
        byte[] raw = {(byte) (start >>> 24), (byte) (start >>> 16), (byte) (start >>> 8), (byte) start};
        ranges.add(new IpRange(InetAddress.getByAddress(raw), 32 - size));
        start += 1L << size;
      }
    } catch (IllegalArgumentException | java.net.UnknownHostException ignored) {
      // Skip malformed ranges.
    }
  }

  /**
   * Downloads lists whose file is missing or older than the update interval.
   */
  public void updateIfStale() {
    if (!enabled) {
      return;
    }
    for (Source source : sources.values()) {
      if (source.enabled() && !source.url().isBlank() && isStale(source.file())) {
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

  private void download(Source source) {
    State state = states.computeIfAbsent(source.name(), n -> new State());
    state.lastAttempt = Instant.now();
    try {
      int status = core.downloader().download(source.url(), source.file(), Downloader.Format.RAW, null,
          null, 256L * 1024 * 1024);
      if (status != 200) {
        throw new IOException("HTTP " + status + " for " + Downloader.redact(source.url()));
      }
      load(source, state);
      LOGGER.info(ru.moonlightproject.dev.thirdvelocity.proxy.util.Ansi.line("[+] lists    » {} updated  networks:{}"), source.name(), state.set.networks());
    } catch (Exception e) {
      state.lastError = e.getMessage();
      LOGGER.warn(ru.moonlightproject.dev.thirdvelocity.proxy.util.Ansi.line("[x] lists    » update failed for {}: {}"), source.name(), e.getMessage());
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
    }
  }

  @Override
  public Set<String> tags(InetAddress address) {
    if (!enabled) {
      return Set.of();
    }
    Set<String> tags = null;
    for (Source source : sources.values()) {
      State state = states.get(source.name());
      if (state != null && state.loaded && state.set.contains(address)) {
        if (tags == null) {
          tags = new LinkedHashSet<>();
        }
        tags.addAll(source.tags());
      }
    }
    return tags == null ? Set.of() : tags;
  }

  @Override
  public Set<String> lists(InetAddress address) {
    if (!enabled) {
      return Set.of();
    }
    Set<String> names = new LinkedHashSet<>();
    for (Source source : sources.values()) {
      State state = states.get(source.name());
      if (state != null && state.loaded && state.set.contains(address)) {
        names.add(source.name());
      }
    }
    return names;
  }

  @Override
  public CompletableFuture<List<DatabaseStatus>> update() {
    return CompletableFuture.supplyAsync(() -> {
      for (Source source : sources.values()) {
        State state = states.computeIfAbsent(source.name(), n -> new State());
        if (!enabled || !source.enabled()) {
          continue;
        }
        if (source.url().isBlank()) {
          if (Files.isRegularFile(source.file())) {
            load(source, state);
          }
        } else {
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
      boolean on = enabled && source.enabled();
      if (state == null) {
        result.add(new DatabaseStatus(source.name(), false, -1, null, null, on ? null : "disabled"));
      } else {
        result.add(new DatabaseStatus(source.name(), state.loaded, state.loaded ? state.set.networks() : -1,
            state.updated, state.lastAttempt, on ? state.lastError : "disabled"));
      }
    }
    return result;
  }
}
