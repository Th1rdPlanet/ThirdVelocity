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

package ru.moonlightproject.dev.thirdvelocity.proxy.reputation;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.moonlightproject.dev.thirdvelocity.api.alt.Observation;
import ru.moonlightproject.dev.thirdvelocity.api.geo.GeoInfo;
import ru.moonlightproject.dev.thirdvelocity.api.reputation.IpAssessment;
import ru.moonlightproject.dev.thirdvelocity.api.reputation.ReputationService;
import ru.moonlightproject.dev.thirdvelocity.api.reputation.Signal;
import ru.moonlightproject.dev.thirdvelocity.api.reputation.SignalProvider;
import ru.moonlightproject.dev.thirdvelocity.api.reputation.Verdict;
import ru.moonlightproject.dev.thirdvelocity.proxy.ThirdVelocityCore;
import ru.moonlightproject.dev.thirdvelocity.proxy.protection.AddressSet;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.ConfigNode;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.IpKeys;

/** Configurable IP scoring. */
public final class ReputationManager implements ReputationService {

  private static final Logger LOGGER = LogManager.getLogger("ThirdVelocity");

  /** Country rule mode. */
  public enum CountryMode {
    /** No country rule. */
    NONE,
    /** Listed countries get points. */
    DENY,
    /** Countries not listed get points. */
    ALLOW
  }

  private record Settings(boolean enabled, boolean exemptPrivate, int flag, int deny,
      Map<String, Integer> tags, CountryMode countryMode, Set<String> countries, int countryPoints,
      Map<Long, Integer> asns, int unknownGeo, int newAddress, int authenticatedAddress,
      int bannedAccountAddress, int rateThreshold, int ratePoints, int namesThreshold, int namesPoints,
      Map<String, Integer> events, int defaultEvent, double halfLifeMillis, int cacheSeconds) {
  }

  /** Decaying event score. */
  private static final class EventScore {
    double value;
    long updated;
  }

  private final ThirdVelocityCore core;
  private final Map<String, SignalProvider> providers = new ConcurrentHashMap<>();
  private final Map<InetAddress, EventScore> events = new ConcurrentHashMap<>();
  private final AddressSet tainted = new AddressSet();
  private volatile Settings settings;
  private volatile Cache<InetAddress, IpAssessment> cache = Caffeine.newBuilder().maximumSize(1).build();

  /**
   * Creates the manager.
   *
   * @param core core
   */
  public ReputationManager(ThirdVelocityCore core) {
    this.core = core;
  }

  /**
   * Applies {@code reputation.yml}.
   *
   * @param config root node
   */
  public void apply(ConfigNode config) {
    ConfigNode thresholds = config.section("thresholds");
    int flag = thresholds.integer("flag", 30, 1, 1_000_000);
    int deny = thresholds.integer("deny", 100, flag, 1_000_000);
    ConfigNode country = config.section("countries");
    Set<String> codes = new HashSet<>();
    for (String code : country.strings("list")) {
      codes.add(code.trim().toUpperCase(Locale.ROOT));
    }
    Map<Long, Integer> asns = new ConcurrentHashMap<>();
    ConfigNode asnSection = config.section("asn");
    for (String key : asnSection.keys()) {
      String number = key.toUpperCase(Locale.ROOT).replaceFirst("^AS", "");
      try {
        asns.put(Long.parseLong(number), asnSection.integer(key, 0, -1_000_000, 1_000_000));
      } catch (NumberFormatException e) {
        throw new ConfigNode.ConfigException("reputation.yml: asn." + key + " is not an AS number");
      }
    }
    ConfigNode behaviour = config.section("behaviour");
    ConfigNode history = config.section("history");
    ConfigNode eventSection = config.section("events");
    Map<String, Integer> eventPoints = new ConcurrentHashMap<>(eventSection.section("points").keys().isEmpty()
        ? Map.of() : eventSection.integerMap("points"));
    Duration halfLife = eventSection.duration("half-life", Duration.ofMinutes(30));
    Map<String, Integer> tagPoints = new ConcurrentHashMap<>();
    config.integerMap("tags").forEach((k, v) -> tagPoints.put(k.toLowerCase(Locale.ROOT), v));
    settings = new Settings(
        config.bool("enabled", true),
        config.bool("exempt-private-networks", true),
        flag, deny, tagPoints,
        country.enumValue("mode", CountryMode.NONE), codes, country.integer("points", 40, -1_000_000, 1_000_000),
        asns,
        config.integer("unknown-geo", 0, -1_000_000, 1_000_000),
        history.integer("new-address", 5, -1_000_000, 1_000_000),
        history.integer("authenticated-address", -15, -1_000_000, 1_000_000),
        history.integer("banned-account-address", 50, -1_000_000, 1_000_000),
        behaviour.section("connections-per-minute").integer("threshold", 20, 1, 1_000_000),
        behaviour.section("connections-per-minute").integer("points", 20, -1_000_000, 1_000_000),
        behaviour.section("names-per-address").integer("threshold", 3, 1, 1_000_000),
        behaviour.section("names-per-address").integer("points", 25, -1_000_000, 1_000_000),
        eventPoints,
        eventSection.integer("default", 0, -1_000_000, 1_000_000),
        Math.max(1000, halfLife.toMillis()),
        config.integer("cache-seconds", 10, 0, 3600));
    cache = Caffeine.newBuilder()
        .maximumSize(200_000)
        .expireAfterWrite(Math.max(1, settings.cacheSeconds()), TimeUnit.SECONDS)
        .build();
  }

  /** Drops cached assessments after lists, bans or GeoIP data change. */
  public void invalidate() {
    cache.invalidateAll();
  }

  /**
   * Returns the set of addresses used by banned accounts.
   *
   * @return set
   */
  public AddressSet taintedAddresses() {
    return tainted;
  }

  @Override
  public IpAssessment assess(InetAddress address) {
    InetAddress canonical = IpKeys.canonical(address);
    if (settings.cacheSeconds() == 0) {
      return compute(canonical);
    }
    return cache.get(canonical, this::compute);
  }

  private static boolean isPrivate(InetAddress address) {
    if (address.isLoopbackAddress() || address.isSiteLocalAddress() || address.isLinkLocalAddress()
        || address.isAnyLocalAddress()) {
      return true;
    }
    byte[] raw = address.getAddress();
    if (raw.length == 4) {
      // 100.64.0.0/10 carrier-grade NAT
      return (raw[0] & 0xff) == 100 && (raw[1] & 0xc0) == 64;
    }
    // fc00::/7 unique local
    return (raw[0] & 0xfe) == 0xfc;
  }

  private IpAssessment compute(InetAddress address) {
    Settings s = settings;
    GeoInfo geo = core.geoIp().lookup(address);
    Set<String> tags = core.ipLists().tags(address);
    if (!s.enabled() || (s.exemptPrivate() && isPrivate(address)) || core.protectionManager().trusted(address)) {
      return new IpAssessment(address, 0, Verdict.ALLOW, List.of(), geo, tags);
    }
    List<Signal> signals = new ArrayList<>();
    for (String tag : tags) {
      Integer points = s.tags().get(tag);
      if (points != null && points != 0) {
        signals.add(new Signal("list:" + tag, points, "в списке " + tag));
      }
    }
    if (s.countryMode() != CountryMode.NONE && geo.countryCode() != null) {
      boolean listed = s.countries().contains(geo.countryCode());
      if ((s.countryMode() == CountryMode.DENY) == listed) {
        signals.add(new Signal("country", s.countryPoints(), "страна " + geo.countryCode()));
      }
    }
    if (geo.asn() > 0) {
      Integer points = s.asns().get(geo.asn());
      if (points != null && points != 0) {
        signals.add(new Signal("asn", points, "AS" + geo.asn()
            + (geo.asOrganization() == null ? "" : " " + geo.asOrganization())));
      }
    }
    if (s.unknownGeo() != 0 && geo.countryCode() == null && core.geoIpManager().anyLoaded()) {
      signals.add(new Signal("geo:unknown", s.unknownGeo(), "нет данных GeoIP"));
    }
    if (core.protectionManager().authenticatedAddresses().contains(address)) {
      if (s.authenticatedAddress() != 0) {
        signals.add(new Signal("history:authenticated", s.authenticatedAddress(), "с адреса уже входили с паролем"));
      }
    } else if (!core.protectionManager().knownAddresses().contains(address) && s.newAddress() != 0) {
      signals.add(new Signal("history:new", s.newAddress(), "адрес раньше не встречался"));
    }
    if (s.bannedAccountAddress() != 0 && tainted.contains(address)) {
      signals.add(new Signal("history:banned-account", s.bannedAccountAddress(), "адрес забаненного аккаунта"));
    }
    int perMinute = core.protectionManager().connectionsLastMinute(address);
    if (perMinute >= s.rateThreshold()) {
      signals.add(new Signal("rate", s.ratePoints(), perMinute + " подключений за минуту"));
    }
    int names = core.altManager().recentNames(address);
    if (names >= s.namesThreshold()) {
      signals.add(new Signal("names", s.namesPoints(), names + " ников с адреса"));
    }
    EventScore score = events.get(address);
    if (score != null) {
      int points;
      synchronized (score) {
        points = (int) Math.round(decayed(score, System.currentTimeMillis(), s));
      }
      if (points != 0) {
        signals.add(new Signal("events", points, "события авторизации"));
      }
    }
    for (Map.Entry<String, SignalProvider> provider : providers.entrySet()) {
      try {
        for (Signal signal : provider.getValue().signals(address, geo)) {
          signals.add(new Signal(provider.getKey() + ":" + signal.id(), signal.points(), signal.detail()));
        }
      } catch (RuntimeException e) {
        LOGGER.warn("[x] score    » правило {} упало: {}", provider.getKey(), e.toString());
      }
    }
    return finish(address, signals, geo, tags, s);
  }

  private static IpAssessment finish(InetAddress address, List<Signal> signals, GeoInfo geo, Set<String> tags,
      Settings s) {
    signals.sort(Comparator.comparingInt(Signal::points).reversed());
    int total = 0;
    for (Signal signal : signals) {
      total += signal.points();
    }
    Verdict verdict = total >= s.deny() ? Verdict.DENY : total >= s.flag() ? Verdict.FLAG : Verdict.ALLOW;
    return new IpAssessment(address, total, verdict, List.copyOf(signals), geo, Set.copyOf(tags));
  }

  private static double decayed(EventScore score, long now, Settings s) {
    double elapsed = now - score.updated;
    return score.value * Math.pow(0.5, elapsed / s.halfLifeMillis());
  }

  @Override
  public CompletableFuture<IpAssessment> scan(InetAddress address) {
    InetAddress canonical = IpKeys.canonical(address);
    IpAssessment base = compute(canonical);
    return core.altManager().address(canonical).thenApply(report -> {
      List<Signal> signals = new ArrayList<>(base.signals());
      int banned = 0;
      for (Observation account : report.accounts()) {
        if (core.bans().matchPlayer(account.name(), null).isPresent()) {
          banned++;
        }
      }
      if (banned > 0 && !tainted.contains(canonical)) {
        signals.add(new Signal("history:banned-account", settings.bannedAccountAddress(),
            banned + " забаненных аккаунтов на адресе"));
      }
      return finish(canonical, signals, base.geo(), base.tags(), settings);
    });
  }

  @Override
  public void report(InetAddress address, String event) {
    Settings s = settings;
    int points = s.events().getOrDefault(event, s.defaultEvent());
    if (points == 0) {
      return;
    }
    InetAddress canonical = IpKeys.canonical(address);
    EventScore score = events.computeIfAbsent(canonical, k -> new EventScore());
    long now = System.currentTimeMillis();
    synchronized (score) {
      score.value = decayed(score, now, s) + points;
      score.updated = now;
    }
    cache.invalidate(canonical);
  }

  /** Removes event scores that decayed to nothing. Called periodically. */
  public void cleanup() {
    Settings s = settings;
    long now = System.currentTimeMillis();
    events.entrySet().removeIf(entry -> {
      synchronized (entry.getValue()) {
        return Math.abs(decayed(entry.getValue(), now, s)) < 0.5;
      }
    });
  }

  @Override
  public void registerProvider(String id, SignalProvider provider) {
    if (providers.putIfAbsent(id, provider) != null) {
      throw new IllegalArgumentException("Provider " + id + " is already registered");
    }
    cache.invalidateAll();
  }

  @Override
  public void unregisterProvider(String id) {
    providers.remove(id);
    cache.invalidateAll();
  }

  /**
   * Returns the thresholds for display.
   *
   * @return flag and deny thresholds
   */
  public int[] thresholds() {
    return new int[] {settings.flag(), settings.deny()};
  }
}
