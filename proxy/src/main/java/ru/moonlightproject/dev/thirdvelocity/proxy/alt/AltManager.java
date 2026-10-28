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

package ru.moonlightproject.dev.thirdvelocity.proxy.alt;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.net.InetAddress;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.moonlightproject.dev.thirdvelocity.api.alt.AddressReport;
import ru.moonlightproject.dev.thirdvelocity.api.alt.AltLink;
import ru.moonlightproject.dev.thirdvelocity.api.alt.AltReport;
import ru.moonlightproject.dev.thirdvelocity.api.alt.AltService;
import ru.moonlightproject.dev.thirdvelocity.api.alt.LinkReason;
import ru.moonlightproject.dev.thirdvelocity.api.alt.Observation;
import ru.moonlightproject.dev.thirdvelocity.api.net.IpRange;
import ru.moonlightproject.dev.thirdvelocity.proxy.ThirdVelocityCore;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.ConfigNode;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.IpKeys;

/**
 * Account/address graph. Links are scored per reason and combined as independent evidence:
 * {@code 1 - (1 - w1)(1 - w2)...}. Addresses shared by many accounts (NAT, mobile carriers,
 * VPNs) are dampened so a public address does not link everybody.
 */
public final class AltManager implements AltService {

  private static final Logger LOGGER = LogManager.getLogger("ThirdVelocity");

  private record Settings(boolean enabled, int retentionDays, int v4Subnet, int v6Subnet,
      double sameIp, double sameIpAuthenticated, double sameSubnet, double sameFingerprint,
      int sharedThreshold, int fingerprintSharedThreshold, double anonymizerFactor,
      Set<String> anonymizerTags, int maxDepth, double transitiveFactor, double minConfidence,
      int maxResults, double notifyConfidence, double evasionConfidence, String evasionAction,
      Duration namesWindow) {
  }

  private record Row(String nameLc, String name, String ip, String subnet, long asn, long lastSeen,
      long firstSeen, long logins, boolean authenticated) {
  }

  /** Mutable evidence for one candidate account. */
  private static final class Evidence {
    String name;
    double miss = 1.0;
    final Set<LinkReason> reasons = EnumSet.noneOf(LinkReason.class);
    final Set<String> shared = new LinkedHashSet<>();
    int depth = Integer.MAX_VALUE;
    long lastSeen;

    void add(LinkReason reason, double weight, String what, int atDepth) {
      if (weight <= 0) {
        return;
      }
      miss *= 1.0 - Math.min(0.999, weight);
      reasons.add(reason);
      if (what != null && shared.size() < 10) {
        shared.add(what);
      }
      depth = Math.min(depth, atDepth);
    }

    double confidence() {
      return 1.0 - miss;
    }
  }

  private final ThirdVelocityCore core;
  private volatile Settings settings;
  private volatile Cache<InetAddress, Set<String>> recentNames = Caffeine.newBuilder().maximumSize(1).build();

  /**
   * Creates the manager.
   *
   * @param core core
   */
  public AltManager(ThirdVelocityCore core) {
    this.core = core;
  }

  /**
   * Applies {@code alts.yml}.
   *
   * @param config root node
   */
  public void apply(ConfigNode config) {
    ConfigNode weights = config.section("weights");
    ConfigNode evasion = config.section("ban-evasion");
    Set<String> tags = new HashSet<>();
    for (String tag : config.strings("anonymizer-tags")) {
      tags.add(tag.toLowerCase(Locale.ROOT));
    }
    String action = evasion.string("action", "notify").toLowerCase(Locale.ROOT);
    if (!List.of("none", "notify", "kick", "ban").contains(action)) {
      throw new ConfigNode.ConfigException("alts.yml: ban-evasion.action must be none, notify, kick or ban");
    }
    Duration window = config.duration("names-per-address-window", Duration.ofHours(1));
    settings = new Settings(
        config.bool("enabled", true),
        config.integer("retention-days", 180, 1, 3650),
        config.integer("subnet-prefix-v4", 24, 8, 32),
        config.integer("subnet-prefix-v6", 48, 16, 128),
        weights.decimal("same-ip", 0.8, 0, 1),
        weights.decimal("same-ip-authenticated", 0.95, 0, 1),
        weights.decimal("same-subnet", 0.2, 0, 1),
        weights.decimal("same-fingerprint", 0.3, 0, 1),
        config.integer("shared-address-threshold", 4, 1, 10_000),
        config.integer("shared-fingerprint-threshold", 3, 1, 10_000),
        config.decimal("anonymizer-factor", 0.3, 0, 1),
        Set.copyOf(tags),
        config.integer("max-depth", 2, 1, 4),
        config.decimal("transitive-factor", 0.5, 0, 1),
        config.decimal("min-confidence", 0.25, 0, 1),
        config.integer("max-results", 50, 1, 1000),
        config.decimal("notify-confidence", 0.7, 0, 1),
        evasion.decimal("confidence", 0.85, 0, 1),
        action,
        window);
    recentNames = Caffeine.newBuilder().maximumSize(500_000)
        .expireAfterWrite(window.toMillis(), TimeUnit.MILLISECONDS).build();
  }

  /**
   * Returns whether alt tracking is on.
   *
   * @return enabled flag
   */
  public boolean enabled() {
    return settings.enabled();
  }

  /**
   * Returns the notify threshold.
   *
   * @return confidence
   */
  public double notifyConfidence() {
    return settings.notifyConfidence();
  }

  /**
   * Returns the ban evasion threshold.
   *
   * @return confidence
   */
  public double evasionConfidence() {
    return settings.evasionConfidence();
  }

  /**
   * Returns the ban evasion action.
   *
   * @return none, notify, kick or ban
   */
  public String evasionAction() {
    return settings.evasionAction();
  }

  /**
   * Notes a login attempt for the names-per-address signal (memory only).
   *
   * @param address address
   * @param name player name
   */
  public void noteAttempt(InetAddress address, String name) {
    recentNames.get(IpKeys.canonical(address), k -> ConcurrentHashMap.newKeySet())
        .add(name.toLowerCase(Locale.ROOT));
  }

  /**
   * Returns the distinct names that tried to log in from an address in the window.
   *
   * @param address address
   * @return count
   */
  public int recentNames(InetAddress address) {
    Set<String> names = recentNames.getIfPresent(address);
    return names == null ? 0 : names.size();
  }

  /**
   * Loads known and authenticated addresses into memory.
   *
   * @return completion
   */
  public CompletableFuture<Void> loadAddresses() {
    long since = System.currentTimeMillis() - settings.retentionDays() * 86_400_000L;
    return core.database().call(c -> {
      List<InetAddress> known = new ArrayList<>();
      List<InetAddress> authenticated = new ArrayList<>();
      try (PreparedStatement ps = c.prepareStatement("SELECT ip, MAX(authenticated) AS auth FROM tv_seen"
          + " WHERE last_seen > ? GROUP BY ip")) {
        ps.setLong(1, since);
        try (ResultSet rs = ps.executeQuery()) {
          while (rs.next()) {
            try {
              InetAddress address = IpRange.parseLiteral(rs.getString(1));
              known.add(address);
              if (rs.getInt(2) > 0) {
                authenticated.add(address);
              }
            } catch (IllegalArgumentException ignored) {
              // Corrupt row.
            }
          }
        }
      }
      core.protectionManager().knownAddresses().replace(known);
      core.protectionManager().authenticatedAddresses().replace(authenticated);
      return known.size();
    }).thenAccept(count -> LOGGER.info("{} known addresses loaded", count));
  }

  /**
   * Rebuilds the set of addresses used by banned accounts.
   */
  public void rebuildTaint() {
    List<String> names = core.banManager().bannedNames();
    if (names.isEmpty()) {
      core.reputation().taintedAddresses().replace(List.of());
      return;
    }
    core.database().call(c -> {
      List<InetAddress> addresses = new ArrayList<>();
      for (int from = 0; from < names.size(); from += 500) {
        List<String> chunk = names.subList(from, Math.min(names.size(), from + 500));
        String marks = String.join(",", java.util.Collections.nCopies(chunk.size(), "?"));
        try (PreparedStatement ps = c.prepareStatement("SELECT DISTINCT ip FROM tv_seen WHERE name_lc IN (" + marks + ")")) {
          for (int i = 0; i < chunk.size(); i++) {
            ps.setString(i + 1, chunk.get(i));
          }
          try (ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
              try {
                addresses.add(IpRange.parseLiteral(rs.getString(1)));
              } catch (IllegalArgumentException ignored) {
                // Corrupt row.
              }
            }
          }
        }
      }
      return addresses;
    }).thenAccept(addresses -> {
      core.reputation().taintedAddresses().replace(addresses);
      core.reputation().invalidate();
    }).exceptionally(error -> {
      LOGGER.warn("cannot rebuild banned-account addresses: {}", error.getMessage());
      return null;
    });
  }

  /**
   * Records a successful proxy login.
   *
   * @param name player name
   * @param address address
   * @return completion
   */
  public CompletableFuture<Void> recordLogin(String name, InetAddress address) {
    if (!settings.enabled()) {
      return CompletableFuture.completedFuture(null);
    }
    InetAddress canonical = IpKeys.canonical(address);
    core.protectionManager().knownAddresses().add(canonical);
    return upsert(name, canonical, false);
  }

  @Override
  public void recordAuthenticated(String name, InetAddress address) {
    if (!settings.enabled()) {
      return;
    }
    InetAddress canonical = IpKeys.canonical(address);
    core.protectionManager().knownAddresses().add(canonical);
    core.protectionManager().authenticatedAddresses().add(canonical);
    core.reputation().invalidate();
    upsert(name, canonical, true).exceptionally(error -> {
      LOGGER.warn("cannot record authenticated login: {}", error.getMessage());
      return null;
    });
  }

  private CompletableFuture<Void> upsert(String name, InetAddress address, boolean authenticated) {
    Settings s = settings;
    long now = System.currentTimeMillis();
    String ip = IpKeys.text(address);
    String subnet = IpKeys.subnet(address, s.v4Subnet(), s.v6Subnet());
    long asn = core.geoIp().lookup(address).asn();
    String sql = "INSERT INTO tv_seen (name_lc, ip, name, subnet, asn, first_seen, last_seen, logins,"
        + " authenticated) VALUES (?,?,?,?,?,?,?,?,?)"
        + core.database().upsert("name_lc, ip", "name = NEW(name), asn = NEW(asn), last_seen = NEW(last_seen),"
        + (authenticated ? "" : " logins = tv_seen.logins + 1,")
        + " authenticated = CASE WHEN NEW(authenticated) > tv_seen.authenticated THEN NEW(authenticated)"
        + " ELSE tv_seen.authenticated END");
    return core.database().call(c -> {
      try (PreparedStatement ps = c.prepareStatement(sql)) {
        ps.setString(1, name.toLowerCase(Locale.ROOT));
        ps.setString(2, ip);
        ps.setString(3, name);
        ps.setString(4, subnet);
        ps.setLong(5, asn);
        ps.setLong(6, now);
        ps.setLong(7, now);
        ps.setLong(8, authenticated ? 0 : 1);
        ps.setInt(9, authenticated ? 1 : 0);
        ps.executeUpdate();
      }
      return null;
    });
  }

  /**
   * Stores a client fingerprint for a name.
   *
   * @param name player name
   * @param fingerprint fingerprint hash
   */
  public void recordFingerprint(String name, String fingerprint) {
    if (!settings.enabled()) {
      return;
    }
    long now = System.currentTimeMillis();
    String sql = "INSERT INTO tv_fingerprints (fingerprint, name_lc, first_seen, last_seen) VALUES (?,?,?,?)"
        + core.database().upsert("fingerprint, name_lc", "last_seen = NEW(last_seen)");
    core.database().call(c -> {
      try (PreparedStatement ps = c.prepareStatement(sql)) {
        ps.setString(1, fingerprint);
        ps.setString(2, name.toLowerCase(Locale.ROOT));
        ps.setLong(3, now);
        ps.setLong(4, now);
        ps.executeUpdate();
      }
      return null;
    }).exceptionally(error -> {
      LOGGER.warn("cannot store fingerprint: {}", error.getMessage());
      return null;
    });
  }

  /** Deletes rows older than the retention period. */
  public void purge() {
    long cutoff = System.currentTimeMillis() - settings.retentionDays() * 86_400_000L;
    core.database().call(c -> {
      int removed;
      try (PreparedStatement ps = c.prepareStatement("DELETE FROM tv_seen WHERE last_seen < ?")) {
        ps.setLong(1, cutoff);
        removed = ps.executeUpdate();
      }
      try (PreparedStatement ps = c.prepareStatement("DELETE FROM tv_fingerprints WHERE last_seen < ?")) {
        ps.setLong(1, cutoff);
        removed += ps.executeUpdate();
      }
      return removed;
    }).thenAccept(removed -> {
      if (removed > 0) {
        LOGGER.info("removed {} expired login records", removed);
      }
    });
  }

  private static List<Row> rows(Connection c, String where, String value, int limit) throws SQLException {
    List<Row> rows = new ArrayList<>();
    try (PreparedStatement ps = c.prepareStatement("SELECT name_lc, name, ip, subnet, asn, last_seen, first_seen,"
        + " logins, authenticated FROM tv_seen WHERE " + where + " = ? ORDER BY last_seen DESC LIMIT " + limit)) {
      ps.setString(1, value);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          rows.add(new Row(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getLong(5),
              rs.getLong(6), rs.getLong(7), rs.getLong(8), rs.getInt(9) > 0));
        }
      }
    }
    return rows;
  }

  private boolean anonymizer(String ip) {
    try {
      Set<String> tags = core.ipLists().tags(IpRange.parseLiteral(ip));
      for (String tag : tags) {
        if (settings.anonymizerTags().contains(tag)) {
          return true;
        }
      }
    } catch (IllegalArgumentException ignored) {
      // Corrupt row.
    }
    return false;
  }

  @Override
  public CompletableFuture<AltReport> alts(String name) {
    String subject = name.toLowerCase(Locale.ROOT);
    Settings s = settings;
    return core.database().call(c -> {
      List<Row> own = rows(c, "name_lc", subject, 200);
      List<String> addresses = own.stream().map(Row::ip).distinct().toList();
      Map<String, Evidence> evidence = new HashMap<>();
      Map<String, Double> frontier = new LinkedHashMap<>();
      frontier.put(subject, 1.0);
      Set<String> visited = new HashSet<>();
      visited.add(subject);
      for (int depth = 1; depth <= s.maxDepth() && !frontier.isEmpty(); depth++) {
        Map<String, Double> next = new LinkedHashMap<>();
        double scale = depth == 1 ? 1.0 : Math.pow(s.transitiveFactor(), depth - 1);
        for (Map.Entry<String, Double> source : frontier.entrySet()) {
          List<Row> sourceRows = source.getKey().equals(subject) ? own : rows(c, "name_lc", source.getKey(), 100);
          double parent = source.getValue() * scale;
          Map<String, Evidence> local = new HashMap<>();
          Set<String> seenIps = new HashSet<>();
          Set<String> seenSubnets = new HashSet<>();
          for (Row row : sourceRows) {
            if (seenIps.add(row.ip())) {
              List<Row> others = rows(c, "ip", row.ip(), 500);
              int sharers = (int) others.stream().map(Row::nameLc).distinct().count();
              double damp = sharers > s.sharedThreshold() ? (double) s.sharedThreshold() / sharers : 1.0;
              double anon = anonymizer(row.ip()) ? s.anonymizerFactor() : 1.0;
              for (Row other : others) {
                if (other.nameLc().equals(source.getKey())) {
                  continue;
                }
                double base = row.authenticated() && other.authenticated() ? s.sameIpAuthenticated() : s.sameIp();
                Evidence e = local.computeIfAbsent(other.nameLc(), k -> new Evidence());
                e.name = other.name();
                e.lastSeen = Math.max(e.lastSeen, other.lastSeen());
                e.add(depth == 1 ? LinkReason.SAME_IP : LinkReason.TRANSITIVE, base * damp * anon * parent, row.ip(), depth);
              }
            }
            if (depth == 1 && s.sameSubnet() > 0 && seenSubnets.add(row.subnet())) {
              List<Row> others = rows(c, "subnet", row.subnet(), 500);
              int sharers = (int) others.stream().map(Row::nameLc).distinct().count();
              double damp = sharers > s.sharedThreshold() * 4 ? (double) s.sharedThreshold() * 4 / sharers : 1.0;
              for (Row other : others) {
                if (other.nameLc().equals(subject) || other.ip().equals(row.ip())
                    || (row.asn() > 0 && other.asn() != row.asn())) {
                  continue;
                }
                Evidence e = local.computeIfAbsent(other.nameLc(), k -> new Evidence());
                e.name = other.name();
                e.lastSeen = Math.max(e.lastSeen, other.lastSeen());
                e.add(LinkReason.SAME_SUBNET, s.sameSubnet() * damp, row.subnet(), depth);
              }
            }
          }
          if (depth == 1 && s.sameFingerprint() > 0) {
            fingerprintLinks(c, subject, local, s);
          }
          // Merge: each reason from this source counts once per candidate.
          for (Map.Entry<String, Evidence> entry : local.entrySet()) {
            if (entry.getKey().equals(subject)) {
              continue;
            }
            Evidence total = evidence.computeIfAbsent(entry.getKey(), k -> new Evidence());
            Evidence part = entry.getValue();
            total.name = part.name;
            total.lastSeen = Math.max(total.lastSeen, part.lastSeen);
            total.miss *= part.miss;
            total.reasons.addAll(part.reasons);
            for (String what : part.shared) {
              if (total.shared.size() < 10) {
                total.shared.add(what);
              }
            }
            total.depth = Math.min(total.depth, part.depth);
            if (!visited.contains(entry.getKey()) && total.confidence() >= s.minConfidence()) {
              next.merge(entry.getKey(), total.confidence(), Math::max);
            }
          }
        }
        visited.addAll(next.keySet());
        frontier = next;
      }
      List<AltLink> links = new ArrayList<>();
      for (Map.Entry<String, Evidence> entry : evidence.entrySet()) {
        Evidence e = entry.getValue();
        if (e.confidence() < s.minConfidence()) {
          continue;
        }
        links.add(new AltLink(e.name == null ? entry.getKey() : e.name,
            Math.round(e.confidence() * 1000) / 1000.0, Set.copyOf(e.reasons), List.copyOf(e.shared),
            e.depth == Integer.MAX_VALUE ? 1 : e.depth,
            e.lastSeen > 0 ? Instant.ofEpochMilli(e.lastSeen) : null,
            core.bans().matchPlayer(e.name == null ? entry.getKey() : e.name, null).orElse(null)));
      }
      links.sort(Comparator.comparingDouble(AltLink::confidence).reversed());
      if (links.size() > s.maxResults()) {
        links = new ArrayList<>(links.subList(0, s.maxResults()));
      }
      String display = own.isEmpty() ? name : own.get(0).name();
      return new AltReport(display, addresses, List.copyOf(links));
    });
  }

  private void fingerprintLinks(Connection c, String subject, Map<String, Evidence> local, Settings s)
      throws SQLException {
    List<String> prints = new ArrayList<>();
    try (PreparedStatement ps = c.prepareStatement("SELECT fingerprint FROM tv_fingerprints WHERE name_lc = ?")) {
      ps.setString(1, subject);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          prints.add(rs.getString(1));
        }
      }
    }
    for (String print : prints) {
      List<String[]> others = new ArrayList<>();
      try (PreparedStatement ps = c.prepareStatement("SELECT f.name_lc, f.last_seen FROM tv_fingerprints f"
          + " WHERE f.fingerprint = ? LIMIT 200")) {
        ps.setString(1, print);
        try (ResultSet rs = ps.executeQuery()) {
          while (rs.next()) {
            others.add(new String[] {rs.getString(1), Long.toString(rs.getLong(2))});
          }
        }
      }
      int sharers = others.size();
      double damp = sharers > s.fingerprintSharedThreshold() ? (double) s.fingerprintSharedThreshold() / sharers : 1.0;
      for (String[] other : others) {
        if (other[0].equals(subject)) {
          continue;
        }
        Evidence e = local.computeIfAbsent(other[0], k -> new Evidence());
        if (e.name == null) {
          e.name = other[0];
        }
        e.lastSeen = Math.max(e.lastSeen, Long.parseLong(other[1]));
        e.add(LinkReason.SAME_FINGERPRINT, s.sameFingerprint() * damp, "fp:" + print.substring(0, 8), 1);
      }
    }
  }

  @Override
  public CompletableFuture<AddressReport> address(InetAddress address) {
    String ip = IpKeys.text(address);
    return core.database().call(c -> {
      List<Row> rows = rows(c, "ip", ip, 500);
      List<Observation> accounts = new ArrayList<>();
      Map<String, Integer> related = new HashMap<>();
      for (Row row : rows) {
        accounts.add(observation(row));
        for (Row other : rows(c, "name_lc", row.nameLc(), 100)) {
          if (!other.ip().equals(ip)) {
            related.merge(other.ip(), 1, Integer::sum);
          }
        }
      }
      Map<String, Integer> sorted = new LinkedHashMap<>();
      related.entrySet().stream()
          .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
          .limit(100)
          .forEach(e -> sorted.put(e.getKey(), e.getValue()));
      return new AddressReport(ip, List.copyOf(accounts), sorted);
    });
  }

  @Override
  public CompletableFuture<List<Observation>> history(String name) {
    String lower = name.toLowerCase(Locale.ROOT);
    return core.database().call(c -> rows(c, "name_lc", lower, 500).stream().map(AltManager::observation).toList());
  }

  private static Observation observation(Row row) {
    return new Observation(row.name(), row.ip(), Instant.ofEpochMilli(row.firstSeen()),
        Instant.ofEpochMilli(row.lastSeen()), row.logins(), row.authenticated());
  }
}
