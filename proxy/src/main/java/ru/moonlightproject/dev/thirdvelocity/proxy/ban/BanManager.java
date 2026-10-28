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

package ru.moonlightproject.dev.thirdvelocity.proxy.ban;

import com.velocitypowered.api.proxy.Player;
import java.net.InetAddress;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import net.kyori.adventure.text.Component;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;
import ru.moonlightproject.dev.thirdvelocity.api.ban.Ban;
import ru.moonlightproject.dev.thirdvelocity.api.ban.BanRequest;
import ru.moonlightproject.dev.thirdvelocity.api.ban.BanService;
import ru.moonlightproject.dev.thirdvelocity.api.ban.BanTarget;
import ru.moonlightproject.dev.thirdvelocity.api.event.BanCreatedEvent;
import ru.moonlightproject.dev.thirdvelocity.api.event.BanRevokedEvent;
import ru.moonlightproject.dev.thirdvelocity.api.geo.GeoInfo;
import ru.moonlightproject.dev.thirdvelocity.proxy.ThirdVelocityCore;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.ConfigNode;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.Durations;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.IpKeys;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.PrefixIndex;

/** Ban storage with an in-memory index rebuilt on every change. */
public final class BanManager implements BanService {

  private static final Logger LOGGER = LogManager.getLogger("ThirdVelocity");

  private record Index(
      List<Ban> active,
      PrefixIndex<Ban> addresses,
      Map<String, Ban> names,
      Map<UUID, Ban> uuids,
      Map<Long, Ban> asns,
      Map<String, Ban> countries) {
  }

  private final ThirdVelocityCore core;
  private final Map<Long, Ban> active = new ConcurrentHashMap<>();
  private volatile Index index = new Index(List.of(), PrefixIndex.<Ban>builder().build(), Map.of(),
      Map.of(), Map.of(), Map.of());
  private volatile long lastSync;
  private volatile boolean enforce;
  private volatile boolean kickOnline;
  private volatile List<String> firewallBan = List.of();
  private volatile List<String> firewallUnban = List.of();

  /**
   * Creates the manager.
   *
   * @param core core
   */
  public BanManager(ThirdVelocityCore core) {
    this.core = core;
  }

  /**
   * Applies the {@code bans} section.
   *
   * @param config section
   */
  public void apply(ConfigNode config) {
    enforce = config.bool("enforce", true);
    kickOnline = config.bool("kick-online", true);
    ConfigNode firewall = config.section("firewall");
    if (firewall.bool("enabled", false)) {
      firewallBan = firewall.strings("on-ban");
      firewallUnban = firewall.strings("on-unban");
    } else {
      firewallBan = List.of();
      firewallUnban = List.of();
    }
  }

  /**
   * Loads active bans from the database.
   *
   * @return completion
   */
  public CompletableFuture<Void> load() {
    long started = System.currentTimeMillis();
    return core.database().call(c -> {
      List<Ban> loaded = new ArrayList<>();
      try (PreparedStatement ps = c.prepareStatement("SELECT * FROM tv_bans WHERE revoked_at IS NULL"
          + " AND (expires_at IS NULL OR expires_at > ?)")) {
        ps.setLong(1, started);
        try (ResultSet rs = ps.executeQuery()) {
          while (rs.next()) {
            Ban ban = read(rs);
            if (ban != null) {
              loaded.add(ban);
            }
          }
        }
      }
      return loaded;
    }).thenAccept(loaded -> {
      active.clear();
      loaded.forEach(ban -> active.put(ban.id(), ban));
      lastSync = started;
      rebuild();
      LOGGER.info("loaded {} active bans", loaded.size());
    });
  }

  /**
   * Pulls changes made by other proxies sharing the database.
   */
  public void sync() {
    long since = lastSync - 5000;
    long now = System.currentTimeMillis();
    core.database().call(c -> {
      List<Ban> changed = new ArrayList<>();
      try (PreparedStatement ps = c.prepareStatement("SELECT * FROM tv_bans WHERE updated_at >= ?")) {
        ps.setLong(1, since);
        try (ResultSet rs = ps.executeQuery()) {
          while (rs.next()) {
            Ban ban = read(rs);
            if (ban != null) {
              changed.add(ban);
            }
          }
        }
      }
      return changed;
    }).thenAccept(changed -> {
      lastSync = now;
      boolean dirty = false;
      Instant instant = Instant.ofEpochMilli(now);
      for (Ban ban : changed) {
        Ban known = active.get(ban.id());
        if (ban.activeAt(instant)) {
          if (known == null) {
            active.put(ban.id(), ban);
            dirty = true;
            LOGGER.info("Ban #{} from shared storage: {} {} ({})", ban.id(), ban.target().kind(),
                ban.target().value(), ban.actor());
            core.fire(new BanCreatedEvent(ban, true));
            applySideEffects(ban, true);
          }
        } else if (known != null) {
          active.remove(ban.id());
          dirty = true;
          if (ban.revokedAt() != null) {
            core.fire(new BanRevokedEvent(ban, true));
            runFirewall(firewallUnban, ban);
          }
        }
      }
      if (purgeExpired() || dirty) {
        rebuild();
      }
    }).exceptionally(error -> {
      LOGGER.warn("ban sync failed: {}", rootMessage(error));
      return null;
    });
  }

  private boolean purgeExpired() {
    Instant now = Instant.now();
    return active.values().removeIf(ban -> !ban.activeAt(now));
  }

  private void rebuild() {
    List<Ban> sorted = new ArrayList<>(active.values());
    sorted.sort(Comparator.comparingLong(Ban::id).reversed());
    PrefixIndex.Builder<Ban> addresses = PrefixIndex.builder();
    Map<String, Ban> names = new HashMap<>();
    Map<UUID, Ban> uuids = new HashMap<>();
    Map<Long, Ban> asns = new HashMap<>();
    Map<String, Ban> countries = new HashMap<>();
    // Oldest first so the newest ban for the same target wins.
    for (int i = sorted.size() - 1; i >= 0; i--) {
      Ban ban = sorted.get(i);
      switch (ban.target()) {
        case BanTarget.Ip ip -> addresses.put(ip.range(), ban);
        case BanTarget.Name name -> names.put(name.value(), ban);
        case BanTarget.Uuid uuid -> uuids.put(uuid.uuid(), ban);
        case BanTarget.Asn asn -> asns.put(asn.asn(), ban);
        case BanTarget.Country country -> countries.put(country.code(), ban);
      }
    }
    index = new Index(List.copyOf(sorted), addresses.build(), Map.copyOf(names), Map.copyOf(uuids),
        Map.copyOf(asns), Map.copyOf(countries));
    core.onBansChanged();
  }

  private static @Nullable Ban read(ResultSet rs) throws SQLException {
    try {
      BanTarget target = BanTarget.parse(rs.getString("kind"), rs.getString("target"));
      long expires = rs.getLong("expires_at");
      Instant expiresAt = rs.wasNull() ? null : Instant.ofEpochMilli(expires);
      long revoked = rs.getLong("revoked_at");
      Instant revokedAt = rs.wasNull() ? null : Instant.ofEpochMilli(revoked);
      return new Ban(rs.getLong("id"), target, rs.getString("reason"), rs.getString("actor"),
          Instant.ofEpochMilli(rs.getLong("created_at")), expiresAt, revokedAt, rs.getString("revoked_by"));
    } catch (IllegalArgumentException e) {
      LOGGER.warn("skipping malformed ban #{}: {}", rs.getLong("id"), e.getMessage());
      return null;
    }
  }

  @Override
  public boolean enforcing() {
    return enforce;
  }

  @Override
  public CompletableFuture<Ban> ban(BanRequest request) {
    long now = System.currentTimeMillis();
    Long expires = request.duration() == null ? null : now + request.duration().toMillis();
    String reason = truncate(request.reason(), 512);
    String actor = truncate(request.actor(), 64);
    return core.database().call(c -> {
      try (PreparedStatement ps = c.prepareStatement("INSERT INTO tv_bans (kind, target, reason, actor,"
          + " created_at, expires_at, revoked_at, revoked_by, updated_at) VALUES (?,?,?,?,?,?,NULL,NULL,?)",
          Statement.RETURN_GENERATED_KEYS)) {
        ps.setString(1, request.target().kind());
        ps.setString(2, request.target().value());
        ps.setString(3, reason);
        ps.setString(4, actor);
        ps.setLong(5, now);
        if (expires == null) {
          ps.setNull(6, Types.BIGINT);
        } else {
          ps.setLong(6, expires);
        }
        ps.setLong(7, now);
        ps.executeUpdate();
        try (ResultSet keys = ps.getGeneratedKeys()) {
          if (!keys.next()) {
            throw new SQLException("No generated id");
          }
          return keys.getLong(1);
        }
      }
    }).thenApply(id -> {
      Ban ban = new Ban(id, request.target(), reason, actor, Instant.ofEpochMilli(now),
          expires == null ? null : Instant.ofEpochMilli(expires), null, null);
      active.put(id, ban);
      rebuild();
      LOGGER.info("{} banned {} {} ({}){}", actor, ban.target().kind(),
          ban.target().value(), reason.isEmpty() ? "-" : reason,
          expires == null ? "" : " for " + Durations.format(request.duration()));
      core.fire(new BanCreatedEvent(ban, false));
      applySideEffects(ban, false);
      return ban;
    });
  }

  private void applySideEffects(Ban ban, boolean remote) {
    runFirewall(firewallBan, ban);
    if (kickOnline && enforce) {
      Component message = core.banScreen(ban);
      for (Player player : core.server().getAllPlayers()) {
        if (matchesPlayer(ban, player)) {
          player.disconnect(message);
        }
      }
    }
  }

  private boolean matchesPlayer(Ban ban, Player player) {
    InetAddress address = IpKeys.of(player.getRemoteAddress());
    return switch (ban.target()) {
      case BanTarget.Ip ip -> address != null && ip.range().contains(address);
      case BanTarget.Name name -> player.getUsername().equalsIgnoreCase(name.name());
      case BanTarget.Uuid uuid -> player.getUniqueId().equals(uuid.uuid());
      case BanTarget.Asn asn -> address != null && core.geoIp().lookup(address).asn() == asn.asn();
      case BanTarget.Country country -> address != null
          && country.code().equals(core.geoIp().lookup(address).countryCode());
    };
  }

  private void runFirewall(List<String> template, Ban ban) {
    if (template.isEmpty() || !(ban.target() instanceof BanTarget.Ip ip)) {
      return;
    }
    List<String> command = new ArrayList<>(template.size());
    for (String part : template) {
      command.add(part.replace("{ip}", ip.range().toString())
          .replace("{family}", ip.range().isIpv4() ? "ipv4" : "ipv6")
          .replace("{v}", ip.range().isIpv4() ? "4" : "6"));
    }
    core.worker().execute(() -> {
      try {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes()).trim();
        int code = process.waitFor();
        if (code != 0) {
          LOGGER.warn("firewall command {} exited with {}: {}", command, code, output);
        }
      } catch (Exception e) {
        LOGGER.warn("firewall command {} failed: {}", command, e.getMessage());
      }
    });
  }

  @Override
  public CompletableFuture<Optional<Ban>> revoke(long id, String actor) {
    long now = System.currentTimeMillis();
    String by = truncate(actor == null || actor.isBlank() ? "API" : actor, 64);
    return core.database().call(c -> revokeRow(c, id, by, now)).thenApply(updated -> {
      if (!updated) {
        return Optional.<Ban>empty();
      }
      Ban old = active.remove(id);
      rebuild();
      if (old == null) {
        return Optional.<Ban>empty();
      }
      Ban revoked = new Ban(old.id(), old.target(), old.reason(), old.actor(), old.createdAt(),
          old.expiresAt(), Instant.ofEpochMilli(now), by);
      LOGGER.info("{} lifted ban #{} ({} {})", by, id, old.target().kind(), old.target().value());
      core.fire(new BanRevokedEvent(revoked, false));
      runFirewall(firewallUnban, revoked);
      return Optional.of(revoked);
    });
  }

  private static boolean revokeRow(Connection c, long id, String by, long now) throws SQLException {
    try (PreparedStatement ps = c.prepareStatement("UPDATE tv_bans SET revoked_at = ?, revoked_by = ?,"
        + " updated_at = ? WHERE id = ? AND revoked_at IS NULL")) {
      ps.setLong(1, now);
      ps.setString(2, by);
      ps.setLong(3, now);
      ps.setLong(4, id);
      return ps.executeUpdate() > 0;
    }
  }

  @Override
  public CompletableFuture<List<Ban>> revoke(BanTarget target, String actor) {
    List<Ban> matching = active(target);
    List<CompletableFuture<Optional<Ban>>> futures = new ArrayList<>();
    for (Ban ban : matching) {
      futures.add(revoke(ban.id(), actor));
    }
    return CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new))
        .thenApply(ignored -> futures.stream().map(CompletableFuture::join).flatMap(Optional::stream).toList());
  }

  @Override
  public Optional<Ban> matchAddress(InetAddress address) {
    Index current = index;
    Instant now = Instant.now();
    Ban hit = current.addresses().longestMatch(address);
    if (hit != null && hit.activeAt(now)) {
      return Optional.of(hit);
    }
    if (!current.asns().isEmpty() || !current.countries().isEmpty()) {
      GeoInfo geo = core.geoIp().lookup(address);
      Ban asn = current.asns().get(geo.asn());
      if (asn != null && asn.activeAt(now)) {
        return Optional.of(asn);
      }
      if (geo.countryCode() != null) {
        Ban country = current.countries().get(geo.countryCode());
        if (country != null && country.activeAt(now)) {
          return Optional.of(country);
        }
      }
    }
    return Optional.empty();
  }

  @Override
  public Optional<Ban> matchPlayer(String name, @Nullable UUID uuid) {
    Index current = index;
    Instant now = Instant.now();
    Ban hit = current.names().get(name.toLowerCase(Locale.ROOT));
    if (hit != null && hit.activeAt(now)) {
      return Optional.of(hit);
    }
    if (uuid != null) {
      hit = current.uuids().get(uuid);
      if (hit != null && hit.activeAt(now)) {
        return Optional.of(hit);
      }
    }
    return Optional.empty();
  }

  @Override
  public List<Ban> active() {
    Instant now = Instant.now();
    return index.active().stream().filter(ban -> ban.activeAt(now)).toList();
  }

  @Override
  public List<Ban> active(BanTarget target) {
    return active().stream().filter(ban -> ban.target().equals(target)).toList();
  }

  /**
   * Returns active name bans (used to taint addresses of banned accounts).
   *
   * @return lowercase names
   */
  public List<String> bannedNames() {
    return index.names().keySet().stream().toList();
  }

  @Override
  public CompletableFuture<List<Ban>> history(int offset, int limit) {
    int bounded = Math.max(1, Math.min(1000, limit));
    int skip = Math.max(0, offset);
    return core.database().call(c -> {
      List<Ban> result = new ArrayList<>();
      try (PreparedStatement ps = c.prepareStatement("SELECT * FROM tv_bans ORDER BY id DESC LIMIT ? OFFSET ?")) {
        ps.setInt(1, bounded);
        ps.setInt(2, skip);
        try (ResultSet rs = ps.executeQuery()) {
          while (rs.next()) {
            Ban ban = read(rs);
            if (ban != null) {
              result.add(ban);
            }
          }
        }
      }
      return result;
    });
  }

  @Override
  public CompletableFuture<Optional<Ban>> byId(long id) {
    return core.database().call(c -> {
      try (PreparedStatement ps = c.prepareStatement("SELECT * FROM tv_bans WHERE id = ?")) {
        ps.setLong(1, id);
        try (ResultSet rs = ps.executeQuery()) {
          return rs.next() ? Optional.ofNullable(read(rs)) : Optional.<Ban>empty();
        }
      }
    });
  }

  private static String truncate(String value, int max) {
    return value.length() <= max ? value : value.substring(0, max);
  }

  private static String rootMessage(Throwable error) {
    Throwable cause = error;
    while (cause.getCause() != null) {
      cause = cause.getCause();
    }
    return cause.getMessage();
  }
}
