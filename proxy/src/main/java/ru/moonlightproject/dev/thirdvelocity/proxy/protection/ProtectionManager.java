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

package ru.moonlightproject.dev.thirdvelocity.proxy.protection;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.net.InetAddress;
import java.time.Duration;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.moonlightproject.dev.thirdvelocity.api.event.AttackLevelChangedEvent;
import ru.moonlightproject.dev.thirdvelocity.api.net.IpRange;
import ru.moonlightproject.dev.thirdvelocity.api.protection.AttackLevel;
import ru.moonlightproject.dev.thirdvelocity.api.protection.ProtectionService;
import ru.moonlightproject.dev.thirdvelocity.api.protection.TrafficSnapshot;
import ru.moonlightproject.dev.thirdvelocity.api.reputation.Verdict;
import ru.moonlightproject.dev.thirdvelocity.proxy.ThirdVelocityCore;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.ConfigNode;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.IpKeys;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.PrefixIndex;

/** Rate limits, temporary blocks, traffic counters and the attack level. */
public final class ProtectionManager implements ProtectionService {

  private static final Logger LOGGER = LogManager.getLogger("ThirdVelocity");

  /** What to do with addresses never seen before during an attack level. */
  public enum UnknownPolicy {
    ALLOW, FLAG, DENY
  }

  /** Per-level policy. */
  public record LevelPolicy(int connectionsPerIp, int connectionsPerSubnet, UnknownPolicy unknown,
      boolean denyFlagged) {
  }

  /** Fixed-window counter. */
  private static final class Window {
    final AtomicInteger count = new AtomicInteger();
  }

  private final ThirdVelocityCore core;
  private final TrafficCounter traffic = new TrafficCounter();
  private final LongAdder connections = new LongAdder();
  private final LongAdder blocked = new LongAdder();
  private final LongAdder handshakes = new LongAdder();
  private final LongAdder pings = new LongAdder();
  private final Map<InetAddress, AtomicInteger> concurrent = new ConcurrentHashMap<>();
  private final AddressSet known = new AddressSet();
  private final AddressSet trustedHistory = new AddressSet();

  private volatile PrefixIndex<Boolean> allowlist = PrefixIndex.<Boolean>builder().build();
  private volatile Cache<InetAddress, Window> perIp = Caffeine.newBuilder().build();
  private volatile Cache<String, Window> perSubnet = Caffeine.newBuilder().build();
  private volatile Cache<InetAddress, Window> perMinute = Caffeine.newBuilder().build();
  private volatile Cache<InetAddress, Window> statusPings = Caffeine.newBuilder().build();
  private volatile Cache<InetAddress, Long> tempBlocks = Caffeine.newBuilder().build();
  private volatile int v4Subnet = 24;
  private volatile int v6Subnet = 48;
  private volatile int maxConcurrent = 8;
  private volatile int statusLimit = 20;
  private volatile boolean blockOnRate = true;
  private volatile Map<AttackLevel, LevelPolicy> policies = Map.of();
  private volatile int windowSeconds = 10;
  private volatile int recoverySeconds = 30;
  private volatile long lowThreshold = 150;
  private volatile long mediumThreshold = 400;
  private volatile long strongThreshold = 1000;
  private volatile AttackLevel minimumLevel = AttackLevel.NORMAL;
  private volatile AttackLevel level = AttackLevel.NORMAL;
  private volatile TrafficSnapshot snapshot = new TrafficSnapshot(0, 0, 0, 0, 0, 0, 0, 0);
  private final long[] history = new long[600];
  private int historyIndex;
  private long calmSince = System.currentTimeMillis();

  /**
   * Creates the manager.
   *
   * @param core core
   */
  public ProtectionManager(ThirdVelocityCore core) {
    this.core = core;
  }

  /**
   * Applies {@code protection.yml}.
   *
   * @param config root node
   */
  public void apply(ConfigNode config) {
    PrefixIndex.Builder<Boolean> allow = PrefixIndex.builder();
    for (String cidr : config.strings("trusted-networks")) {
      try {
        allow.put(IpRange.parse(cidr), Boolean.TRUE);
      } catch (IllegalArgumentException e) {
        throw new ConfigNode.ConfigException("protection.yml: trusted-networks: " + e.getMessage());
      }
    }
    allowlist = allow.build();
    ConfigNode limits = config.section("rate-limit");
    int window = limits.integer("window-seconds", 10, 1, 3600);
    v4Subnet = limits.integer("subnet-prefix-v4", 24, 8, 32);
    v6Subnet = limits.integer("subnet-prefix-v6", 48, 16, 128);
    maxConcurrent = limits.integer("max-concurrent-per-ip", 8, 1, 10_000);
    blockOnRate = limits.bool("temporary-block", true);
    Duration block = limits.duration("temporary-block-duration", Duration.ofMinutes(5));
    statusLimit = limits.integer("status-pings-per-window", 20, 1, 100_000);
    perIp = Caffeine.newBuilder().expireAfterWrite(window, TimeUnit.SECONDS).maximumSize(1_000_000).build();
    perSubnet = Caffeine.newBuilder().expireAfterWrite(window, TimeUnit.SECONDS).maximumSize(500_000).build();
    statusPings = Caffeine.newBuilder().expireAfterWrite(window, TimeUnit.SECONDS).maximumSize(1_000_000).build();
    perMinute = Caffeine.newBuilder().expireAfterWrite(60, TimeUnit.SECONDS).maximumSize(1_000_000).build();
    tempBlocks = Caffeine.newBuilder().expireAfterWrite(block).maximumSize(1_000_000).build();

    ConfigNode attack = config.section("attack");
    windowSeconds = attack.integer("window-seconds", 10, 1, 600);
    recoverySeconds = attack.integer("recovery-seconds", 30, 1, 3600);
    minimumLevel = attack.enumValue("minimum-level", AttackLevel.NORMAL);
    ConfigNode thresholds = attack.section("thresholds");
    lowThreshold = thresholds.longValue("low", 150, 1, Long.MAX_VALUE);
    mediumThreshold = thresholds.longValue("medium", 400, lowThreshold, Long.MAX_VALUE);
    strongThreshold = thresholds.longValue("strong", 1000, mediumThreshold, Long.MAX_VALUE);
    Map<AttackLevel, LevelPolicy> parsed = new EnumMap<>(AttackLevel.class);
    ConfigNode levels = attack.section("levels");
    for (AttackLevel attackLevel : AttackLevel.values()) {
      ConfigNode node = levels.section(attackLevel.name().toLowerCase(Locale.ROOT));
      parsed.put(attackLevel, new LevelPolicy(
          node.integer("connections-per-ip", 10, 1, 1_000_000),
          node.integer("connections-per-subnet", 60, 1, 10_000_000),
          node.enumValue("unknown-addresses", UnknownPolicy.ALLOW),
          node.bool("deny-flagged", false)));
    }
    policies = parsed;
    if (level.compareTo(minimumLevel) < 0) {
      setLevel(minimumLevel, "minimum-level");
    }
  }

  /**
   * Returns the shared traffic handler.
   *
   * @return handler
   */
  public TrafficCounter trafficHandler() {
    return traffic;
  }

  /**
   * Reports whether an address is in {@code trusted-networks}.
   *
   * @param address address
   * @return true if trusted
   */
  public boolean trusted(InetAddress address) {
    return allowlist.longestMatch(address) != null;
  }

  /**
   * Accept-time checks that only need counters. Returns the block reason or {@code null}.
   *
   * @param address address
   * @return reason id or {@code null}
   */
  public String checkAccept(InetAddress address) {
    connections.increment();
    if (tempBlocks.getIfPresent(address) != null) {
      return "rate";
    }
    LevelPolicy policy = policies.getOrDefault(level, new LevelPolicy(10, 60, UnknownPolicy.ALLOW, false));
    int ipCount = perIp.get(address, k -> new Window()).count.incrementAndGet();
    perMinute.get(address, k -> new Window()).count.incrementAndGet();
    if (ipCount > policy.connectionsPerIp()) {
      if (blockOnRate) {
        tempBlocks.put(address, System.currentTimeMillis());
      }
      return "rate";
    }
    String subnet = IpKeys.subnet(address, v4Subnet, v6Subnet);
    if (perSubnet.get(subnet, k -> new Window()).count.incrementAndGet() > policy.connectionsPerSubnet()) {
      return "rate";
    }
    AtomicInteger open = concurrent.computeIfAbsent(address, k -> new AtomicInteger());
    if (open.get() >= maxConcurrent) {
      return "concurrency";
    }
    if (policy.unknown() == UnknownPolicy.DENY && !known.contains(address)) {
      return "attack";
    }
    return null;
  }

  /**
   * Checks whether the attack policy refuses a flagged address.
   *
   * @param verdict reputation verdict
   * @return true if the connection must be refused
   */
  public boolean denyByVerdict(Verdict verdict) {
    LevelPolicy policy = policies.get(level);
    return policy != null && policy.denyFlagged() && verdict == Verdict.FLAG;
  }

  /**
   * Registers an admitted connection; the returned runnable must run when it closes.
   *
   * @param address address
   * @return release callback
   */
  public Runnable admit(InetAddress address) {
    AtomicInteger open = concurrent.computeIfAbsent(address, k -> new AtomicInteger());
    open.incrementAndGet();
    return () -> {
      if (open.decrementAndGet() <= 0) {
        concurrent.remove(address, open);
      }
    };
  }

  /** Counts a refused connection. */
  public void countBlocked() {
    blocked.increment();
  }

  /** Counts a login handshake. */
  public void countHandshake() {
    handshakes.increment();
  }

  /**
   * Counts a status request and reports whether it is within the limit.
   *
   * @param address address
   * @return true if allowed
   */
  public boolean allowStatus(InetAddress address) {
    pings.increment();
    return statusPings.get(address, k -> new Window()).count.incrementAndGet() <= statusLimit;
  }

  /**
   * Returns connections from an address in the last minute.
   *
   * @param address address
   * @return count
   */
  public int connectionsLastMinute(InetAddress address) {
    Window window = perMinute.getIfPresent(address);
    return window == null ? 0 : window.count.get();
  }

  /**
   * Returns the set of addresses seen before.
   *
   * @return set
   */
  public AddressSet knownAddresses() {
    return known;
  }

  /**
   * Returns the set of addresses with a confirmed (authenticated) login.
   *
   * @return set
   */
  public AddressSet authenticatedAddresses() {
    return trustedHistory;
  }

  /** Samples counters; called once per second. */
  public void tick() {
    long conn = connections.sumThenReset();
    long block = blocked.sumThenReset();
    snapshot = new TrafficSnapshot(conn, block, handshakes.sumThenReset(), pings.sumThenReset(),
        traffic.inboundBytes.sumThenReset(), traffic.outboundBytes.sumThenReset(),
        traffic.outboundPackets.sumThenReset(), traffic.open.sum());
    long sum;
    synchronized (history) {
      history[historyIndex] = conn + block;
      historyIndex = (historyIndex + 1) % history.length;
      sum = 0;
      for (int i = 1; i <= windowSeconds; i++) {
        sum += history[(historyIndex - i + history.length) % history.length];
      }
    }
    AttackLevel measured = AttackLevel.NORMAL;
    if (sum >= strongThreshold) {
      measured = AttackLevel.STRONG;
    } else if (sum >= mediumThreshold) {
      measured = AttackLevel.MEDIUM;
    } else if (sum >= lowThreshold) {
      measured = AttackLevel.LOW;
    }
    if (measured.compareTo(minimumLevel) < 0) {
      measured = minimumLevel;
    }
    long now = System.currentTimeMillis();
    if (measured.compareTo(level) > 0) {
      setLevel(measured, sum + " connections in " + windowSeconds + "s");
      calmSince = now;
    } else if (measured.compareTo(level) < 0) {
      if (now - calmSince >= recoverySeconds * 1000L) {
        AttackLevel next = AttackLevel.values()[level.ordinal() - 1];
        setLevel(next.compareTo(measured) < 0 ? measured : next, "calm for " + recoverySeconds + "s");
        calmSince = now;
      }
    } else {
      calmSince = now;
    }
  }

  private void setLevel(AttackLevel next, String reason) {
    AttackLevel previous = level;
    if (previous == next) {
      return;
    }
    level = next;
    if (next.compareTo(previous) > 0) {
      LOGGER.warn("attack level {} -> {} ({})", previous, next, reason);
    } else {
      LOGGER.info("attack level {} -> {} ({})", previous, next, reason);
    }
    core.fire(new AttackLevelChangedEvent(previous, next, reason));
  }

  @Override
  public AttackLevel level() {
    return level;
  }

  /**
   * Returns the policy of the current level.
   *
   * @return policy
   */
  public LevelPolicy policy() {
    return policies.getOrDefault(level, new LevelPolicy(10, 60, UnknownPolicy.ALLOW, false));
  }

  @Override
  public TrafficSnapshot traffic() {
    return snapshot;
  }

  @Override
  public boolean suspicious(String name, InetAddress address) {
    InetAddress canonical = IpKeys.canonical(address);
    if (trusted(canonical)) {
      return false;
    }
    if (core.reputation().assess(canonical).suspicious()) {
      return true;
    }
    if (core.clientTracker().flagged(name)) {
      return true;
    }
    return policy().unknown() == UnknownPolicy.FLAG && !known.contains(canonical);
  }

  @Override
  public boolean known(InetAddress address) {
    return known.contains(IpKeys.canonical(address));
  }

  @Override
  public Set<String> temporaryBlocks() {
    return tempBlocks.asMap().keySet().stream().map(InetAddress::getHostAddress).collect(Collectors.toSet());
  }

  /**
   * Lifts a temporary block.
   *
   * @param address address
   * @return true if a block was removed
   */
  public boolean unblock(InetAddress address) {
    return tempBlocks.asMap().remove(IpKeys.canonical(address)) != null;
  }

  /**
   * Returns open connections per address, highest first (for diagnostics).
   *
   * @param limit maximum entries
   * @return address and count pairs
   */
  public List<Map.Entry<InetAddress, Integer>> topConcurrent(int limit) {
    return concurrent.entrySet().stream()
        .map(e -> Map.entry(e.getKey(), e.getValue().get()))
        .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
        .limit(limit)
        .toList();
  }
}
