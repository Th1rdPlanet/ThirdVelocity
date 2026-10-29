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
import com.github.benmanes.caffeine.cache.Expiry;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;
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

/**
 * Rate limits, escalating temporary blocks, traffic counters and the attack level.
 *
 * <p>The accept path does one lookup for the per-address state, one for the subnet counter and
 * one for temporary blocks, all with numeric keys, so a flood allocates almost nothing.</p>
 */
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

  private static final LevelPolicy DEFAULT_POLICY = new LevelPolicy(10, 60, UnknownPolicy.ALLOW, false);

  /** Counters of one address; guarded by its monitor. */
  private static final class AddressState {
    long windowStart;
    int windowCount;
    long minuteStart;
    int minuteCount;
    long statusStart;
    int statusCount;
  }

  /** Counter of one subnet. */
  private static final class SubnetState {
    long windowStart;
    int windowCount;
  }

  /** An active temporary block. */
  private record Block(String address, long untilMillis, int strike) {
  }

  private final ThirdVelocityCore core;
  private final TrafficCounter traffic = new TrafficCounter();
  private final LongAdder connections = new LongAdder();
  private final LongAdder blocked = new LongAdder();
  private final LongAdder handshakes = new LongAdder();
  private final LongAdder pings = new LongAdder();
  private final AtomicLong connectionsTotal = new AtomicLong();
  private final AtomicLong blockedTotal = new AtomicLong();
  private final AtomicLong handshakesTotal = new AtomicLong();
  private final AtomicLong pingsTotal = new AtomicLong();
  private final AtomicLong inboundTotal = new AtomicLong();
  private final AtomicLong outboundTotal = new AtomicLong();
  private final AtomicLong packetsTotal = new AtomicLong();
  private final AtomicLong temporaryBlocksTotal = new AtomicLong();
  private final Map<Long, AtomicInteger> concurrent = new ConcurrentHashMap<>();
  private final AddressSet known = new AddressSet();
  private final AddressSet trustedHistory = new AddressSet();
  private final ConcurrentLinkedQueue<String[]> firewallQueue = new ConcurrentLinkedQueue<>();
  private final Cache<Long, Block> blocks = Caffeine.newBuilder()
      .maximumSize(1_000_000)
      .expireAfter(new Expiry<Long, Block>() {
        @Override
        public long expireAfterCreate(Long key, Block value, long currentTime) {
          return remaining(value);
        }

        @Override
        public long expireAfterUpdate(Long key, Block value, long currentTime, long currentDuration) {
          return remaining(value);
        }

        @Override
        public long expireAfterRead(Long key, Block value, long currentTime, long currentDuration) {
          return currentDuration;
        }

        private long remaining(Block value) {
          return TimeUnit.MILLISECONDS.toNanos(Math.max(1, value.untilMillis() - System.currentTimeMillis()));
        }
      })
      .build();

  private volatile PrefixIndex<Boolean> allowlist = PrefixIndex.<Boolean>builder().build();
  private volatile Cache<Long, AddressState> addresses = Caffeine.newBuilder().maximumSize(1).build();
  private volatile Cache<Long, SubnetState> subnets = Caffeine.newBuilder().maximumSize(1).build();
  private volatile Cache<Long, AtomicInteger> strikes = Caffeine.newBuilder().maximumSize(1).build();
  private volatile long windowMillis = 10_000;
  private volatile int v4Subnet = 24;
  private volatile int v6Subnet = 48;
  private volatile int maxConcurrent = 8;
  private volatile int statusLimit = 20;
  private volatile boolean blockOnRate = true;
  private volatile List<Duration> blockDurations = List.of(Duration.ofMinutes(5));
  private volatile List<String> firewallCommand = List.of();
  private volatile List<String> firewallUnblock = List.of();
  private volatile String firewallElement = "{ip} timeout {seconds}s";
  private volatile int firewallBatch = 500;
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
  private final long[] authAttempts = new long[600];
  private final long[] authFailures = new long[600];
  private final LongAdder authAttemptsNow = new LongAdder();
  private final LongAdder authFailuresNow = new LongAdder();
  private final Map<String, long[]> pendingLogins = new ConcurrentHashMap<>();
  private volatile int failureMinimumSamples = 20;
  private volatile int failureLowPercent = 50;
  private volatile int failureMediumPercent = 75;
  private volatile int pendingMedium = 100;
  private volatile int pendingStrong = 500;
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
    ConfigNode limits = config.section("rate-limit");
    int window = limits.integer("window-seconds", 10, 1, 3600);
    List<Duration> durations = new ArrayList<>();
    for (String text : limits.strings("temporary-block-durations")) {
      try {
        durations.add(ru.moonlightproject.dev.thirdvelocity.proxy.util.Durations.parse(text));
      } catch (IllegalArgumentException e) {
        throw new ConfigNode.ConfigException("protection.yml: rate-limit.temporary-block-durations: " + e.getMessage());
      }
    }
    if (durations.isEmpty()) {
      durations.add(limits.duration("temporary-block-duration", Duration.ofMinutes(5)));
    }
    Duration escalationReset = limits.duration("escalation-reset", Duration.ofDays(1));
    ConfigNode firewall = config.section("firewall");
    boolean firewallOn = firewall.bool("enabled", false);

    ConfigNode attack = config.section("attack");
    ConfigNode thresholds = attack.section("thresholds");
    long low = thresholds.longValue("low", 150, 1, Long.MAX_VALUE);
    long medium = thresholds.longValue("medium", 400, low, Long.MAX_VALUE);
    long strong = thresholds.longValue("strong", 1000, medium, Long.MAX_VALUE);
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

    // Everything parsed: apply.
    allowlist = allow.build();
    windowMillis = window * 1000L;
    v4Subnet = limits.integer("subnet-prefix-v4", 24, 8, 32);
    v6Subnet = limits.integer("subnet-prefix-v6", 48, 16, 128);
    maxConcurrent = limits.integer("max-concurrent-per-ip", 8, 1, 10_000);
    blockOnRate = limits.bool("temporary-block", true);
    statusLimit = limits.integer("status-pings-per-window", 20, 1, 100_000);
    blockDurations = List.copyOf(durations);
    long idle = Math.max(window, 60) + 60;
    addresses = Caffeine.newBuilder().expireAfterAccess(idle, TimeUnit.SECONDS).maximumSize(1_000_000).build();
    subnets = Caffeine.newBuilder().expireAfterAccess(idle, TimeUnit.SECONDS).maximumSize(500_000).build();
    strikes = Caffeine.newBuilder().expireAfterWrite(escalationReset).maximumSize(1_000_000).build();
    firewallCommand = firewallOn ? firewall.strings("command") : List.of();
    firewallUnblock = firewallOn ? firewall.strings("unblock-command") : List.of();
    firewallElement = firewall.string("element", "{ip} timeout {seconds}s");
    firewallBatch = firewall.integer("max-elements-per-call", 500, 1, 100_000);
    windowSeconds = attack.integer("window-seconds", 10, 1, 600);
    recoverySeconds = attack.integer("recovery-seconds", 30, 1, 3600);
    minimumLevel = attack.enumValue("minimum-level", AttackLevel.NORMAL);
    ConfigNode signals = attack.section("signals");
    failureMinimumSamples = signals.integer("failure-minimum-samples", 20, 1, 1_000_000);
    failureLowPercent = signals.integer("failure-ratio-low-percent", 50, 1, 100);
    failureMediumPercent = signals.integer("failure-ratio-medium-percent", 75, failureLowPercent, 100);
    pendingMedium = signals.integer("pending-logins-medium", 100, 1, 10_000_000);
    pendingStrong = signals.integer("pending-logins-strong", 500, pendingMedium, 10_000_000);
    lowThreshold = low;
    mediumThreshold = medium;
    strongThreshold = strong;
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
   * @param address canonical address
   * @return reason id or {@code null}
   */
  public @Nullable String checkAccept(InetAddress address) {
    connections.increment();
    long key = IpKeys.key(address);
    if (blocks.getIfPresent(key) != null) {
      return "rate";
    }
    LevelPolicy policy = policies.getOrDefault(level, DEFAULT_POLICY);
    long now = System.currentTimeMillis();
    AddressState state = addresses.get(key, k -> new AddressState());
    int count;
    synchronized (state) {
      if (now - state.windowStart >= windowMillis) {
        state.windowStart = now;
        state.windowCount = 0;
      }
      count = ++state.windowCount;
      if (now - state.minuteStart >= 60_000) {
        state.minuteStart = now;
        state.minuteCount = 0;
      }
      state.minuteCount++;
    }
    if (count > policy.connectionsPerIp()) {
      if (blockOnRate) {
        block(key, address);
      }
      return "rate";
    }
    SubnetState subnet = subnets.get(IpKeys.subnetKey(address, v4Subnet, v6Subnet), k -> new SubnetState());
    synchronized (subnet) {
      if (now - subnet.windowStart >= windowMillis) {
        subnet.windowStart = now;
        subnet.windowCount = 0;
      }
      if (++subnet.windowCount > policy.connectionsPerSubnet()) {
        return "rate";
      }
    }
    AtomicInteger open = concurrent.get(key);
    if (open != null && open.get() >= maxConcurrent) {
      return "concurrency";
    }
    if (policy.unknown() == UnknownPolicy.DENY && !known.contains(address)) {
      return "attack";
    }
    return null;
  }

  private void block(long key, InetAddress address) {
    // Concurrent floods may race here; only the first caller creates the block.
    Block existing = blocks.getIfPresent(key);
    if (existing != null) {
      return;
    }
    int strike = strikes.get(key, k -> new AtomicInteger()).getAndIncrement();
    List<Duration> durations = blockDurations;
    Duration duration = durations.get(Math.min(strike, durations.size() - 1));
    Block created = new Block(address.getHostAddress(), System.currentTimeMillis() + duration.toMillis(), strike);
    if (blocks.asMap().putIfAbsent(key, created) != null) {
      return;
    }
    temporaryBlocksTotal.incrementAndGet();
    if (!firewallCommand.isEmpty()) {
      firewallQueue.add(new String[] {address.getAddress().length == 4 ? "4" : "6",
          firewallElement.replace("{ip}", address.getHostAddress())
              .replace("{seconds}", Long.toString(Math.max(1, duration.getSeconds())))});
    }
  }

  /** Sends queued temporary blocks to the firewall in batches; called once per second. */
  public void flushFirewall() {
    List<String> template = firewallCommand;
    if (firewallQueue.isEmpty()) {
      return;
    }
    if (template.isEmpty()) {
      firewallQueue.clear();
      return;
    }
    Map<String, List<String>> byFamily = new java.util.HashMap<>();
    String[] item;
    while ((item = firewallQueue.poll()) != null) {
      byFamily.computeIfAbsent(item[0], k -> new ArrayList<>()).add(item[1]);
    }
    for (Map.Entry<String, List<String>> family : byFamily.entrySet()) {
      List<String> elements = family.getValue();
      for (int from = 0; from < elements.size(); from += firewallBatch) {
        String joined = String.join(", ", elements.subList(from, Math.min(elements.size(), from + firewallBatch)));
        runCommand(template, family.getKey(), joined, "");
      }
    }
  }

  private void runCommand(List<String> template, String family, String elements, String ip) {
    List<String> command = new ArrayList<>(template.size());
    for (String part : template) {
      command.add(part.replace("{v}", family).replace("{elements}", elements).replace("{ip}", ip));
    }
    core.worker().execute(() -> {
      try {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes()).trim();
        if (!process.waitFor(10, TimeUnit.SECONDS)) {
          process.destroyForcibly();
          LOGGER.warn("[x] firewall » команда {} не ответила вовремя", command.get(0));
        } else if (process.exitValue() != 0) {
          LOGGER.warn("[x] firewall » команда завершилась с кодом {}: {}", process.exitValue(), output);
        }
      } catch (Exception e) {
        LOGGER.warn("[x] firewall » команда не запустилась: {}", e.getMessage());
      } finally {
        if (Thread.currentThread().isInterrupted()) {
          Thread.currentThread().interrupt();
        }
      }
    });
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
   * @param address canonical address
   * @return release callback
   */
  public Runnable admit(InetAddress address) {
    long key = IpKeys.key(address);
    AtomicInteger open = concurrent.computeIfAbsent(key, k -> new AtomicInteger());
    open.incrementAndGet();
    return () -> {
      if (open.decrementAndGet() <= 0) {
        concurrent.remove(key, open);
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
    AddressState state = addresses.get(IpKeys.key(address), k -> new AddressState());
    long now = System.currentTimeMillis();
    synchronized (state) {
      if (now - state.statusStart >= windowMillis) {
        state.statusStart = now;
        state.statusCount = 0;
      }
      return ++state.statusCount <= statusLimit;
    }
  }

  /**
   * Returns connections from an address in the current minute window.
   *
   * @param address address
   * @return count
   */
  public int connectionsLastMinute(InetAddress address) {
    AddressState state = addresses.getIfPresent(IpKeys.key(address));
    if (state == null) {
      return 0;
    }
    synchronized (state) {
      return System.currentTimeMillis() - state.minuteStart < 60_000 ? state.minuteCount : 0;
    }
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
    long hs = handshakes.sumThenReset();
    long ping = pings.sumThenReset();
    long in = traffic.inboundBytes.sumThenReset();
    long out = traffic.outboundBytes.sumThenReset();
    long packets = traffic.outboundPackets.sumThenReset();
    connectionsTotal.addAndGet(conn);
    blockedTotal.addAndGet(block);
    handshakesTotal.addAndGet(hs);
    pingsTotal.addAndGet(ping);
    inboundTotal.addAndGet(in);
    outboundTotal.addAndGet(out);
    packetsTotal.addAndGet(packets);
    snapshot = new TrafficSnapshot(conn, block, hs, ping, in, out, packets, traffic.open.sum());
    long sum;
    long attempts;
    long failures;
    synchronized (history) {
      history[historyIndex] = conn + block;
      authAttempts[historyIndex] = authAttemptsNow.sumThenReset();
      authFailures[historyIndex] = authFailuresNow.sumThenReset();
      historyIndex = (historyIndex + 1) % history.length;
      sum = 0;
      attempts = 0;
      failures = 0;
      for (int i = 1; i <= windowSeconds; i++) {
        int index = (historyIndex - i + history.length) % history.length;
        sum += history[index];
        attempts += authAttempts[index];
        failures += authFailures[index];
      }
    }
    AttackLevel measured = AttackLevel.NORMAL;
    String reason = sum + " connections in " + windowSeconds + "s";
    if (sum >= strongThreshold) {
      measured = AttackLevel.STRONG;
    } else if (sum >= mediumThreshold) {
      measured = AttackLevel.MEDIUM;
    } else if (sum >= lowThreshold) {
      measured = AttackLevel.LOW;
    }
    // Signals from authentication plugins (Selene): failure ratio and unfinished logins.
    if (attempts >= failureMinimumSamples) {
      long percent = failures * 100 / attempts;
      AttackLevel byFailures = percent >= failureMediumPercent ? AttackLevel.MEDIUM
          : percent >= failureLowPercent ? AttackLevel.LOW : AttackLevel.NORMAL;
      if (byFailures.compareTo(measured) > 0) {
        measured = byFailures;
        reason = percent + "% failed logins (" + failures + "/" + attempts + ")";
      }
    }
    long now0 = System.currentTimeMillis();
    pendingLogins.values().removeIf(entry -> now0 - entry[1] > 10_000);
    long pending = 0;
    for (long[] entry : pendingLogins.values()) {
      pending += entry[0];
    }
    AttackLevel byPending = pending >= pendingStrong ? AttackLevel.STRONG
        : pending >= pendingMedium ? AttackLevel.MEDIUM : AttackLevel.NORMAL;
    if (byPending.compareTo(measured) > 0) {
      measured = byPending;
      reason = pending + " unfinished logins";
    }
    if (measured.compareTo(minimumLevel) < 0) {
      measured = minimumLevel;
    }
    long now = System.currentTimeMillis();
    if (measured.compareTo(level) > 0) {
      setLevel(measured, reason);
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
      LOGGER.warn("[!] shield   » {} ──▶ {}  ({})", previous, next, reason);
    } else {
      LOGGER.info("[!] shield   » {} ──▶ {}  ({})", previous, next, reason);
    }
    core.fire(new AttackLevelChangedEvent(previous, next, reason));
  }

  @Override
  public void reportAuthentication(boolean failed) {
    authAttemptsNow.increment();
    if (failed) {
      authFailuresNow.increment();
    }
  }

  @Override
  public void reportPendingLogins(String source, int pending) {
    pendingLogins.put(source, new long[] {Math.max(0, pending), System.currentTimeMillis()});
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
    return policies.getOrDefault(level, DEFAULT_POLICY);
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
    return blocks.asMap().values().stream().map(Block::address).collect(Collectors.toSet());
  }

  /**
   * Lifts a temporary block (the escalation counter is kept).
   *
   * @param address address
   * @return true if a block was removed
   */
  public boolean unblock(InetAddress address) {
    InetAddress canonical = IpKeys.canonical(address);
    boolean removed = blocks.asMap().remove(IpKeys.key(canonical)) != null;
    if (removed && !firewallUnblock.isEmpty()) {
      runCommand(firewallUnblock, canonical.getAddress().length == 4 ? "4" : "6", "", canonical.getHostAddress());
    }
    return removed;
  }

  @Override
  public ru.moonlightproject.dev.thirdvelocity.api.protection.ProtectionTotals totals() {
    return new ru.moonlightproject.dev.thirdvelocity.api.protection.ProtectionTotals(
        connectionsTotal.get(), blockedTotal.get(), Map.copyOf(core.filter().blockedTotals()),
        handshakesTotal.get(), pingsTotal.get(), inboundTotal.get(), outboundTotal.get(), packetsTotal.get(),
        temporaryBlocksTotal.get(), blocks.estimatedSize(), known.size());
  }

  /**
   * Returns the number of active temporary blocks.
   *
   * @return count
   */
  public long activeBlocks() {
    return blocks.estimatedSize();
  }
}
