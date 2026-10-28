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
import com.velocitypowered.api.network.ProtocolVersion;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelOption;
import io.netty.handler.codec.haproxy.HAProxyMessage;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;
import java.util.regex.Pattern;
import net.kyori.adventure.text.Component;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;
import ru.moonlightproject.dev.thirdvelocity.api.ban.Ban;
import ru.moonlightproject.dev.thirdvelocity.api.event.ConnectionBlockedEvent;
import ru.moonlightproject.dev.thirdvelocity.api.net.IpRange;
import ru.moonlightproject.dev.thirdvelocity.api.reputation.IpAssessment;
import ru.moonlightproject.dev.thirdvelocity.api.reputation.Verdict;
import ru.moonlightproject.dev.thirdvelocity.proxy.ThirdVelocityCore;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.ConfigNode;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.IpKeys;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.PrefixIndex;

/**
 * Decisions taken inside the Velocity network code. Every method runs on a Netty event loop and
 * uses only in-memory data.
 */
public final class ConnectionFilter {

  private static final Logger LOGGER = LogManager.getLogger("ThirdVelocity");
  private static final AttributeKey<Ban> PENDING_BAN = AttributeKey.valueOf("thirdvelocity:ban");

  /** What to do with a banned address at accept time. */
  public enum BanAction {
    /** Close the TCP connection immediately. */
    DROP,
    /** Let the handshake through and show the ban screen at login. */
    MESSAGE
  }

  /** Logging of refused connections. */
  public enum BlockLog {
    NONE, SUMMARY, EACH
  }

  private final ThirdVelocityCore core;
  private final Map<String, LongAdder> blockedByReason = new ConcurrentHashMap<>();
  private final Cache<InetAddress, Boolean> eventThrottle = Caffeine.newBuilder()
      .expireAfterWrite(1, TimeUnit.SECONDS).maximumSize(100_000).build();
  private volatile BanAction banAction = BanAction.DROP;
  private volatile boolean resetOnDrop = true;
  private volatile boolean enforceReputation = true;
  private volatile BlockLog blockLog = BlockLog.SUMMARY;
  private volatile PrefixIndex<Boolean> trustedProxies = PrefixIndex.<Boolean>builder().build();
  private volatile boolean requireTrustedProxy;
  private volatile List<Pattern> allowedHosts = List.of();
  private volatile boolean denyIpHosts;
  private volatile boolean allowLegacyPing = true;
  private volatile boolean allowTransferIntent = true;
  private volatile Pattern namePattern = Pattern.compile("^[A-Za-z0-9_]{3,16}$");
  private volatile List<Pattern> deniedNames = List.of();
  private volatile int maxNamesPerAddress = 0;
  private volatile boolean encryptOffline;

  /**
   * Creates the filter.
   *
   * @param core core
   */
  public ConnectionFilter(ThirdVelocityCore core) {
    this.core = core;
  }

  /**
   * Applies settings from {@code config.yml} ({@code bans}) and {@code protection.yml}.
   *
   * @param bans bans section of config.yml
   * @param protection protection.yml root
   * @param reputation reputation.yml root
   */
  public void apply(ConfigNode bans, ConfigNode protection, ConfigNode reputation) {
    banAction = bans.enumValue("address-action", BanAction.DROP);
    ConfigNode early = protection.section("early-filter");
    resetOnDrop = early.bool("reset-connection", true);
    blockLog = early.enumValue("log", BlockLog.SUMMARY);
    enforceReputation = reputation.bool("enforce-deny", true);
    ConfigNode proxy = protection.section("proxy-protocol");
    PrefixIndex.Builder<Boolean> proxies = PrefixIndex.builder();
    for (String cidr : proxy.strings("trusted-sources")) {
      proxies.put(IpRange.parse(cidr), Boolean.TRUE);
    }
    trustedProxies = proxies.build();
    requireTrustedProxy = !trustedProxies.isEmpty();
    ConfigNode handshake = protection.section("handshake");
    List<Pattern> hosts = new ArrayList<>();
    for (String glob : handshake.strings("allowed-hosts")) {
      hosts.add(Pattern.compile("^" + Pattern.quote(glob.toLowerCase(Locale.ROOT)).replace("*", "\\E[^.]*\\Q") + "$"));
    }
    allowedHosts = List.copyOf(hosts);
    denyIpHosts = handshake.bool("deny-ip-hosts", false);
    allowLegacyPing = handshake.bool("allow-legacy-ping", true);
    allowTransferIntent = handshake.bool("allow-transfer-intent", true);
    ConfigNode login = protection.section("login");
    namePattern = Pattern.compile(login.string("name-pattern", "^[A-Za-z0-9_]{3,16}$"));
    List<Pattern> denied = new ArrayList<>();
    for (String regex : login.strings("denied-names")) {
      denied.add(Pattern.compile(regex, Pattern.CASE_INSENSITIVE));
    }
    deniedNames = List.copyOf(denied);
    maxNamesPerAddress = login.integer("max-names-per-address", 0, 0, 10_000);
    encryptOffline = protection.section("security").bool("encrypt-offline-connections", true);
  }

  private void block(Channel channel, @Nullable InetAddress address, String stage, String reason, String detail) {
    core.protectionManager().countBlocked();
    blockedByReason.computeIfAbsent(reason, k -> new LongAdder()).increment();
    if (blockLog == BlockLog.EACH) {
      LOGGER.info("refused {} at {}: {} {}", address == null ? "?" : address.getHostAddress(),
          stage, reason, detail);
    }
    if (resetOnDrop) {
      try {
        channel.config().setOption(ChannelOption.SO_LINGER, 0);
      } catch (RuntimeException ignored) {
        // Not a TCP channel.
      }
    }
    channel.close();
    if (address != null && eventThrottle.asMap().putIfAbsent(address, Boolean.TRUE) == null) {
      core.fire(new ConnectionBlockedEvent(address, stage, reason, detail));
    }
  }

  /**
   * Logs the per-reason summary of refused connections; called periodically.
   */
  public void logSummary() {
    if (blockLog != BlockLog.SUMMARY) {
      blockedByReason.clear();
      return;
    }
    Map<String, Long> counts = new TreeMap<>();
    blockedByReason.forEach((reason, adder) -> {
      long value = adder.sumThenReset();
      if (value > 0) {
        counts.put(reason, value);
      }
    });
    if (!counts.isEmpty()) {
      LOGGER.info("refused connections in the last 30s: {}", counts);
    }
  }

  /**
   * Called first in channel initialization, before any Minecraft handler exists.
   *
   * @param channel accepted channel
   * @param proxyProtocol whether PROXY protocol is enabled
   * @return false if the channel was closed
   */
  public boolean initChannel(Channel channel, boolean proxyProtocol) {
    InetAddress address = IpKeys.of(channel.remoteAddress());
    if (address == null) {
      return true;
    }
    if (proxyProtocol) {
      if (requireTrustedProxy && trustedProxies.longestMatch(address) == null) {
        block(channel, address, "accept", "proxy-protocol", "not a trusted PROXY source");
        return false;
      }
      // The real client address is known only after the PROXY header; see proxyGate().
      return true;
    }
    return admit(channel, address);
  }

  /**
   * Returns a handler to place right after the HAProxy decoder.
   *
   * @return handler
   */
  public ChannelHandler proxyGate() {
    return new ChannelInboundHandlerAdapter() {
      @Override
      public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof HAProxyMessage message) {
          ctx.pipeline().remove(this);
          String source = message.sourceAddress();
          if (source != null) {
            InetAddress address;
            try {
              address = IpKeys.canonical(IpRange.parseLiteral(source));
            } catch (IllegalArgumentException e) {
              ReferenceCountUtil.release(msg);
              block(ctx.channel(), null, "accept", "proxy-protocol", "bad source " + source);
              return;
            }
            if (!admit(ctx.channel(), address)) {
              ReferenceCountUtil.release(msg);
              return;
            }
          }
        }
        super.channelRead(ctx, msg);
      }
    };
  }

  private boolean admit(Channel channel, InetAddress address) {
    ProtectionManager protection = core.protectionManager();
    // Bans apply to trusted networks too; trust only skips limits and scoring.
    if (core.bans().enforcing()) {
      Optional<Ban> ban = core.bans().matchAddress(address);
      if (ban.isPresent()) {
        if (banAction == BanAction.DROP) {
          block(channel, address, "accept", "ban", "#" + ban.get().id());
          return false;
        }
        channel.attr(PENDING_BAN).set(ban.get());
      }
    }
    if (protection.trusted(address)) {
      Runnable release = protection.admit(address);
      channel.closeFuture().addListener(f -> release.run());
      return true;
    }
    String reason = protection.checkAccept(address);
    if (reason != null) {
      block(channel, address, "accept", reason, protection.level().name());
      return false;
    }
    IpAssessment assessment = core.reputation().assess(address);
    if (enforceReputation && assessment.verdict() == Verdict.DENY) {
      block(channel, address, "accept", "reputation", "score " + assessment.score());
      return false;
    }
    if (protection.denyByVerdict(assessment.verdict())) {
      block(channel, address, "accept", "attack", "flagged during " + protection.level());
      return false;
    }
    Runnable release = protection.admit(address);
    channel.closeFuture().addListener(f -> release.run());
    return true;
  }

  /**
   * Handshake checks. Returns the component to disconnect with (login), {@link Component#empty()}
   * to close silently, or {@code null} to continue.
   *
   * @param channel channel
   * @param address real client address
   * @param host cleaned virtual host
   * @param login true for login intent, false for status
   * @param transfer true for the 1.20.5+ transfer intent
   * @return decision
   */
  public @Nullable Component handshake(Channel channel, @Nullable InetAddress address, String host, boolean login,
      boolean transfer) {
    if (address == null) {
      return null;
    }
    ProtectionManager protection = core.protectionManager();
    boolean trusted = protection.trusted(address);
    if (login) {
      protection.countHandshake();
    }
    Ban pending = channel.attr(PENDING_BAN).get();
    if (pending != null) {
      if (!login) {
        return Component.empty();
      }
      core.protectionManager().countBlocked();
      return core.banScreen(pending);
    }
    if (!trusted) {
      if (transfer && !allowTransferIntent) {
        blockedByReason.computeIfAbsent("transfer", k -> new LongAdder()).increment();
        return Component.empty();
      }
      String lower = host.toLowerCase(Locale.ROOT);
      boolean badHost = denyIpHosts && isIpLiteral(lower);
      if (!badHost && !allowedHosts.isEmpty()) {
        badHost = allowedHosts.stream().noneMatch(p -> p.matcher(lower).matches());
      }
      if (badHost) {
        core.reputation().report(address, "handshake.bad-host");
        blockedByReason.computeIfAbsent("hostname", k -> new LongAdder()).increment();
        if (eventThrottle.asMap().putIfAbsent(address, Boolean.TRUE) == null) {
          core.fire(new ConnectionBlockedEvent(address, "handshake", "hostname", host));
        }
        return login ? core.messages().render("bad-host") : Component.empty();
      }
      if (!login && !protection.allowStatus(address)) {
        blockedByReason.computeIfAbsent("status-rate", k -> new LongAdder()).increment();
        return Component.empty();
      }
    } else if (!login) {
      protection.allowStatus(address);
    }
    return null;
  }

  private static boolean isIpLiteral(String host) {
    try {
      IpRange.parseLiteral(host);
      return true;
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  /**
   * Reports whether legacy (pre-1.7) pings are answered.
   *
   * @return true if allowed
   */
  public boolean allowLegacyPing() {
    return allowLegacyPing;
  }

  /**
   * Login checks before {@code PreLoginEvent}. Returns the disconnect reason or {@code null}.
   *
   * @param address client address
   * @param name requested name
   * @param uuid UUID sent by the client (1.20.2+) or {@code null}
   * @param protocol client protocol
   * @param rawHost raw handshake host
   * @return reason or {@code null}
   */
  public @Nullable Component login(@Nullable InetAddress address, String name, @Nullable UUID uuid,
      ProtocolVersion protocol, String rawHost) {
    boolean trusted = address != null && core.protectionManager().trusted(address);
    if (!namePattern.matcher(name).matches()) {
      if (address != null) {
        core.reputation().report(address, "login.bad-name");
      }
      return core.messages().render("bad-name", "name", name);
    }
    for (Pattern denied : deniedNames) {
      if (denied.matcher(name).find()) {
        return core.messages().render("denied-name", "name", name);
      }
    }
    if (core.bans().enforcing()) {
      Optional<Ban> ban = core.bans().matchPlayer(name, uuid);
      if (ban.isPresent()) {
        return core.banScreen(ban.get());
      }
    }
    if (address != null) {
      core.altManager().noteAttempt(address, name);
      if (!trusted && maxNamesPerAddress > 0 && core.altManager().recentNames(address) > maxNamesPerAddress) {
        core.reputation().report(address, "login.too-many-names");
        return core.messages().render("too-many-names");
      }
      core.clientTracker().rememberLogin(name, IpKeys.text(address), protocol.getProtocol(),
          protocol.getMostRecentSupportedVersion(), rawHost, uuid);
    }
    return null;
  }

  /**
   * Reports whether an offline-mode login should still be encrypted.
   *
   * @param protocol client protocol
   * @return true for 1.20.5+ clients when enabled
   */
  public boolean encryptOffline(ProtocolVersion protocol) {
    return encryptOffline && protocol.noLessThan(ProtocolVersion.MINECRAFT_1_20_5);
  }
}
