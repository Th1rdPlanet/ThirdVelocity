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

package ru.moonlightproject.dev.thirdvelocity.proxy.command;

import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.ConsoleCommandSource;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.proxy.plugin.virtual.VelocityVirtualPlugin;
import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.kyori.adventure.text.minimessage.tag.resolver.TagResolver;
import org.jspecify.annotations.Nullable;
import ru.moonlightproject.dev.thirdvelocity.api.alt.AltLink;
import ru.moonlightproject.dev.thirdvelocity.api.alt.Observation;
import ru.moonlightproject.dev.thirdvelocity.api.ban.Ban;
import ru.moonlightproject.dev.thirdvelocity.api.ban.BanRequest;
import ru.moonlightproject.dev.thirdvelocity.api.ban.BanTarget;
import ru.moonlightproject.dev.thirdvelocity.api.client.ClientInfo;
import ru.moonlightproject.dev.thirdvelocity.api.geo.DatabaseStatus;
import ru.moonlightproject.dev.thirdvelocity.api.geo.GeoInfo;
import ru.moonlightproject.dev.thirdvelocity.api.net.IpRange;
import ru.moonlightproject.dev.thirdvelocity.api.protection.TrafficSnapshot;
import ru.moonlightproject.dev.thirdvelocity.api.reputation.IpAssessment;
import ru.moonlightproject.dev.thirdvelocity.api.reputation.Signal;
import ru.moonlightproject.dev.thirdvelocity.proxy.ThirdVelocityCore;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.ConfigNode;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.Durations;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.IpKeys;

/**
 * {@code /tv}: staff command over the API. Every subcommand has the permission
 * {@code thirdvelocity.command.<name>} and can be disabled in {@code config.yml}.
 */
public final class ThirdVelocityCommand implements SimpleCommand {

  private static final MiniMessage MM = MiniMessage.miniMessage();
  private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm")
      .withZone(ZoneId.systemDefault());
  private static final List<String> KINDS = List.of("ip", "name", "uuid", "asn", "country");

  private record Sub(String usage, String description) {
  }

  private static final Map<String, Sub> SUBCOMMANDS = new LinkedHashMap<>();

  static {
    SUBCOMMANDS.put("ban", new Sub("ban [ip|name|uuid|asn|country] <target> [duration] [reason]",
        "ban an IP or subnet, name, UUID, AS or country"));
    SUBCOMMANDS.put("unban", new Sub("unban <id> | unban [kind] <target>", "lift a ban"));
    SUBCOMMANDS.put("bans", new Sub("bans [page]", "active bans"));
    SUBCOMMANDS.put("baninfo", new Sub("baninfo <id>", "ban details"));
    SUBCOMMANDS.put("check", new Sub("check <ip|player>", "IP check: GeoIP, lists, score (offline players: last address)"));
    SUBCOMMANDS.put("alts", new Sub("alts <name>", "alt and linked accounts"));
    SUBCOMMANDS.put("ip", new Sub("ip <ip|player>", "accounts on an IP and related addresses (offline players: last address)"));
    SUBCOMMANDS.put("history", new Sub("history <name>", "address history of a player"));
    SUBCOMMANDS.put("client", new Sub("client <player>", "client, mods, launcher"));
    SUBCOMMANDS.put("geoip", new Sub("geoip [status|update]", "GeoIP databases"));
    SUBCOMMANDS.put("lists", new Sub("lists [status|update]", "IP lists"));
    SUBCOMMANDS.put("attack", new Sub("attack", "attack level and traffic"));
    SUBCOMMANDS.put("unblock", new Sub("unblock <ip>", "lift a temporary block"));
    SUBCOMMANDS.put("reload", new Sub("reload", "reload configs"));
  }

  private final ThirdVelocityCore core;
  private final Set<String> disabled;

  private ThirdVelocityCommand(ThirdVelocityCore core, Set<String> disabled) {
    this.core = core;
    this.disabled = disabled;
  }

  /**
   * Registers the command unless disabled.
   *
   * @param core core
   */
  public static void register(ThirdVelocityCore core) {
    ConfigNode commands = core.mainConfig().section("commands");
    if (!commands.bool("enabled", true)) {
      return;
    }
    Set<String> disabled = commands.strings("disabled").stream()
        .map(s -> s.toLowerCase(Locale.ROOT)).collect(Collectors.toUnmodifiableSet());
    List<String> aliases = commands.strings("aliases");
    CommandMeta meta = core.server().getCommandManager().metaBuilder(commands.string("name", "tv"))
        .aliases(aliases.toArray(String[]::new))
        .plugin(VelocityVirtualPlugin.INSTANCE)
        .build();
    core.server().getCommandManager().register(meta, new ThirdVelocityCommand(core, disabled));
  }

  private boolean allowed(CommandSource source, String sub) {
    return !disabled.contains(sub) && SUBCOMMANDS.containsKey(sub)
        && (source instanceof ConsoleCommandSource || source.hasPermission("thirdvelocity.command." + sub));
  }

  @Override
  public boolean hasPermission(Invocation invocation) {
    CommandSource source = invocation.source();
    return SUBCOMMANDS.keySet().stream().anyMatch(sub -> allowed(source, sub));
  }

  private static String actor(CommandSource source) {
    return source instanceof Player player ? player.getUsername() : "CONSOLE";
  }

  // ---- output ----------------------------------------------------------------------------
  // One layout for every reply: a marked header, then labelled rows drawn as a small tree.
  // Values are inserted unparsed, so player names or ban reasons can never inject tags.

  private static final String MARK = "<#7dd3fc>◆</#7dd3fc> ";
  private static final String BRANCH = "<dark_gray>  ├</dark_gray> ";
  private static final String LAST = "<dark_gray>  └</dark_gray> ";
  private static final String DOT = " <dark_gray>·</dark_gray> ";

  private static void send(CommandSource source, String format, String... placeholders) {
    TagResolver.Builder resolver = TagResolver.builder();
    for (int i = 0; i + 1 < placeholders.length; i += 2) {
      resolver.resolver(Placeholder.unparsed(placeholders[i], placeholders[i + 1] == null ? "" : placeholders[i + 1]));
    }
    source.sendMessage(MM.deserialize(format, resolver.build()));
  }

  private static void head(CommandSource source, String format, String... placeholders) {
    send(source, MARK + format, placeholders);
  }

  /** A labelled row; {@code value} is a MiniMessage format using the placeholders. */
  private static void row(CommandSource source, boolean last, String label, String value, String... placeholders) {
    send(source, (last ? LAST : BRANCH) + "<gray>" + label + ":</gray> " + value, placeholders);
  }

  private static void ok(CommandSource source, String format, String... placeholders) {
    send(source, MARK + "<green>" + format, placeholders);
  }

  private static void error(CommandSource source, String text) {
    send(source, MARK + "<red><text>", "text", text);
  }

  private static void usage(CommandSource source, String sub) {
    send(source, MARK + "<gray>Usage:</gray> <white>/tv <usage>", "usage", SUBCOMMANDS.get(sub).usage());
  }

  private static String expires(Ban ban) {
    return ban.expiresAt() == null ? "permanent" : "until " + TIME.format(ban.expiresAt());
  }

  private static String target(Ban ban) {
    return ban.target().kind() + " " + ban.target().value();
  }

  @Override
  public void execute(Invocation invocation) {
    CommandSource source = invocation.source();
    String[] args = invocation.arguments();
    if (args.length == 0 || args[0].equalsIgnoreCase("help")) {
      help(source);
      return;
    }
    String sub = args[0].toLowerCase(Locale.ROOT);
    if (!allowed(source, sub)) {
      error(source, SUBCOMMANDS.containsKey(sub) && !disabled.contains(sub)
          ? "You may not use this command." : "Unknown subcommand, see /" + invocation.alias() + " help");
      return;
    }
    String[] rest = Arrays.copyOfRange(args, 1, args.length);
    CompletableFuture<?> future = switch (sub) {
      case "ban" -> ban(source, rest);
      case "unban" -> unban(source, rest);
      case "bans" -> bans(source, rest);
      case "baninfo" -> banInfo(source, rest);
      case "check" -> check(source, rest);
      case "alts" -> alts(source, rest);
      case "ip" -> ip(source, rest);
      case "history" -> history(source, rest);
      case "client" -> client(source, rest);
      case "geoip" -> geoip(source, rest);
      case "lists" -> lists(source, rest);
      case "attack" -> attack(source);
      case "unblock" -> unblock(source, rest);
      case "reload" -> reload(source);
      default -> CompletableFuture.completedFuture(null);
    };
    future.exceptionally(failure -> {
      Throwable cause = failure;
      while (cause.getCause() != null) {
        cause = cause.getCause();
      }
      error(source, "Failed: " + cause.getMessage());
      return null;
    });
  }

  private void help(CommandSource source) {
    head(source, "<white><b>ThirdVelocity</b></white> <dark_gray><version> · commands", "version", ThirdVelocityCore.VERSION);
    List<Map.Entry<String, Sub>> visible = SUBCOMMANDS.entrySet().stream()
        .filter(entry -> allowed(source, entry.getKey())).toList();
    for (int i = 0; i < visible.size(); i++) {
      send(source, (i == visible.size() - 1 ? LAST : BRANCH)
              + "<white>/tv <usage></white> <dark_gray>—</dark_gray> <gray><description>",
          "usage", visible.get(i).getValue().usage(), "description", visible.get(i).getValue().description());
    }
  }

  private static CompletableFuture<Void> done() {
    return CompletableFuture.completedFuture(null);
  }

  // ---- bans ------------------------------------------------------------------------------

  private @Nullable BanTarget target(CommandSource source, String[] args, int[] consumed) {
    if (args.length == 0) {
      return null;
    }
    String first = args[0].toLowerCase(Locale.ROOT);
    try {
      if ((KINDS.contains(first) || first.equals("cidr")) && args.length >= 2) {
        consumed[0] = 2;
        String value = args[1];
        if (first.equals("ip") || first.equals("cidr")) {
          Optional<Player> online = core.server().getPlayer(value);
          if (online.isPresent()) {
            InetAddress address = IpKeys.of(online.get().getRemoteAddress());
            if (address != null) {
              value = address.getHostAddress();
            }
          }
        }
        return BanTarget.parse(first, value);
      }
      consumed[0] = 1;
      String value = args[0];
      if (value.contains(".") && value.matches("[0-9./]+") || value.contains(":")) {
        return BanTarget.parse("ip", value);
      }
      return BanTarget.parse("name", value);
    } catch (IllegalArgumentException e) {
      error(source, e.getMessage());
      consumed[0] = -1;
      return null;
    }
  }

  private CompletableFuture<?> ban(CommandSource source, String[] args) {
    int[] consumed = new int[1];
    BanTarget target = target(source, args, consumed);
    if (target == null) {
      if (consumed[0] >= 0) {
        usage(source, "ban");
      }
      return done();
    }
    int index = consumed[0];
    Duration duration = null;
    if (index < args.length && !args[index].equalsIgnoreCase("perm") && Durations.isDuration(args[index])) {
      duration = Durations.parse(args[index]);
      index++;
    } else if (index < args.length && args[index].equalsIgnoreCase("perm")) {
      index++;
    }
    String reason = String.join(" ", Arrays.copyOfRange(args, index, args.length));
    if (duration != null && duration.isZero()) {
      error(source, "The duration must be longer than zero.");
      return done();
    }
    return core.bans().ban(new BanRequest(target, reason, actor(source), duration)).thenAccept(ban ->
        ok(source, "Ban <white>#<id></white> issued:</green> <white><target></white>" + DOT + "<yellow><expires>",
            "id", Long.toString(ban.id()), "target", target(ban), "expires", expires(ban)));
  }

  private CompletableFuture<?> unban(CommandSource source, String[] args) {
    if (args.length == 1 && args[0].matches("#?\\d+")) {
      long id = Long.parseLong(args[0].replace("#", ""));
      return core.bans().revoke(id, actor(source)).thenAccept(result -> {
        if (result.isPresent()) {
          ok(source, "Ban <white>#<id></white> lifted.", "id", Long.toString(id));
        } else {
          error(source, "No active ban #" + id + ".");
        }
      });
    }
    int[] consumed = new int[1];
    BanTarget target = target(source, args, consumed);
    if (target == null) {
      if (consumed[0] >= 0) {
        usage(source, "unban");
      }
      return done();
    }
    return core.bans().revoke(target, actor(source)).thenAccept(revoked -> {
      if (revoked.isEmpty()) {
        error(source, "No active bans for " + target.kind() + " " + target.value() + ".");
      } else {
        ok(source, "Lifted <white><count></white> ban(s).", "count", Integer.toString(revoked.size()));
      }
    });
  }

  private CompletableFuture<?> bans(CommandSource source, String[] args) {
    List<Ban> active = core.bans().active();
    int page = 1;
    if (args.length > 0) {
      try {
        page = Math.max(1, Integer.parseInt(args[0]));
      } catch (NumberFormatException e) {
        error(source, "The page must be a number.");
        return done();
      }
    }
    int pages = Math.max(1, (active.size() + 9) / 10);
    page = Math.min(page, pages);
    head(source, "<white><b>Active bans</b></white> <white><count></white> <dark_gray>· page <page>/<pages>",
        "count", Integer.toString(active.size()), "page", Integer.toString(page), "pages", Integer.toString(pages));
    if (active.isEmpty()) {
      send(source, LAST + "<gray>none");
    }
    for (Ban ban : active.subList((page - 1) * 10, Math.min(active.size(), page * 10))) {
      sendBanLine(source, ban);
    }
    return done();
  }

  private static void sendBanLine(CommandSource source, Ban ban) {
    send(source, "<dark_gray>  •</dark_gray> <gray>#<id></gray> <white><target></white>" + DOT + "<gray><reason></gray>"
            + DOT + "<yellow><expires></yellow> <dark_gray>by <actor>",
        "id", Long.toString(ban.id()), "target", target(ban),
        "reason", ban.reason().isEmpty() ? "no reason" : ban.reason(), "expires", expires(ban), "actor", ban.actor());
  }

  private CompletableFuture<?> banInfo(CommandSource source, String[] args) {
    if (args.length != 1 || !args[0].matches("#?\\d+")) {
      usage(source, "baninfo");
      return done();
    }
    long id = Long.parseLong(args[0].replace("#", ""));
    return core.bans().byId(id).thenAccept(found -> {
      if (found.isEmpty()) {
        error(source, "Ban #" + id + " not found.");
        return;
      }
      Ban ban = found.get();
      String status = ban.activeAt(Instant.now()) ? "<green>active"
          : ban.revokedAt() != null ? "<gray>lifted <white><revoked></white> by <white><by>" : "<gray>expired";
      head(source, "<white><b>Ban #<id></b></white>", "id", Long.toString(ban.id()));
      row(source, false, "Target", "<white><target>", "target", target(ban));
      row(source, false, "Reason", "<white><reason>", "reason", ban.reason().isEmpty() ? "no reason" : ban.reason());
      row(source, false, "Expires", "<yellow><expires>", "expires", expires(ban));
      row(source, false, "Issued", "<white><created></white> <dark_gray>by <actor>",
          "created", TIME.format(ban.createdAt()), "actor", ban.actor());
      row(source, true, "Status", status, "revoked", ban.revokedAt() == null ? "" : TIME.format(ban.revokedAt()),
          "by", ban.revokedBy() == null ? "" : ban.revokedBy());
    });
  }

  // ---- intel -----------------------------------------------------------------------------

  private @Nullable InetAddress resolveAddress(CommandSource source, String value) {
    Optional<Player> online = core.server().getPlayer(value);
    if (online.isPresent()) {
      return IpKeys.of(online.get().getRemoteAddress());
    }
    try {
      return IpKeys.canonical(IpRange.parseLiteral(value));
    } catch (IllegalArgumentException e) {
      error(source, "Expected an IP address or the name of an online player: " + value);
      return null;
    }
  }

  /**
   * Like {@link #resolveAddress}, but a player who is offline resolves to the address of their
   * most recent login from the history. Completes with {@code null} after reporting an error.
   */
  private CompletableFuture<@Nullable InetAddress> resolveKnownAddress(CommandSource source, String value) {
    Optional<Player> online = core.server().getPlayer(value);
    if (online.isPresent()) {
      return CompletableFuture.completedFuture(IpKeys.of(online.get().getRemoteAddress()));
    }
    try {
      return CompletableFuture.completedFuture(IpKeys.canonical(IpRange.parseLiteral(value)));
    } catch (IllegalArgumentException notAnAddress) {
      // Not an IP literal: try the name.
    }
    if (!value.matches("[A-Za-z0-9_]{1,16}")) {
      error(source, "Expected an IP address or a player name: " + value);
      return CompletableFuture.completedFuture(null);
    }
    return core.alts().history(value).thenApply(rows -> {
      Optional<Observation> last = rows.stream().max(java.util.Comparator.comparing(Observation::lastSeen));
      if (last.isEmpty()) {
        error(source, "No known address for " + value + ".");
        return null;
      }
      try {
        InetAddress address = IpKeys.canonical(IpRange.parseLiteral(last.get().address()));
        send(source, MARK + "<gray><name> is offline, using the last address</gray> <white><ip></white>"
            + " <dark_gray>(<seen>)", "name", value, "ip", last.get().address(), "seen", TIME.format(last.get().lastSeen()));
        return address;
      } catch (IllegalArgumentException corrupt) {
        error(source, "The stored address of " + value + " is invalid.");
        return null;
      }
    });
  }

  private static String geoLine(GeoInfo geo) {
    if (geo.isUnknown()) {
      return "no data";
    }
    StringBuilder out = new StringBuilder();
    if (geo.countryCode() != null) {
      out.append(geo.countryCode());
      if (geo.countryName() != null) {
        out.append(" ").append(geo.countryName());
      }
    }
    if (geo.city() != null) {
      out.append(", ").append(geo.city());
    }
    if (geo.asn() > 0) {
      out.append(out.isEmpty() ? "" : " · ").append("AS").append(geo.asn());
      if (geo.asOrganization() != null) {
        out.append(" ").append(geo.asOrganization());
      }
    }
    return out.toString();
  }

  private CompletableFuture<?> check(CommandSource source, String[] args) {
    if (args.length != 1) {
      usage(source, "check");
      return done();
    }
    return resolveKnownAddress(source, args[0]).thenCompose(address -> address == null ? done()
        : checkAddress(source, address).thenAccept(ignored -> { }));
  }

  private CompletableFuture<?> checkAddress(CommandSource source, InetAddress address) {
    return core.reputation().scan(address).thenCombine(core.altManager().address(address), (assessment, report) -> {
      sendAssessment(source, assessment);
      Optional<Ban> ban = core.bans().matchAddress(address);
      boolean blocked = core.protectionManager().temporaryBlocks().contains(address.getHostAddress());
      row(source, false, "Banned", ban.map(b -> "<red>yes</red> <white>#<id> <target>").orElse("<green>no"),
          "id", ban.map(b -> Long.toString(b.id())).orElse(""), "target", ban.map(ThirdVelocityCommand::target).orElse(""));
      row(source, false, "Rate-limit block", blocked ? "<red>yes" : "<green>no");
      row(source, true, "Accounts", "<white><list>", "list", report.accounts().isEmpty() ? "none"
          : report.accounts().stream().limit(15).map(Observation::name).collect(Collectors.joining(", ")));
      return null;
    });
  }

  private void sendAssessment(CommandSource source, IpAssessment assessment) {
    int[] thresholds = core.reputationManager().thresholds();
    String color = switch (assessment.verdict()) {
      case ALLOW -> "green";
      case FLAG -> "yellow";
      case DENY -> "red";
    };
    head(source, "<white><b><ip></b></white> <" + color + "><verdict></" + color + ">"
            + " <dark_gray>· score <score> · flag at <flag>, deny at <deny>",
        "ip", assessment.address().getHostAddress(), "verdict", assessment.verdict().name(),
        "score", Integer.toString(assessment.score()), "flag", Integer.toString(thresholds[0]),
        "deny", Integer.toString(thresholds[1]));
    row(source, false, "GeoIP", "<white><geo>", "geo", geoLine(assessment.geo()));
    row(source, false, "Lists", "<white><tags>", "tags",
        assessment.tags().isEmpty() ? "none" : String.join(", ", assessment.tags()));
    for (Signal signal : assessment.signals()) {
      send(source, "<dark_gray>  │   •</dark_gray> <" + (signal.points() > 0 ? "yellow" : "green") + "><points></"
              + (signal.points() > 0 ? "yellow" : "green") + "> <gray><detail>",
          "points", (signal.points() > 0 ? "+" : "") + signal.points(), "detail", signal.detail());
    }
  }

  private CompletableFuture<?> alts(CommandSource source, String[] args) {
    if (args.length != 1) {
      usage(source, "alts");
      return done();
    }
    return core.alts().alts(args[0]).thenAccept(report -> {
      head(source, "<white><b><name></b></white> <dark_gray>· linked accounts:</dark_gray> <white><count></white>"
              + " <dark_gray>· addresses:</dark_gray> <white><ips>",
          "name", report.subject(), "count", Integer.toString(report.links().size()),
          "ips", Integer.toString(report.addresses().size()));
      if (report.links().isEmpty()) {
        send(source, LAST + "<gray>none");
      }
      for (AltLink link : report.links().stream().limit(25).toList()) {
        String color = link.confidence() >= 0.8 ? "red" : link.confidence() >= 0.5 ? "yellow" : "gray";
        send(source, "<dark_gray>  •</dark_gray> <" + color + "><percent>%</" + color + "> <white><name></white>"
                + "<red><banned></red>" + DOT + "<gray><reasons></gray>" + DOT + "<gray><shared></gray>"
                + DOT + "<dark_gray>seen <seen>",
            "percent", Long.toString(Math.round(link.confidence() * 100)), "name", link.name(),
            "banned", link.ban() == null ? "" : " banned #" + link.ban().id(),
            "reasons", link.reasons().stream().map(Enum::name).map(r -> r.toLowerCase(Locale.ROOT).replace('_', ' '))
                .collect(Collectors.joining(", ")),
            "shared", String.join(", ", link.sharedAddresses().stream().limit(3).toList()),
            "seen", link.lastSeen() == null ? "never" : TIME.format(link.lastSeen()));
      }
    });
  }

  private CompletableFuture<?> ip(CommandSource source, String[] args) {
    if (args.length != 1) {
      usage(source, "ip");
      return done();
    }
    return resolveKnownAddress(source, args[0]).thenCompose(address -> address == null ? done()
        : core.alts().address(address).thenAccept(report -> {
      head(source, "<white><b><ip></b></white> <dark_gray>· accounts:</dark_gray> <white><count>", "ip", report.address(),
          "count", Integer.toString(report.accounts().size()));
      for (Observation account : report.accounts().stream().limit(25).toList()) {
        send(source, "<dark_gray>  •</dark_gray> <white><name></white>" + DOT + "<gray><logins> logins</gray>"
                + DOT + "<gray>last <seen></gray><green><auth>",
            "name", account.name(), "logins", Long.toString(account.connections()),
            "seen", TIME.format(account.lastSeen()), "auth", account.authenticated() ? " · password" : "");
      }
      if (!report.relatedAddresses().isEmpty()) {
        row(source, true, "Related addresses", "<white><list>", "list", report.relatedAddresses().entrySet().stream()
            .limit(15).map(e -> e.getKey() + " (" + e.getValue() + ")").collect(Collectors.joining(", ")));
      }
    }));
  }

  private CompletableFuture<?> history(CommandSource source, String[] args) {
    if (args.length != 1) {
      usage(source, "history");
      return done();
    }
    return core.alts().history(args[0]).thenAccept(rows -> {
      head(source, "<white><b><name></b></white> <dark_gray>· addresses:</dark_gray> <white><count>", "name", args[0],
          "count", Integer.toString(rows.size()));
      for (Observation row : rows.stream().limit(25).toList()) {
        GeoInfo geo = GeoInfo.UNKNOWN;
        try {
          geo = core.geoIp().lookup(IpRange.parseLiteral(row.address()));
        } catch (IllegalArgumentException ignored) {
          // Corrupt row.
        }
        send(source, "<dark_gray>  •</dark_gray> <white><ip></white>" + DOT + "<gray><geo></gray>" + DOT
                + "<gray><logins> logins</gray>" + DOT + "<dark_gray><first> → <last></dark_gray><green><auth>",
            "ip", row.address(), "geo", geoLine(geo), "logins", Long.toString(row.connections()),
            "first", TIME.format(row.firstSeen()), "last", TIME.format(row.lastSeen()),
            "auth", row.authenticated() ? " · password" : "");
      }
    });
  }

  private CompletableFuture<?> client(CommandSource source, String[] args) {
    if (args.length != 1) {
      usage(source, "client");
      return done();
    }
    Optional<Player> player = core.server().getPlayer(args[0]);
    Optional<ClientInfo> info = player.flatMap(p -> core.clients().get(p.getUniqueId()));
    if (info.isEmpty()) {
      error(source, "The player is offline.");
      return done();
    }
    ClientInfo c = info.get();
    head(source, "<white><b><name></b></white> <dark_gray>· client", "name", c.name());
    row(source, false, "Loader", "<white><loader></white> <dark_gray><version> · protocol <protocol>",
        "loader", c.loader().name().toLowerCase(Locale.ROOT), "version", c.version(), "protocol", Integer.toString(c.protocol()));
    row(source, false, "Brand", "<white><brand>", "brand", c.brand() == null ? "not sent" : c.brand());
    row(source, false, "Language", "<white><locale></white>" + DOT + "<gray>view distance</gray> <white><view>",
        "locale", c.locale() == null ? "not sent" : c.locale(),
        "view", c.viewDistance() < 0 ? "not sent" : Integer.toString(c.viewDistance()));
    row(source, false, "Detected", c.detections().isEmpty() ? "<green>nothing" : "<yellow><detections>",
        "detections", c.detections().stream().map(d -> d.label() + " (" + d.kind() + ")").collect(Collectors.joining(", ")));
    row(source, false, "Mods", "<white><mods></white> <dark_gray>(<count>)", "count", Integer.toString(c.mods().size()),
        "mods", c.mods().isEmpty() ? "none" : String.join(", ", c.mods().stream().limit(40).toList()));
    row(source, false, "Login UUID", "<white><uuid></white> <dark_gray><offline>",
        "uuid", c.loginUuid() == null ? "not sent" : c.loginUuid().toString(),
        "offline", c.offlineUuidMatches() == null ? "" : c.offlineUuidMatches() ? "standard offline" : "not an offline UUID");
    row(source, true, "Fingerprint", "<dark_gray><fp>", "fp", c.fingerprint());
    return done();
  }

  private void sendStatus(CommandSource source, String title, List<DatabaseStatus> statuses) {
    head(source, "<white><b><title></b></white>", "title", title);
    for (int i = 0; i < statuses.size(); i++) {
      DatabaseStatus status = statuses.get(i);
      send(source, (i == statuses.size() - 1 ? LAST : BRANCH) + (status.loaded() ? "<green>✔" : "<red>✘")
              + " <white><name></white>" + DOT + "<gray><entries> entries</gray>" + DOT + "<dark_gray>built <build>"
              + "</dark_gray><red><error>",
          "name", status.name(), "entries", status.entries() < 0 ? "?" : Long.toString(status.entries()),
          "build", status.buildTime() == null ? "never" : TIME.format(status.buildTime()),
          "error", status.lastError() == null ? "" : " · " + status.lastError());
    }
  }

  private CompletableFuture<?> geoip(CommandSource source, String[] args) {
    if (args.length > 0 && args[0].equalsIgnoreCase("update")) {
      head(source, "<gray>Updating GeoIP databases…");
      return core.geoIp().update().thenAccept(statuses -> {
        core.reputationManager().invalidate();
        sendStatus(source, "GeoIP updated", statuses);
      });
    }
    sendStatus(source, "GeoIP", core.geoIp().status());
    return done();
  }

  private CompletableFuture<?> lists(CommandSource source, String[] args) {
    if (args.length > 0 && args[0].equalsIgnoreCase("update")) {
      head(source, "<gray>Updating IP lists…");
      return core.ipLists().update().thenAccept(statuses -> sendStatus(source, "IP lists updated", statuses));
    }
    sendStatus(source, "IP lists", core.ipLists().status());
    return done();
  }

  private CompletableFuture<?> attack(CommandSource source) {
    TrafficSnapshot t = core.protection().traffic();
    head(source, "<white><b>Shield</b></white> <white><level>", "level", core.protection().level().name());
    row(source, false, "Per second", "<white><conn></white> <gray>connections</gray>" + DOT + "<white><blocked></white>"
            + " <gray>refused</gray>" + DOT + "<white><hs></white> <gray>logins</gray>" + DOT + "<white><pings></white> <gray>pings",
        "conn", Long.toString(t.connections()), "blocked", Long.toString(t.blocked()),
        "hs", Long.toString(t.handshakes()), "pings", Long.toString(t.pings()));
    row(source, false, "Traffic", "<white><in></white> <gray>KB/s in</gray>" + DOT + "<white><out></white> <gray>KB/s out</gray>"
            + DOT + "<white><packets></white> <gray>packets/s",
        "in", Long.toString(t.inboundBytes() / 1024), "out", Long.toString(t.outboundBytes() / 1024),
        "packets", Long.toString(t.outboundPackets()));
    row(source, true, "Connections", "<white><open></white> <gray>open</gray>" + DOT + "<white><blocks></white>"
            + " <gray>blocked</gray>" + DOT + "<white><known></white> <gray>known addresses",
        "open", Long.toString(t.openConnections()),
        "blocks", Integer.toString(core.protection().temporaryBlocks().size()),
        "known", Integer.toString(core.protectionManager().knownAddresses().size()));
    return done();
  }

  private CompletableFuture<?> unblock(CommandSource source, String[] args) {
    if (args.length != 1) {
      usage(source, "unblock");
      return done();
    }
    InetAddress address = resolveAddress(source, args[0]);
    if (address != null) {
      if (core.protectionManager().unblock(address)) {
        ok(source, "Temporary block lifted.");
      } else {
        error(source, "The address is not blocked.");
      }
    }
    return done();
  }

  private CompletableFuture<?> reload(CommandSource source) {
    try {
      core.reload();
      ok(source, "ThirdVelocity configs reloaded.");
    } catch (Exception e) {
      error(source, "Config not applied: " + e.getMessage());
    }
    return done();
  }

  /** Adds names from the login history to the online players wherever a player name is expected. */
  @Override
  public CompletableFuture<List<String>> suggestAsync(Invocation invocation) {
    List<String> base = suggest(invocation);
    String[] args = invocation.arguments();
    if (!namePosition(invocation.source(), args)) {
      return CompletableFuture.completedFuture(base);
    }
    return core.altManager().knownNames(args[args.length - 1], 30).<List<String>>thenApply(names -> {
      Set<String> merged = new java.util.LinkedHashSet<>(base);
      Set<String> seen = base.stream().map(n -> n.toLowerCase(Locale.ROOT)).collect(Collectors.toSet());
      names.stream().filter(n -> seen.add(n.toLowerCase(Locale.ROOT))).forEach(merged::add);
      return List.copyOf(merged);
    }).exceptionally(failure -> base);
  }

  private boolean namePosition(CommandSource source, String[] args) {
    if (args.length < 2) {
      return false;
    }
    String sub = args[0].toLowerCase(Locale.ROOT);
    if (!allowed(source, sub) || sub.equals("client")) {
      return false;
    }
    if (args.length == 2) {
      return !List.of("geoip", "lists", "attack", "reload", "bans", "baninfo", "unblock").contains(sub);
    }
    return args.length == 3 && (sub.equals("ban") || sub.equals("unban")) && args[1].equalsIgnoreCase("name");
  }

  @Override
  public List<String> suggest(Invocation invocation) {
    String[] args = invocation.arguments();
    CommandSource source = invocation.source();
    if (args.length <= 1) {
      String prefix = args.length == 0 ? "" : args[0].toLowerCase(Locale.ROOT);
      List<String> result = new ArrayList<>();
      for (String sub : SUBCOMMANDS.keySet()) {
        if (sub.startsWith(prefix) && allowed(source, sub)) {
          result.add(sub);
        }
      }
      return result;
    }
    String sub = args[0].toLowerCase(Locale.ROOT);
    String last = args[args.length - 1].toLowerCase(Locale.ROOT);
    if (!allowed(source, sub)) {
      return List.of();
    }
    if (args.length == 2) {
      List<String> result = new ArrayList<>();
      switch (sub) {
        case "ban", "unban" -> KINDS.stream().filter(k -> k.startsWith(last)).forEach(result::add);
        case "geoip", "lists" -> List.of("status", "update").stream().filter(k -> k.startsWith(last)).forEach(result::add);
        default -> {
        }
      }
      if (!List.of("geoip", "lists", "attack", "reload", "bans", "baninfo").contains(sub)) {
        core.server().getAllPlayers().stream().map(Player::getUsername)
            .filter(n -> n.toLowerCase(Locale.ROOT).startsWith(last)).forEach(result::add);
      }
      return result;
    }
    if (args.length == 3 && sub.equals("ban") && KINDS.contains(args[1].toLowerCase(Locale.ROOT))) {
      return core.server().getAllPlayers().stream().map(Player::getUsername)
          .filter(n -> n.toLowerCase(Locale.ROOT).startsWith(last)).toList();
    }
    return List.of();
  }
}
