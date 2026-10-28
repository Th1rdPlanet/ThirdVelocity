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
    SUBCOMMANDS.put("ban", new Sub("ban [ip|name|uuid|asn|country] <цель> [срок] [причина]",
        "забанить IP/подсеть, ник, UUID, AS или страну"));
    SUBCOMMANDS.put("unban", new Sub("unban <id> | unban [вид] <цель>", "снять бан"));
    SUBCOMMANDS.put("bans", new Sub("bans [страница]", "активные баны"));
    SUBCOMMANDS.put("baninfo", new Sub("baninfo <id>", "подробности бана"));
    SUBCOMMANDS.put("check", new Sub("check <ip|игрок>", "проверка IP: GeoIP, списки, оценка"));
    SUBCOMMANDS.put("alts", new Sub("alts <ник>", "твинки и связанные аккаунты"));
    SUBCOMMANDS.put("ip", new Sub("ip <ip|игрок>", "аккаунты на IP и связанные адреса"));
    SUBCOMMANDS.put("history", new Sub("history <ник>", "история адресов игрока"));
    SUBCOMMANDS.put("client", new Sub("client <игрок>", "клиент, моды, лаунчер"));
    SUBCOMMANDS.put("geoip", new Sub("geoip [status|update]", "базы GeoIP"));
    SUBCOMMANDS.put("lists", new Sub("lists [status|update]", "IP-списки"));
    SUBCOMMANDS.put("attack", new Sub("attack", "уровень атаки и трафик"));
    SUBCOMMANDS.put("unblock", new Sub("unblock <ip>", "снять временную блокировку"));
    SUBCOMMANDS.put("reload", new Sub("reload", "перечитать конфиги"));
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

  private static void send(CommandSource source, String format, String... placeholders) {
    TagResolver.Builder resolver = TagResolver.builder();
    for (int i = 0; i + 1 < placeholders.length; i += 2) {
      resolver.resolver(Placeholder.unparsed(placeholders[i], placeholders[i + 1] == null ? "" : placeholders[i + 1]));
    }
    source.sendMessage(MM.deserialize(format, resolver.build()));
  }

  private static void error(CommandSource source, String text) {
    send(source, "<red><text>", "text", text);
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
          ? "Недостаточно прав." : "Неизвестная подкоманда. /" + invocation.alias() + " help");
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
      error(source, "Ошибка: " + cause.getMessage());
      return null;
    });
  }

  private void help(CommandSource source) {
    send(source, "<gradient:#7f5af0:#2cb67d><b>ThirdVelocity</b></gradient> <gray><version>",
        "version", ThirdVelocityCore.VERSION);
    for (Map.Entry<String, Sub> entry : SUBCOMMANDS.entrySet()) {
      if (allowed(source, entry.getKey())) {
        send(source, " <aqua>/tv <usage></aqua> <dark_gray>—</dark_gray> <gray><description>",
            "usage", entry.getValue().usage(), "description", entry.getValue().description());
      }
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
        error(source, "Использование: /tv " + SUBCOMMANDS.get("ban").usage());
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
      error(source, "Срок должен быть больше нуля.");
      return done();
    }
    return core.bans().ban(new BanRequest(target, reason, actor(source), duration)).thenAccept(ban ->
        send(source, "<green>Бан <white>#<id></white> выдан: <white><target></white> <gray>(<expires>)</gray>",
            "id", Long.toString(ban.id()), "target", ban.target().kind() + " " + ban.target().value(),
            "expires", ban.expiresAt() == null ? "навсегда" : "до " + TIME.format(ban.expiresAt())));
  }

  private CompletableFuture<?> unban(CommandSource source, String[] args) {
    if (args.length == 1 && args[0].matches("#?\\d+")) {
      long id = Long.parseLong(args[0].replace("#", ""));
      return core.bans().revoke(id, actor(source)).thenAccept(result -> {
        if (result.isPresent()) {
          send(source, "<green>Бан <white>#<id></white> снят.", "id", Long.toString(id));
        } else {
          error(source, "Активного бана #" + id + " нет.");
        }
      });
    }
    int[] consumed = new int[1];
    BanTarget target = target(source, args, consumed);
    if (target == null) {
      if (consumed[0] >= 0) {
        error(source, "Использование: /tv " + SUBCOMMANDS.get("unban").usage());
      }
      return done();
    }
    return core.bans().revoke(target, actor(source)).thenAccept(revoked -> {
      if (revoked.isEmpty()) {
        error(source, "Активных банов для " + target.kind() + " " + target.value() + " нет.");
      } else {
        send(source, "<green>Снято банов: <white><count></white>.", "count", Integer.toString(revoked.size()));
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
        error(source, "Страница должна быть числом.");
        return done();
      }
    }
    int pages = Math.max(1, (active.size() + 9) / 10);
    page = Math.min(page, pages);
    send(source, "<gold>Активные баны: <white><count></white> <gray>(стр. <page>/<pages>)",
        "count", Integer.toString(active.size()), "page", Integer.toString(page), "pages", Integer.toString(pages));
    for (Ban ban : active.subList((page - 1) * 10, Math.min(active.size(), page * 10))) {
      sendBanLine(source, ban);
    }
    return done();
  }

  private static void sendBanLine(CommandSource source, Ban ban) {
    send(source, " <gray>#<id></gray> <white><target></white> <dark_gray>|</dark_gray> <gray><reason></gray>"
            + " <dark_gray>|</dark_gray> <yellow><expires></yellow> <dark_gray>(<actor>)",
        "id", Long.toString(ban.id()), "target", ban.target().kind() + " " + ban.target().value(),
        "reason", ban.reason().isEmpty() ? "-" : ban.reason(),
        "expires", ban.expiresAt() == null ? "навсегда" : "до " + TIME.format(ban.expiresAt()),
        "actor", ban.actor());
  }

  private CompletableFuture<?> banInfo(CommandSource source, String[] args) {
    if (args.length != 1 || !args[0].matches("#?\\d+")) {
      error(source, "Использование: /tv baninfo <id>");
      return done();
    }
    long id = Long.parseLong(args[0].replace("#", ""));
    return core.bans().byId(id).thenAccept(found -> {
      if (found.isEmpty()) {
        error(source, "Бан #" + id + " не найден.");
        return;
      }
      Ban ban = found.get();
      sendBanLine(source, ban);
      send(source, " <gray>Создан: <white><created></white>  Статус: <status>",
          "created", TIME.format(ban.createdAt()),
          "status", ban.activeAt(Instant.now()) ? "активен"
              : ban.revokedAt() != null ? "снят " + TIME.format(ban.revokedAt()) + " (" + ban.revokedBy() + ")" : "истёк");
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
      error(source, "Нужен IP-адрес или ник игрока онлайн: " + value);
      return null;
    }
  }

  private static String geoLine(GeoInfo geo) {
    if (geo.isUnknown()) {
      return "нет данных";
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
      out.append(out.isEmpty() ? "" : " • ").append("AS").append(geo.asn());
      if (geo.asOrganization() != null) {
        out.append(" ").append(geo.asOrganization());
      }
    }
    return out.toString();
  }

  private CompletableFuture<?> check(CommandSource source, String[] args) {
    if (args.length != 1) {
      error(source, "Использование: /tv check <ip|игрок>");
      return done();
    }
    InetAddress address = resolveAddress(source, args[0]);
    if (address == null) {
      return done();
    }
    return core.reputation().scan(address).thenCombine(core.altManager().address(address), (assessment, report) -> {
      sendAssessment(source, assessment);
      Optional<Ban> ban = core.bans().matchAddress(address);
      ban.ifPresent(b -> send(source, " <red>Забанен:</red> <white>#<id> <target>", "id", Long.toString(b.id()),
          "target", b.target().kind() + " " + b.target().value()));
      if (core.protectionManager().temporaryBlocks().contains(address.getHostAddress())) {
        send(source, " <red>Временно заблокирован лимитом подключений.");
      }
      send(source, " <gray>Аккаунты на адресе: <white><list>", "list", report.accounts().isEmpty() ? "нет"
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
    send(source, "<gold>IP <white><ip></white>: <" + color + "><verdict></" + color + "> <gray>(оценка <score>,"
            + " пороги <flag>/<deny>)",
        "ip", assessment.address().getHostAddress(), "verdict", assessment.verdict().name(),
        "score", Integer.toString(assessment.score()), "flag", Integer.toString(thresholds[0]),
        "deny", Integer.toString(thresholds[1]));
    send(source, " <gray>GeoIP: <white><geo>", "geo", geoLine(assessment.geo()));
    send(source, " <gray>Списки: <white><tags>", "tags",
        assessment.tags().isEmpty() ? "нет" : String.join(", ", assessment.tags()));
    for (Signal signal : assessment.signals()) {
      send(source, "  <dark_gray>•</dark_gray> <white><points></white> <gray><detail> <dark_gray>(<id>)",
          "points", (signal.points() > 0 ? "+" : "") + signal.points(), "detail", signal.detail(), "id", signal.id());
    }
  }

  private CompletableFuture<?> alts(CommandSource source, String[] args) {
    if (args.length != 1) {
      error(source, "Использование: /tv alts <ник>");
      return done();
    }
    return core.alts().alts(args[0]).thenAccept(report -> {
      send(source, "<gold>Связанные аккаунты <white><name></white>: <white><count></white> <gray>(адресов: <ips>)",
          "name", report.subject(), "count", Integer.toString(report.links().size()),
          "ips", Integer.toString(report.addresses().size()));
      for (AltLink link : report.links().stream().limit(25).toList()) {
        String color = link.confidence() >= 0.8 ? "red" : link.confidence() >= 0.5 ? "yellow" : "gray";
        send(source, " <" + color + "><percent>%</" + color + "> <white><name></white><banned> <dark_gray>"
                + "<reasons> • <shared> • <seen>",
            "percent", Long.toString(Math.round(link.confidence() * 100)), "name", link.name(),
            "banned", link.ban() == null ? "" : " [БАН #" + link.ban().id() + "]",
            "reasons", link.reasons().stream().map(Enum::name).map(r -> r.toLowerCase(Locale.ROOT))
                .collect(Collectors.joining(",")),
            "shared", String.join(", ", link.sharedAddresses().stream().limit(3).toList()),
            "seen", link.lastSeen() == null ? "-" : TIME.format(link.lastSeen()));
      }
    });
  }

  private CompletableFuture<?> ip(CommandSource source, String[] args) {
    if (args.length != 1) {
      error(source, "Использование: /tv ip <ip|игрок>");
      return done();
    }
    InetAddress address = resolveAddress(source, args[0]);
    if (address == null) {
      return done();
    }
    return core.alts().address(address).thenAccept(report -> {
      send(source, "<gold>Адрес <white><ip></white>: аккаунтов <white><count>", "ip", report.address(),
          "count", Integer.toString(report.accounts().size()));
      for (Observation account : report.accounts().stream().limit(25).toList()) {
        send(source, " <white><name></white> <gray>входов <logins>, последний <seen><auth>",
            "name", account.name(), "logins", Long.toString(account.connections()),
            "seen", TIME.format(account.lastSeen()), "auth", account.authenticated() ? ", с паролем" : "");
      }
      if (!report.relatedAddresses().isEmpty()) {
        send(source, " <gray>Связанные адреса: <white><list>", "list", report.relatedAddresses().entrySet().stream()
            .limit(15).map(e -> e.getKey() + " (" + e.getValue() + ")").collect(Collectors.joining(", ")));
      }
    });
  }

  private CompletableFuture<?> history(CommandSource source, String[] args) {
    if (args.length != 1) {
      error(source, "Использование: /tv history <ник>");
      return done();
    }
    return core.alts().history(args[0]).thenAccept(rows -> {
      send(source, "<gold>Адреса <white><name></white>: <white><count>", "name", args[0],
          "count", Integer.toString(rows.size()));
      for (Observation row : rows.stream().limit(25).toList()) {
        GeoInfo geo = GeoInfo.UNKNOWN;
        try {
          geo = core.geoIp().lookup(IpRange.parseLiteral(row.address()));
        } catch (IllegalArgumentException ignored) {
          // Corrupt row.
        }
        send(source, " <white><ip></white> <gray><geo> • входов <logins> • <first> — <last><auth>",
            "ip", row.address(), "geo", geoLine(geo), "logins", Long.toString(row.connections()),
            "first", TIME.format(row.firstSeen()), "last", TIME.format(row.lastSeen()),
            "auth", row.authenticated() ? " • с паролем" : "");
      }
    });
  }

  private CompletableFuture<?> client(CommandSource source, String[] args) {
    if (args.length != 1) {
      error(source, "Использование: /tv client <игрок>");
      return done();
    }
    Optional<Player> player = core.server().getPlayer(args[0]);
    Optional<ClientInfo> info = player.flatMap(p -> core.clients().get(p.getUniqueId()));
    if (info.isEmpty()) {
      error(source, "Игрок не в сети.");
      return done();
    }
    ClientInfo c = info.get();
    send(source, "<gold>Клиент <white><name></white>: <white><loader></white> <gray><version> (протокол <protocol>)",
        "name", c.name(), "loader", c.loader().name(), "version", c.version(),
        "protocol", Integer.toString(c.protocol()));
    send(source, " <gray>Brand: <white><brand></white>  Язык: <white><locale></white>  Дальность: <white><view>",
        "brand", c.brand() == null ? "-" : c.brand(), "locale", c.locale() == null ? "-" : c.locale(),
        "view", c.viewDistance() < 0 ? "-" : Integer.toString(c.viewDistance()));
    send(source, " <gray>Определено: <white><detections>", "detections", c.detections().isEmpty() ? "ничего"
        : c.detections().stream().map(d -> d.label() + " (" + d.kind() + ")").collect(Collectors.joining(", ")));
    send(source, " <gray>Моды/неймспейсы (<count>): <white><mods>", "count", Integer.toString(c.mods().size()),
        "mods", c.mods().isEmpty() ? "-" : String.join(", ", c.mods().stream().limit(40).toList()));
    send(source, " <gray>UUID при входе: <white><uuid></white> <dark_gray>(<offline>)",
        "uuid", c.loginUuid() == null ? "-" : c.loginUuid().toString(),
        "offline", c.offlineUuidMatches() == null ? "n/a"
            : c.offlineUuidMatches() ? "стандартный offline" : "НЕ offline UUID");
    send(source, " <gray>Отпечаток: <white><fp>", "fp", c.fingerprint());
    return done();
  }

  private void sendStatus(CommandSource source, String title, List<DatabaseStatus> statuses) {
    send(source, "<gold><title>", "title", title);
    for (DatabaseStatus status : statuses) {
      send(source, " <state> <white><name></white> <gray>записей <entries> • сборка <build><error>",
          "state", status.loaded() ? "✔" : "✘", "name", status.name(),
          "entries", status.entries() < 0 ? "-" : Long.toString(status.entries()),
          "build", status.buildTime() == null ? "-" : TIME.format(status.buildTime()),
          "error", status.lastError() == null ? "" : " • " + status.lastError());
    }
  }

  private CompletableFuture<?> geoip(CommandSource source, String[] args) {
    if (args.length > 0 && args[0].equalsIgnoreCase("update")) {
      send(source, "<gray>Обновляю базы GeoIP…");
      return core.geoIp().update().thenAccept(statuses -> {
        core.reputationManager().invalidate();
        sendStatus(source, "GeoIP после обновления", statuses);
      });
    }
    sendStatus(source, "GeoIP", core.geoIp().status());
    return done();
  }

  private CompletableFuture<?> lists(CommandSource source, String[] args) {
    if (args.length > 0 && args[0].equalsIgnoreCase("update")) {
      send(source, "<gray>Обновляю IP-списки…");
      return core.ipLists().update().thenAccept(statuses -> sendStatus(source, "IP-списки после обновления", statuses));
    }
    sendStatus(source, "IP-списки", core.ipLists().status());
    return done();
  }

  private CompletableFuture<?> attack(CommandSource source) {
    TrafficSnapshot t = core.protection().traffic();
    send(source, "<gold>Уровень атаки: <white><level>", "level", core.protection().level().name());
    send(source, " <gray>За секунду: подключений <white><conn></white>, отклонено <white><blocked></white>,"
            + " входов <white><hs></white>, пингов <white><pings>",
        "conn", Long.toString(t.connections()), "blocked", Long.toString(t.blocked()),
        "hs", Long.toString(t.handshakes()), "pings", Long.toString(t.pings()));
    send(source, " <gray>Трафик: вход <white><in></white> КБ/с, выход <white><out></white> КБ/с,"
            + " <white><packets></white> пакетов/с, открыто <white><open>",
        "in", Long.toString(t.inboundBytes() / 1024), "out", Long.toString(t.outboundBytes() / 1024),
        "packets", Long.toString(t.outboundPackets()), "open", Long.toString(t.openConnections()));
    send(source, " <gray>Временных блокировок: <white><blocks></white>, известных адресов: <white><known>",
        "blocks", Integer.toString(core.protection().temporaryBlocks().size()),
        "known", Integer.toString(core.protectionManager().knownAddresses().size()));
    return done();
  }

  private CompletableFuture<?> unblock(CommandSource source, String[] args) {
    if (args.length != 1) {
      error(source, "Использование: /tv unblock <ip>");
      return done();
    }
    InetAddress address = resolveAddress(source, args[0]);
    if (address != null) {
      if (core.protectionManager().unblock(address)) {
        send(source, "<green>Временная блокировка снята.");
      } else {
        error(source, "Адрес не заблокирован.");
      }
    }
    return done();
  }

  private CompletableFuture<?> reload(CommandSource source) {
    try {
      core.reload();
      send(source, "<green>Конфиги ThirdVelocity перечитаны.");
    } catch (Exception e) {
      error(source, "Конфиг не применён: " + e.getMessage());
    }
    return done();
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
