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

package ru.moonlightproject.dev.thirdvelocity.proxy.client;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.player.PlayerSettings;
import com.velocitypowered.api.proxy.player.SkinParts;
import com.velocitypowered.api.util.ModInfo;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;
import ru.moonlightproject.dev.thirdvelocity.api.client.ClientInfo;
import ru.moonlightproject.dev.thirdvelocity.api.client.ClientLoader;
import ru.moonlightproject.dev.thirdvelocity.api.client.ClientService;
import ru.moonlightproject.dev.thirdvelocity.api.client.Detection;
import ru.moonlightproject.dev.thirdvelocity.api.event.ClientDetectedEvent;
import ru.moonlightproject.dev.thirdvelocity.proxy.ThirdVelocityCore;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.ConfigNode;

/**
 * Collects handshake, login, brand, channel and settings data and evaluates the detection rules
 * of {@code clients.yml}.
 */
public final class ClientTracker implements ClientService {

  private static final Logger LOGGER = LogManager.getLogger("ThirdVelocity");

  /** Data captured before the player object exists. */
  private record LoginData(int protocol, String version, String rawHost, @Nullable UUID loginUuid) {
  }

  /** A configured detection rule; every present matcher must match. */
  private record Rule(String id, String kind, String label, String action, String message,
      @Nullable Pattern brand, @Nullable Pattern channel, @Nullable Pattern mod, @Nullable Pattern host,
      @Nullable Boolean uuidMismatch, int minProtocol, int maxProtocol) {

    boolean matches(Session s) {
      if (s.protocol < minProtocol || s.protocol > maxProtocol) {
        return false;
      }
      if (brand != null && (s.brand == null || !brand.matcher(s.brand).find())) {
        return false;
      }
      if (channel != null && s.channels.stream().noneMatch(c -> channel.matcher(c).find())) {
        return false;
      }
      if (mod != null && s.mods.stream().noneMatch(m -> mod.matcher(m).find())) {
        return false;
      }
      if (host != null && !host.matcher(s.rawHost).find()) {
        return false;
      }
      if (uuidMismatch != null) {
        if (s.offlineUuidMatches == null || uuidMismatch == s.offlineUuidMatches) {
          return false;
        }
      }
      return brand != null || channel != null || mod != null || host != null || uuidMismatch != null;
    }
  }

  /** Mutable per-player state; guarded by its own monitor. */
  private static final class Session {
    UUID playerId;
    String name;
    int protocol;
    String version;
    String rawHost = "";
    @Nullable UUID loginUuid;
    @Nullable Boolean offlineUuidMatches;
    @Nullable String brand;
    final Set<String> channels = new LinkedHashSet<>();
    final Set<String> mods = new TreeSet<>();
    @Nullable String locale;
    int viewDistance = -1;
    int skinParts = -1;
    boolean mainHandRight = true;
    boolean settingsReceived;
    List<Detection> detections = List.of();
    final Set<String> actedRules = new LinkedHashSet<>();
    final Set<String> behaviour = new LinkedHashSet<>();
    @Nullable ScheduledFuture<?> pending;
    @Nullable String storedFingerprint;
    volatile @Nullable ClientInfo snapshot;
  }

  private final ThirdVelocityCore core;
  private final Map<UUID, Session> sessions = new ConcurrentHashMap<>();
  private final Map<String, Boolean> flaggedNames = new ConcurrentHashMap<>();
  private final Cache<String, LoginData> logins = Caffeine.newBuilder()
      .expireAfterWrite(2, TimeUnit.MINUTES).maximumSize(100_000).build();
  private volatile boolean enabled = true;
  private volatile List<Rule> rules = List.of();
  private volatile Set<String> ignoredNamespaces = Set.of();
  private volatile boolean logDetections;
  private volatile boolean behaviourEnabled;
  private volatile long behaviourDelayMillis = 10_000;
  private volatile Map<String, String> behaviourActions = Map.of();
  private static final Pattern VANILLA_LOCALE = Pattern.compile("^[a-z]{2,3}_[a-z0-9]{2,4}$");

  /**
   * Creates the tracker.
   *
   * @param core core
   */
  public ClientTracker(ThirdVelocityCore core) {
    this.core = core;
  }

  /**
   * Applies {@code clients.yml}.
   *
   * @param config root node
   */
  public void apply(ConfigNode config) {
    enabled = config.bool("enabled", true);
    logDetections = config.bool("log-detections", true);
    Set<String> ignored = new LinkedHashSet<>();
    for (String namespace : config.strings("ignored-namespaces")) {
      ignored.add(namespace.toLowerCase(Locale.ROOT));
    }
    ignoredNamespaces = Set.copyOf(ignored);
    List<Rule> parsed = new ArrayList<>();
    for (ConfigNode node : config.sections("rules")) {
      if (!node.bool("enabled", true)) {
        continue;
      }
      String id = node.string("id", "");
      if (id.isBlank()) {
        throw new ConfigNode.ConfigException("clients.yml: every rule needs an id");
      }
      String action = node.string("action", "none").toLowerCase(Locale.ROOT);
      if (!List.of("none", "flag", "kick").contains(action)) {
        throw new ConfigNode.ConfigException("clients.yml: rule " + id + ": action must be none, flag or kick");
      }
      Boolean uuidMismatch = node.has("uuid-mismatch") ? node.bool("uuid-mismatch", false) : null;
      Rule rule = new Rule(id, node.string("kind", "client").toLowerCase(Locale.ROOT), node.string("label", id),
          action, node.string("message", ""), pattern(node, "brand", id), pattern(node, "channel", id),
          pattern(node, "mod", id), pattern(node, "host", id), uuidMismatch,
          node.integer("min-protocol", 0, 0, Integer.MAX_VALUE),
          node.integer("max-protocol", Integer.MAX_VALUE, 0, Integer.MAX_VALUE));
      if (rule.brand() == null && rule.channel() == null && rule.mod() == null && rule.host() == null
          && rule.uuidMismatch() == null) {
        throw new ConfigNode.ConfigException("clients.yml: rule " + id + " has no matcher");
      }
      parsed.add(rule);
    }
    rules = List.copyOf(parsed);
    ConfigNode behaviour = config.section("behaviour");
    behaviourEnabled = behaviour.bool("enabled", true);
    behaviourDelayMillis = behaviour.duration("check-after", java.time.Duration.ofSeconds(10)).toMillis();
    Map<String, String> actions = new java.util.HashMap<>();
    ConfigNode signals = behaviour.section("signals");
    for (String signal : List.of("no-brand", "no-settings", "odd-locale", "odd-view-distance")) {
      ConfigNode node = signals.section(signal);
      if (!node.bool("enabled", true)) {
        continue;
      }
      String action = node.string("action", "none").toLowerCase(Locale.ROOT);
      if (!List.of("none", "flag", "kick").contains(action)) {
        throw new ConfigNode.ConfigException("clients.yml: behaviour.signals." + signal + ".action must be none, flag or kick");
      }
      actions.put(signal, action);
    }
    behaviourActions = Map.copyOf(actions);
  }

  private static final Map<String, String> BEHAVIOUR_LABELS = Map.of(
      "no-brand", "Не прислал brand",
      "no-settings", "Не прислал настройки клиента",
      "odd-locale", "Нестандартный формат языка",
      "odd-view-distance", "Невозможная дальность прорисовки");

  /** Records a behaviour signal once per session and applies its action. */
  private void behaviourSignal(Session s, Player player, String signal) {
    String action = behaviourActions.get(signal);
    if (action == null) {
      return;
    }
    synchronized (s) {
      if (!s.behaviour.add(signal)) {
        return;
      }
    }
    java.net.InetAddress address = ru.moonlightproject.dev.thirdvelocity.proxy.util.IpKeys.of(player.getRemoteAddress());
    if (address != null) {
      core.reputation().report(address, "client." + signal);
    }
    if (logDetections) {
      LOGGER.info("[!] client   » {} » поведенческий сигнал {}", s.name, signal);
    }
    if (action.equals("flag")) {
      flaggedNames.put(s.name.toLowerCase(Locale.ROOT), Boolean.TRUE);
    } else if (action.equals("kick")) {
      player.disconnect(core.messages().render("client-kick", "rule", BEHAVIOUR_LABELS.get(signal)));
      return;
    }
    update(s, player);
  }

  private void checkBehaviour(Session s, Player player) {
    if (!behaviourEnabled || !sessions.containsKey(s.playerId) || !player.isActive()) {
      return;
    }
    boolean noBrand;
    boolean noSettings;
    synchronized (s) {
      noBrand = s.brand == null;
      noSettings = !s.settingsReceived;
    }
    if (noBrand) {
      behaviourSignal(s, player, "no-brand");
    }
    if (noSettings) {
      behaviourSignal(s, player, "no-settings");
    }
  }

  private static @Nullable Pattern pattern(ConfigNode node, String key, String id) {
    if (!node.has(key)) {
      return null;
    }
    try {
      return Pattern.compile(node.string(key, ""));
    } catch (PatternSyntaxException e) {
      throw new ConfigNode.ConfigException("clients.yml: rule " + id + ": invalid " + key + " regex: "
          + e.getDescription());
    }
  }

  private static String loginKey(String name, String address) {
    return name.toLowerCase(Locale.ROOT) + "|" + address;
  }

  /**
   * Remembers login-stage data until the player object exists.
   *
   * @param name player name
   * @param address player address text
   * @param protocol protocol number
   * @param version version name
   * @param rawHost raw handshake host
   * @param loginUuid UUID from the login packet
   */
  public void rememberLogin(String name, String address, int protocol, String version, String rawHost,
      @Nullable UUID loginUuid) {
    logins.put(loginKey(name, address), new LoginData(protocol, version, rawHost, loginUuid));
  }

  /**
   * Starts tracking a player after login.
   *
   * @param player player
   * @param address address text
   */
  public void start(Player player, String address) {
    Session s = new Session();
    s.playerId = player.getUniqueId();
    s.name = player.getUsername();
    LoginData data = logins.asMap().remove(loginKey(player.getUsername(), address));
    s.protocol = player.getProtocolVersion().getProtocol();
    s.version = player.getProtocolVersion().getMostRecentSupportedVersion();
    if (data != null) {
      s.rawHost = data.rawHost();
      s.loginUuid = data.loginUuid();
    } else {
      s.rawHost = player.getRawVirtualHost().orElse("");
    }
    if (s.loginUuid != null && !player.isOnlineMode()) {
      UUID offline = UUID.nameUUIDFromBytes(("OfflinePlayer:" + player.getUsername()).getBytes(StandardCharsets.UTF_8));
      s.offlineUuidMatches = offline.equals(s.loginUuid);
    }
    if (player.getModInfo().isPresent()) {
      addMods(s, player.getModInfo().get());
    }
    sessions.put(s.playerId, s);
    if (behaviourEnabled) {
      core.scheduler().schedule(() -> checkBehaviour(s, player), behaviourDelayMillis, TimeUnit.MILLISECONDS);
    }
    update(s, player);
  }

  /**
   * Stops tracking a player.
   *
   * @param playerId player UUID
   */
  public void stop(UUID playerId) {
    Session s = sessions.remove(playerId);
    if (s != null) {
      synchronized (s) {
        if (s.pending != null) {
          s.pending.cancel(false);
        }
      }
      if (sessions.values().stream().noneMatch(other -> other.name.equalsIgnoreCase(s.name))) {
        flaggedNames.remove(s.name.toLowerCase(Locale.ROOT));
      }
    }
  }

  /**
   * Records the client brand.
   *
   * @param player player
   * @param brand brand
   */
  public void brand(Player player, String brand) {
    Session s = sessions.get(player.getUniqueId());
    if (s == null) {
      return;
    }
    synchronized (s) {
      s.brand = brand.length() > 128 ? brand.substring(0, 128) : brand;
    }
    update(s, player);
  }

  /**
   * Records registered channels.
   *
   * @param player player
   * @param channels channel ids
   */
  public void channels(Player player, Collection<String> channels) {
    Session s = sessions.get(player.getUniqueId());
    if (s == null) {
      return;
    }
    synchronized (s) {
      for (String channel : channels) {
        if (s.channels.size() >= 1024) {
          break;
        }
        String lower = channel.toLowerCase(Locale.ROOT);
        s.channels.add(lower);
        int colon = lower.indexOf(':');
        String namespace = colon > 0 ? lower.substring(0, colon) : lower;
        if (!namespace.isEmpty() && !ignoredNamespaces.contains(namespace) && s.mods.size() < 512) {
          s.mods.add(namespace);
        }
      }
    }
    update(s, player);
  }

  /**
   * Records legacy Forge mod info.
   *
   * @param player player
   * @param info mod list
   */
  public void modInfo(Player player, ModInfo info) {
    Session s = sessions.get(player.getUniqueId());
    if (s == null) {
      return;
    }
    synchronized (s) {
      addMods(s, info);
    }
    update(s, player);
  }

  private static void addMods(Session s, ModInfo info) {
    for (ModInfo.Mod mod : info.getMods()) {
      if (s.mods.size() >= 512) {
        break;
      }
      s.mods.add(mod.getId().toLowerCase(Locale.ROOT));
    }
  }

  /**
   * Records client settings.
   *
   * @param player player
   * @param settings settings
   */
  public void settings(Player player, PlayerSettings settings) {
    Session s = sessions.get(player.getUniqueId());
    if (s == null) {
      return;
    }
    String rawLocale = settings instanceof com.velocitypowered.proxy.connection.client.ClientSettingsWrapper wrapper
        ? wrapper.getRawLocale() : settings.getLocale().toString().toLowerCase(Locale.ROOT);
    if (behaviourEnabled && !VANILLA_LOCALE.matcher(rawLocale).matches()) {
      behaviourSignal(s, player, "odd-locale");
    }
    if (behaviourEnabled && (settings.getViewDistance() < 2 || settings.getViewDistance() > 32)) {
      behaviourSignal(s, player, "odd-view-distance");
    }
    synchronized (s) {
      s.locale = rawLocale.toLowerCase(Locale.ROOT);
      s.viewDistance = settings.getViewDistance();
      s.skinParts = mask(settings.getSkinParts());
      s.mainHandRight = settings.getMainHand() == PlayerSettings.MainHand.RIGHT;
      s.settingsReceived = true;
    }
    update(s, player);
  }

  private static int mask(SkinParts parts) {
    int mask = 0;
    mask |= parts.hasCape() ? 1 : 0;
    mask |= parts.hasJacket() ? 2 : 0;
    mask |= parts.hasLeftSleeve() ? 4 : 0;
    mask |= parts.hasRightSleeve() ? 8 : 0;
    mask |= parts.hasLeftPants() ? 16 : 0;
    mask |= parts.hasRightPants() ? 32 : 0;
    mask |= parts.hasHat() ? 64 : 0;
    return mask;
  }

  private ClientLoader loader(Session s) {
    String host = s.rawHost;
    String brand = s.brand == null ? "" : s.brand.toLowerCase(Locale.ROOT);
    if (brand.contains("neoforge")) {
      return ClientLoader.NEOFORGE;
    }
    if (host.contains("\0FML\0") || host.contains("\0FML2\0") || host.contains("\0FML3\0")
        || host.contains("\0FORGE") || brand.contains("forge")) {
      return ClientLoader.FORGE;
    }
    if (brand.startsWith("lunarclient")) {
      return ClientLoader.LUNAR;
    }
    if (brand.contains("feather")) {
      return ClientLoader.FEATHER;
    }
    if (brand.contains("labymod") || s.channels.stream().anyMatch(c -> c.startsWith("labymod"))) {
      return ClientLoader.LABYMOD;
    }
    if (brand.contains("badlion") || s.channels.stream().anyMatch(c -> c.startsWith("badlion:"))) {
      return ClientLoader.BADLION;
    }
    if (brand.contains("quilt")) {
      return ClientLoader.QUILT;
    }
    if (brand.contains("fabric")) {
      return ClientLoader.FABRIC;
    }
    if (brand.equals("vanilla")) {
      return ClientLoader.VANILLA;
    }
    return brand.isEmpty() ? ClientLoader.UNKNOWN : ClientLoader.OTHER;
  }

  private void update(Session s, Player player) {
    if (!enabled) {
      return;
    }
    List<Rule> kicks = new ArrayList<>();
    ClientInfo info;
    synchronized (s) {
      List<Detection> detections = new ArrayList<>();
      for (Rule rule : rules) {
        if (rule.matches(s)) {
          detections.add(new Detection(rule.id(), rule.kind(), rule.label(), rule.action()));
          if (s.actedRules.add(rule.id())) {
            switch (rule.action()) {
              case "flag" -> flaggedNames.put(s.name.toLowerCase(Locale.ROOT), Boolean.TRUE);
              case "kick" -> kicks.add(rule);
              default -> {
              }
            }
          }
        }
      }
      for (String signal : s.behaviour) {
        detections.add(new Detection("behaviour:" + signal, "behaviour", BEHAVIOUR_LABELS.get(signal),
            behaviourActions.getOrDefault(signal, "none")));
      }
      boolean changed = !detections.equals(s.detections);
      s.detections = List.copyOf(detections);
      info = snapshot(s);
      s.snapshot = info;
      if (changed && logDetections && !detections.isEmpty()) {
        LOGGER.info("[*] client   » {} » {}", s.name,
            detections.stream().map(Detection::label).toList());
      }
      // Debounce: settings, brand and channels arrive within a moment of each other.
      if (s.pending != null) {
        s.pending.cancel(false);
      }
      s.pending = core.scheduler().schedule(() -> settle(s), 3, TimeUnit.SECONDS);
    }
    for (Rule rule : kicks) {
      LOGGER.info("[-] client   » {} кикнут правилом {}", s.name, rule.id());
      core.reputation().report(player.getRemoteAddress().getAddress(), "client.kicked");
      player.disconnect(core.messages().render(rule.message().isBlank() ? "client-kick" : "client-kick-custom",
          "rule", rule.label(), "message", rule.message()));
    }
  }

  private void settle(Session s) {
    ClientInfo info;
    boolean store;
    synchronized (s) {
      s.pending = null;
      info = s.snapshot;
      store = info != null && s.settingsReceived && !info.fingerprint().equals(s.storedFingerprint);
      if (store) {
        s.storedFingerprint = info.fingerprint();
      }
    }
    if (info == null || !sessions.containsKey(s.playerId)) {
      return;
    }
    core.fire(new ClientDetectedEvent(info));
    if (store) {
      core.altManager().recordFingerprint(s.name, info.fingerprint());
    }
  }

  private ClientInfo snapshot(Session s) {
    String launcher = s.detections.stream().filter(d -> d.kind().equals("launcher")).map(Detection::label)
        .findFirst().orElse("");
    ClientLoader loader = loader(s);
    String fingerprintSource = String.join("|", loader.name(), s.brand == null ? "" : s.brand,
        String.join(",", s.mods), s.locale == null ? "" : s.locale, Integer.toString(s.viewDistance),
        Integer.toString(s.skinParts), Boolean.toString(s.mainHandRight), launcher,
        String.valueOf(s.offlineUuidMatches));
    return new ClientInfo(s.playerId, s.name, s.protocol, s.version, s.rawHost.replace('\0', '|'), s.loginUuid,
        s.offlineUuidMatches, s.brand, loader, Set.copyOf(s.channels), Set.copyOf(s.mods), s.locale,
        s.viewDistance, s.skinParts, s.mainHandRight, s.detections, sha256(fingerprintSource));
  }

  private static String sha256(String text) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest, 0, 16);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Reports whether a client rule with action {@code flag} matched the name.
   *
   * @param name player name
   * @return true if flagged
   */
  public boolean flagged(String name) {
    return flaggedNames.containsKey(name.toLowerCase(Locale.ROOT));
  }

  @Override
  public Optional<ClientInfo> get(UUID playerId) {
    Session s = sessions.get(playerId);
    return s == null ? Optional.empty() : Optional.ofNullable(s.snapshot);
  }

  @Override
  public Collection<ClientInfo> online() {
    List<ClientInfo> result = new ArrayList<>();
    for (Session s : sessions.values()) {
      ClientInfo info = s.snapshot;
      if (info != null) {
        result.add(info);
      }
    }
    return result;
  }
}
