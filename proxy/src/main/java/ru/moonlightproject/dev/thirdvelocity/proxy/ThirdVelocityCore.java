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

package ru.moonlightproject.dev.thirdvelocity.proxy;

import com.velocitypowered.api.event.PostOrder;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.player.PlayerChannelRegisterEvent;
import com.velocitypowered.api.event.player.PlayerClientBrandEvent;
import com.velocitypowered.api.event.player.PlayerModInfoEvent;
import com.velocitypowered.api.event.player.PlayerSettingsChangedEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.messages.ChannelIdentifier;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.plugin.virtual.VelocityVirtualPlugin;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import net.kyori.adventure.text.Component;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;
import ru.moonlightproject.dev.thirdvelocity.api.ThirdVelocity;
import ru.moonlightproject.dev.thirdvelocity.api.ThirdVelocityApi;
import ru.moonlightproject.dev.thirdvelocity.api.alt.AltLink;
import ru.moonlightproject.dev.thirdvelocity.api.alt.AltReport;
import ru.moonlightproject.dev.thirdvelocity.api.alt.AltService;
import ru.moonlightproject.dev.thirdvelocity.api.ban.Ban;
import ru.moonlightproject.dev.thirdvelocity.api.ban.BanRequest;
import ru.moonlightproject.dev.thirdvelocity.api.ban.BanService;
import ru.moonlightproject.dev.thirdvelocity.api.ban.BanTarget;
import ru.moonlightproject.dev.thirdvelocity.api.client.ClientService;
import ru.moonlightproject.dev.thirdvelocity.api.event.AltsDetectedEvent;
import ru.moonlightproject.dev.thirdvelocity.api.geo.GeoIpService;
import ru.moonlightproject.dev.thirdvelocity.api.intel.IpListService;
import ru.moonlightproject.dev.thirdvelocity.api.protection.ProtectionService;
import ru.moonlightproject.dev.thirdvelocity.proxy.alt.AltManager;
import ru.moonlightproject.dev.thirdvelocity.proxy.ban.BanManager;
import ru.moonlightproject.dev.thirdvelocity.proxy.client.ClientTracker;
import ru.moonlightproject.dev.thirdvelocity.proxy.command.ThirdVelocityCommand;
import ru.moonlightproject.dev.thirdvelocity.proxy.geo.GeoIpManager;
import ru.moonlightproject.dev.thirdvelocity.proxy.intel.IpListManager;
import ru.moonlightproject.dev.thirdvelocity.proxy.protection.ConnectionFilter;
import ru.moonlightproject.dev.thirdvelocity.proxy.protection.ProtectionManager;
import ru.moonlightproject.dev.thirdvelocity.proxy.reputation.ReputationManager;
import ru.moonlightproject.dev.thirdvelocity.proxy.storage.Database;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.ConfigNode;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.Downloader;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.Durations;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.IpKeys;

/**
 * The ThirdVelocity core: owns the services, schedules background work and listens to proxy
 * events. Upstream Velocity code talks to it only through {@link #filter()} and the lifecycle
 * methods.
 */
public final class ThirdVelocityCore implements ThirdVelocityApi {

  /** Version of the core and its API. */
  public static final String VERSION = "1.1.0";

  private static final Logger LOGGER = LogManager.getLogger("ThirdVelocity");
  private static volatile @Nullable ThirdVelocityCore instance;

  private final VelocityServer server;
  private final Path directory;
  private final ScheduledExecutorService scheduler;
  private final ExecutorService worker;
  private final Downloader downloader;
  private final BanManager bans;
  private final GeoIpManager geoIp;
  private final IpListManager ipLists;
  private final ProtectionManager protection;
  private final ReputationManager reputation;
  private final AltManager alts;
  private final ClientTracker clients;
  private final ConnectionFilter filter;
  private final List<ScheduledFuture<?>> tasks = new java.util.concurrent.CopyOnWriteArrayList<>();
  private @Nullable Database database;
  private volatile Messages messages;
  private volatile ConfigNode mainConfig;
  private volatile boolean notifyAlts = true;

  private ThirdVelocityCore(VelocityServer server, Path directory) {
    this.server = server;
    this.directory = directory;
    AtomicInteger counter = new AtomicInteger();
    this.scheduler = Executors.newScheduledThreadPool(2, runnable -> {
      Thread thread = new Thread(runnable, "ThirdVelocity-Scheduler-" + counter.incrementAndGet());
      thread.setDaemon(true);
      return thread;
    });
    AtomicInteger workers = new AtomicInteger();
    this.worker = Executors.newFixedThreadPool(2, runnable -> {
      Thread thread = new Thread(runnable, "ThirdVelocity-Worker-" + workers.incrementAndGet());
      thread.setDaemon(true);
      return thread;
    });
    this.downloader = new Downloader("ThirdVelocity/" + VERSION);
    this.bans = new BanManager(this);
    this.geoIp = new GeoIpManager(this);
    this.ipLists = new IpListManager(this);
    this.protection = new ProtectionManager(this);
    this.reputation = new ReputationManager(this);
    this.alts = new AltManager(this);
    this.clients = new ClientTracker(this);
    this.filter = new ConnectionFilter(this);
  }

  /**
   * Returns the running core.
   *
   * @return core or {@code null} when disabled
   */
  public static @Nullable ThirdVelocityCore get() {
    return instance;
  }

  /**
   * Returns the connection filter of the running core.
   *
   * @return filter or {@code null} when the core is disabled
   */
  public static @Nullable ConnectionFilter filterOrNull() {
    ThirdVelocityCore core = instance;
    return core == null ? null : core.filter;
  }

  /**
   * Starts the core. Called by {@code VelocityServer} after the proxy config is loaded and
   * before plugins load. A broken config stops the proxy, as a security layer must not silently
   * run without its rules.
   *
   * @param server proxy
   */
  public static void start(VelocityServer server) {
    Path directory = Path.of("thirdvelocity");
    ThirdVelocityCore core = new ThirdVelocityCore(server, directory);
    try {
      core.loadConfigs();
      if (!core.mainConfig.bool("enabled", true)) {
        LOGGER.warn("ThirdVelocity core is disabled in thirdvelocity/config.yml");
        core.scheduler.shutdownNow();
        core.worker.shutdownNow();
        return;
      }
      ConfigNode storage = core.mainConfig.section("storage");
      core.database = new Database(storage.string("url", "sqlite:data.db"),
          firstNonBlank(System.getenv("THIRDVELOCITY_DB_USER"), storage.string("user", "")),
          firstNonBlank(System.getenv("THIRDVELOCITY_DB_PASSWORD"), storage.string("password", "")),
          storage.integer("pool-size", 4, 1, 64), directory);
      core.bans.load().join();
      core.alts.loadAddresses().join();
      core.alts.rebuildTaint();
    } catch (IOException | SQLException | RuntimeException e) {
      throw new IllegalStateException("ThirdVelocity failed to start: " + e.getMessage(), e);
    }
    instance = core;
    ThirdVelocity.install(core);
    core.registerListeners();
    core.schedule();
    ThirdVelocityCommand.register(core);
    LOGGER.info("ThirdVelocity {} ready • storage: {} • bans: {} • attack level: {}", VERSION,
        core.database.dialect(), core.bans.active().size(), core.protection.level());
  }

  private static String firstNonBlank(@Nullable String first, String second) {
    return first != null && !first.isBlank() ? first : second;
  }

  private void loadConfigs() throws IOException {
    ConfigNode main = ConfigNode.load(directory.resolve("config.yml"), "thirdvelocity/config.yml");
    ConfigNode protectionConfig = ConfigNode.load(directory.resolve("protection.yml"), "thirdvelocity/protection.yml");
    migrateIntelConfig();
    ConfigNode geoipConfig = ConfigNode.load(directory.resolve("geoip.yml"), "thirdvelocity/geoip.yml");
    ConfigNode ipListsConfig = ConfigNode.load(directory.resolve("ip-lists.yml"), "thirdvelocity/ip-lists.yml");
    ConfigNode reputationConfig = ConfigNode.load(directory.resolve("reputation.yml"), "thirdvelocity/reputation.yml");
    ConfigNode altsConfig = ConfigNode.load(directory.resolve("alts.yml"), "thirdvelocity/alts.yml");
    ConfigNode clientsConfig = ConfigNode.load(directory.resolve("clients.yml"), "thirdvelocity/clients.yml");
    ConfigNode messageConfig = ConfigNode.load(directory.resolve("messages.yml"), "thirdvelocity/messages.yml");
    // Parse everything first; apply only if the whole set is valid.
    bans.apply(main.section("bans"));
    protection.apply(protectionConfig);
    geoIp.apply(geoipConfig);
    ipLists.apply(ipListsConfig);
    reputation.apply(reputationConfig);
    alts.apply(altsConfig);
    clients.apply(clientsConfig);
    filter.apply(main.section("bans"), protectionConfig, reputationConfig);
    notifyAlts = altsConfig.bool("notify-staff", true);
    messages = new Messages(messageConfig);
    mainConfig = main;
    reputation.invalidate();
  }

  /**
   * Versions before the split kept GeoIP and IP lists in one {@code intel.yml}. Its sections are
   * written to {@code geoip.yml} and {@code ip-lists.yml} (values only, comments are lost) and the
   * old file is renamed to {@code intel.yml.old}.
   */
  @SuppressWarnings("unchecked")
  private void migrateIntelConfig() throws IOException {
    Path legacy = directory.resolve("intel.yml");
    if (!java.nio.file.Files.isRegularFile(legacy)) {
      return;
    }
    Map<String, Object> root = new org.yaml.snakeyaml.Yaml(new org.yaml.snakeyaml.constructor.SafeConstructor(
        new org.yaml.snakeyaml.LoaderOptions())).load(java.nio.file.Files.readString(legacy));
    org.yaml.snakeyaml.DumperOptions options = new org.yaml.snakeyaml.DumperOptions();
    options.setDefaultFlowStyle(org.yaml.snakeyaml.DumperOptions.FlowStyle.BLOCK);
    org.yaml.snakeyaml.Yaml dumper = new org.yaml.snakeyaml.Yaml(options);
    for (String[] part : new String[][] {{"geoip", "geoip.yml"}, {"ip-lists", "ip-lists.yml"}}) {
      Path target = directory.resolve(part[1]);
      Object section = root == null ? null : root.get(part[0]);
      if (section instanceof Map<?, ?> map && java.nio.file.Files.notExists(target)) {
        java.nio.file.Files.writeString(target, "# Перенесено из intel.yml. Прокомментированный образец — в jar,"
            + " thirdvelocity/" + part[1] + "\n" + dumper.dump(map));
      }
    }
    java.nio.file.Files.move(legacy, directory.resolve("intel.yml.old"),
        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    LOGGER.warn("intel.yml was split into geoip.yml and ip-lists.yml; the old file is kept as intel.yml.old");
  }

  /**
   * Reloads every config file except storage settings.
   *
   * @throws IOException on read errors
   */
  public void reload() throws IOException {
    loadConfigs();
    geoIp.updateIfStale();
    ipLists.updateIfStale();
    LOGGER.info("ThirdVelocity configuration reloaded");
  }

  private void schedule() {
    ConfigNode storage = mainConfig.section("storage");
    int sync = storage.integer("sync-seconds", 10, 1, 3600);
    tasks.add(scheduler.scheduleAtFixedRate(protection::tick, 1, 1, TimeUnit.SECONDS));
    tasks.add(scheduler.scheduleAtFixedRate(safe(protection::flushFirewall), 1, 1, TimeUnit.SECONDS));
    tasks.add(scheduler.scheduleAtFixedRate(safe(alts::flush), 500, 500, TimeUnit.MILLISECONDS));
    tasks.add(scheduler.scheduleAtFixedRate(safe(bans::sync), sync, sync, TimeUnit.SECONDS));
    tasks.add(scheduler.scheduleAtFixedRate(safe(filter::logSummary), 30, 30, TimeUnit.SECONDS));
    tasks.add(scheduler.scheduleAtFixedRate(safe(reputation::cleanup), 5, 5, TimeUnit.MINUTES));
    tasks.add(scheduler.scheduleAtFixedRate(safe(() -> {
      geoIp.updateIfStale();
      ipLists.updateIfStale();
    }), 5, 15 * 60, TimeUnit.SECONDS));
    tasks.add(scheduler.scheduleAtFixedRate(safe(alts::purge), 10, 24 * 60, TimeUnit.MINUTES));
  }

  private static Runnable safe(Runnable task) {
    return () -> {
      try {
        task.run();
      } catch (RuntimeException e) {
        LOGGER.warn("ThirdVelocity background task failed", e);
      }
    };
  }

  private void registerListeners() {
    server.getEventManager().register(VelocityVirtualPlugin.INSTANCE, this);
  }

  /**
   * Stops background work and closes storage.
   */
  public static void shutdown() {
    ThirdVelocityCore core = instance;
    if (core == null) {
      return;
    }
    instance = null;
    ThirdVelocity.uninstall(core);
    core.tasks.forEach(task -> task.cancel(false));
    core.alts.flush();
    core.scheduler.shutdownNow();
    core.worker.shutdownNow();
    core.geoIp.close();
    if (core.database != null) {
      core.database.close();
    }
  }

  // ---- event listeners -------------------------------------------------------------------

  /**
   * Records the login and runs the alt check.
   *
   * @param event event
   */
  @Subscribe(order = PostOrder.LATE)
  public void onPostLogin(PostLoginEvent event) {
    Player player = event.getPlayer();
    InetAddress address = IpKeys.of(player.getRemoteAddress());
    if (address == null) {
      return;
    }
    clients.start(player, IpKeys.text(address));
    if (!alts.enabled()) {
      return;
    }
    alts.recordLogin(player.getUsername(), address)
        .thenCompose(ignored -> alts.alts(player.getUsername()))
        .thenAccept(report -> onAltReport(player, report))
        .exceptionally(error -> {
          LOGGER.warn("alt check for {} failed: {}", player.getUsername(), error.getMessage());
          return null;
        });
  }

  private void onAltReport(Player player, AltReport report) {
    List<AltLink> strong = report.atLeast(alts.notifyConfidence());
    if (strong.isEmpty()) {
      return;
    }
    AltLink evasion = strong.stream()
        .filter(link -> link.ban() != null && link.confidence() >= alts.evasionConfidence())
        .findFirst().orElse(null);
    fire(new AltsDetectedEvent(report, evasion != null));
    String names = String.join(", ", strong.stream().limit(8)
        .map(link -> link.name() + " " + Math.round(link.confidence() * 100) + "%").toList());
    if (notifyAlts) {
      Component note = messages.render(evasion != null ? "staff-evasion" : "staff-alts",
          "player", player.getUsername(), "alts", names,
          "banned", evasion == null ? "" : evasion.name());
      server.getConsoleCommandSource().sendMessage(note);
      for (Player staff : server.getAllPlayers()) {
        if (staff.hasPermission("thirdvelocity.notify.alts")) {
          staff.sendMessage(note);
        }
      }
    }
    if (evasion != null && evasion.ban() != null) {
      Ban source = evasion.ban();
      switch (alts.evasionAction()) {
        case "kick" -> player.disconnect(banScreen(source));
        case "ban" -> {
          Duration remaining = source.expiresAt() == null ? null
              : Duration.between(Instant.now(), source.expiresAt());
          if (remaining == null || !remaining.isNegative()) {
            bans.ban(new BanRequest(new BanTarget.Name(player.getUsername()),
                "Обход бана (" + evasion.name() + ")", "ThirdVelocity", remaining));
          }
        }
        default -> {
        }
      }
    }
  }

  /**
   * Stops tracking the client.
   *
   * @param event event
   */
  @Subscribe
  public void onDisconnect(DisconnectEvent event) {
    clients.stop(event.getPlayer().getUniqueId());
  }

  /**
   * Records the brand.
   *
   * @param event event
   */
  @Subscribe
  public void onBrand(PlayerClientBrandEvent event) {
    clients.brand(event.getPlayer(), event.getBrand());
  }

  /**
   * Records channels.
   *
   * @param event event
   */
  @Subscribe
  public void onChannels(PlayerChannelRegisterEvent event) {
    clients.channels(event.getPlayer(), event.getChannels().stream().map(ChannelIdentifier::getId).toList());
  }

  /**
   * Records settings.
   *
   * @param event event
   */
  @Subscribe
  public void onSettings(PlayerSettingsChangedEvent event) {
    clients.settings(event.getPlayer(), event.getPlayerSettings());
  }

  /**
   * Records legacy Forge mods.
   *
   * @param event event
   */
  @Subscribe
  public void onModInfo(PlayerModInfoEvent event) {
    clients.modInfo(event.getPlayer(), event.getModInfo());
  }

  // ---- helpers ---------------------------------------------------------------------------

  /**
   * Fires an API event without waiting.
   *
   * @param event event
   */
  public void fire(Object event) {
    server.getEventManager().fireAndForget(event);
  }

  /**
   * Renders the ban screen.
   *
   * @param ban ban
   * @return component
   */
  public Component banScreen(Ban ban) {
    String expires = ban.expiresAt() == null ? messages.raw("ban-permanent")
        : DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm").withZone(ZoneId.systemDefault()).format(ban.expiresAt())
        + " (" + Durations.format(Duration.between(Instant.now(), ban.expiresAt())) + ")";
    return messages.render("ban-screen", "reason", ban.reason().isEmpty() ? messages.raw("ban-no-reason") : ban.reason(),
        "expires", expires, "id", Long.toString(ban.id()), "actor", ban.actor(),
        "target", ban.target().kind() + " " + ban.target().value());
  }

  /** Called by the ban manager after the ban index changed. */
  public void onBansChanged() {
    reputation.invalidate();
    if (database != null) {
      alts.rebuildTaint();
    }
  }

  /** Called after IP lists change. */
  public void onIntelChanged() {
    reputation.invalidate();
  }

  /**
   * Returns the proxy.
   *
   * @return proxy
   */
  public VelocityServer server() {
    return server;
  }

  /**
   * Returns the data directory.
   *
   * @return directory
   */
  public Path directory() {
    return directory;
  }

  /**
   * Returns the scheduler.
   *
   * @return scheduler
   */
  public ScheduledExecutorService scheduler() {
    return scheduler;
  }

  /**
   * Returns the worker pool for downloads and process calls.
   *
   * @return executor
   */
  public ExecutorService worker() {
    return worker;
  }

  /**
   * Returns the downloader.
   *
   * @return downloader
   */
  public Downloader downloader() {
    return downloader;
  }

  /**
   * Returns the database.
   *
   * @return database
   */
  public Database database() {
    Database db = database;
    if (db == null) {
      throw new IllegalStateException("ThirdVelocity storage is not open");
    }
    return db;
  }

  /**
   * Returns the player messages.
   *
   * @return messages
   */
  public Messages messages() {
    return messages;
  }

  /**
   * Returns the main config.
   *
   * @return config.yml
   */
  public ConfigNode mainConfig() {
    return mainConfig;
  }

  /**
   * Returns the connection filter.
   *
   * @return filter
   */
  public ConnectionFilter filter() {
    return filter;
  }

  /**
   * Returns the protection manager.
   *
   * @return manager
   */
  public ProtectionManager protectionManager() {
    return protection;
  }

  /**
   * Returns the alt manager.
   *
   * @return manager
   */
  public AltManager altManager() {
    return alts;
  }

  /**
   * Returns the client tracker.
   *
   * @return tracker
   */
  public ClientTracker clientTracker() {
    return clients;
  }

  /**
   * Returns the IP list manager.
   *
   * @return manager
   */
  public IpListManager ipListManager() {
    return ipLists;
  }

  /**
   * Returns the GeoIP manager.
   *
   * @return manager
   */
  public GeoIpManager geoIpManager() {
    return geoIp;
  }

  /**
   * Returns the ban manager.
   *
   * @return manager
   */
  public BanManager banManager() {
    return bans;
  }

  /**
   * Returns the reputation manager.
   *
   * @return manager
   */
  public ReputationManager reputationManager() {
    return reputation;
  }

  @Override
  public String version() {
    return VERSION;
  }

  @Override
  public BanService bans() {
    return bans;
  }

  @Override
  public GeoIpService geoIp() {
    return geoIp;
  }

  @Override
  public IpListService ipLists() {
    return ipLists;
  }

  @Override
  public ReputationManager reputation() {
    return reputation;
  }

  @Override
  public AltService alts() {
    return alts;
  }

  @Override
  public ClientService clients() {
    return clients;
  }

  @Override
  public ProtectionService protection() {
    return protection;
  }
}
