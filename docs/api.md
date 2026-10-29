# ThirdVelocity Java API

Пакет `ru.moonlightproject.dev.thirdvelocity.api`, артефакт `thirdvelocity-api`
(байткод Java 21, без зависимостей кроме аннотаций JSpecify). API находится в classpath
прокси, поэтому плагину нужна только `compileOnly`-зависимость.

```kotlin
repositories { maven("https://jitpack.io") }
dependencies { compileOnly("com.github.Th1rdPlanet.ThirdVelocity:thirdvelocity-api:v1.1.0") }
```

Локально: `./gradlew :thirdvelocity-api:publishToMavenLocal` → `ru.moonlightproject:thirdvelocity-api:1.1.0`.

## Точка входа

```java
ThirdVelocityApi tv = ThirdVelocity.api();          // IllegalStateException, если ядра нет
Optional<ThirdVelocityApi> maybe = ThirdVelocity.find();
boolean present = ThirdVelocity.isPresent();
```

Ядро устанавливает API до загрузки плагинов, поэтому `ThirdVelocity.api()` доступен уже
в конструкторе плагина. Если плагин должен работать и на обычном Velocity, проверяйте
наличие класса:

```java
static boolean hasThirdVelocity() {
  try {
    Class.forName("ru.moonlightproject.dev.thirdvelocity.api.ThirdVelocity");
    return ThirdVelocity.isPresent();
  } catch (ClassNotFoundException e) {
    return false;
  }
}
```

## Правила потоков

- Методы, помеченные в Javadoc как **fast**, читают только память. Их можно вызывать из
  event loop Netty и обработчиков событий.
- Методы, возвращающие `CompletableFuture`, обращаются к БД или сети и завершаются на
  потоках ThirdVelocity. Не вызывайте `join()` на event loop.

## Сервисы

| Метод | Сервис | Назначение |
|---|---|---|
| `bans()` | `BanService` | баны и их проверка |
| `geoIp()` | `GeoIpService` | страна, город, AS |
| `ipLists()` | `IpListService` | теги Tor/VPN/хостинг/блоклисты |
| `reputation()` | `ReputationService` | оценка IP, события, свои правила |
| `alts()` | `AltService` | твинки, аккаунты на IP, история |
| `clients()` | `ClientService` | клиент, моды, лаунчер онлайн-игроков |
| `protection()` | `ProtectionService` | уровень атаки, трафик, подозрительность |

### BanService

```java
BanService bans = tv.bans();

// Цели: Ip(IpRange), Name, Uuid, Asn, Country. Или BanTarget.parse(kind, value).
bans.ban(new BanRequest(new BanTarget.Ip(IpRange.parse("1.2.3.0/24")), "Боты", "MyPlugin",
    Duration.ofDays(7)));
bans.ban(BanRequest.permanent(new BanTarget.Name("Griefer"), "Гриф", "MyPlugin"));

bans.revoke(42, "MyPlugin");                                  // по id
bans.revoke(new BanTarget.Name("Griefer"), "MyPlugin");       // все активные на цель

Optional<Ban> ipBan = bans.matchAddress(address);             // fast: IP → подсеть → AS → страна
Optional<Ban> playerBan = bans.matchPlayer("Name", uuid);     // fast
List<Ban> active = bans.active();                             // fast
bans.history(0, 50);                                          // БД, включая снятые
bans.byId(42);
boolean coreEnforces = bans.enforcing();                      // bans.enforce в config.yml
```

Чтобы бан-плагин решал сам, поставьте `bans.enforce: false` и `commands.disabled: [ban, unban, bans, baninfo]`.
Хранилище, синхронизация между прокси и события продолжат работать.

### GeoIpService

```java
GeoInfo geo = tv.geoIp().lookup(address);   // fast; GeoInfo.UNKNOWN, если данных нет
geo.countryCode(); geo.countryName(); geo.continentCode(); geo.city(); geo.asn(); geo.asOrganization();
tv.geoIp().update();                        // скачать базы сейчас
tv.geoIp().status();                        // List<DatabaseStatus>
```

### IpListService

```java
Set<String> tags = tv.ipLists().tags(address);    // fast: {"tor"}, {"vpn","hosting"}…
Set<String> lists = tv.ipLists().lists(address);  // имена списков из ip-lists.yml
```

### ReputationService

```java
IpAssessment a = tv.reputation().assess(address);  // fast, кэш cache-seconds
a.score(); a.verdict(); a.signals(); a.geo(); a.tags(); a.suspicious();

tv.reputation().scan(address);                     // + история из БД (аккаунты, баны)

// События с очками из reputation.yml → events.points, затухают по half-life.
tv.reputation().report(address, "auth.failed");
tv.reputation().report(address, "captcha.failed");
tv.reputation().report(address, "auth.success");

// Своё правило: вызывается на event loop, должно быть быстрым.
tv.reputation().registerProvider("myplugin", (ip, geo) ->
    myBlacklist.contains(ip) ? List.of(new Signal("blacklist", 80, "в моём списке")) : List.of());
tv.reputation().unregisterProvider("myplugin");
```

### AltService

```java
tv.alts().alts("Player").thenAccept(report -> {
  for (AltLink link : report.atLeast(0.7)) {
    link.name(); link.confidence(); link.reasons(); link.sharedAddresses(); link.depth();
    link.lastSeen(); link.ban();   // активный бан связанного аккаунта или null
  }
  report.anyBanned();
});
tv.alts().address(address);        // AddressReport: аккаунты на IP и связанные адреса
tv.alts().history("Player");       // List<Observation>
tv.alts().recordAuthenticated("Player", address);  // вызывать после успешного входа по паролю/2FA
```

Причины связи (`LinkReason`): `SAME_IP`, `SAME_SUBNET`, `SAME_FINGERPRINT`, `TRANSITIVE`.
Веса — в `alts.yml`.

### ClientService

```java
tv.clients().get(player.getUniqueId()).ifPresent(c -> {
  c.loader();          // VANILLA, FABRIC, FORGE, NEOFORGE, LUNAR…
  c.brand(); c.mods(); c.channels(); c.locale(); c.viewDistance();
  c.loginUuid(); c.offlineUuidMatches();
  c.detections();      // правила clients.yml
  c.detected("launcher");
  c.fingerprint();
});
tv.clients().online();
```

### ProtectionService

```java
tv.protection().level();                         // AttackLevel NORMAL/LOW/MEDIUM/STRONG
tv.protection().traffic();                       // TrafficSnapshot за последнюю секунду
tv.protection().totals();                        // ProtectionTotals: накопительные счётчики (для Prometheus)
tv.protection().suspicious("Player", address);   // репутация + правила клиентов + политика уровня
tv.protection().known(address);                  // адрес уже встречался
tv.protection().temporaryBlocks();
```

## События

Обычные события Velocity, подписка через `@Subscribe`:

| Событие | Когда |
|---|---|
| `ConnectionBlockedEvent(address, stage, reason, detail)` | ядро отклонило соединение (не чаще раза в секунду на адрес) |
| `BanCreatedEvent(ban, remote)` | бан создан, в том числе другим прокси через общую БД |
| `BanRevokedEvent(ban, remote)` | бан снят |
| `ClientDetectedEvent(client)` | изменились данные клиента (brand, каналы, настройки) |
| `AltsDetectedEvent(report, banEvasion)` | у вошедшего игрока есть связи выше `notify-confidence` |
| `AttackLevelChangedEvent(previous, current, reason)` | сменился уровень атаки |

```java
@Subscribe
public void onAlts(AltsDetectedEvent event) {
  if (event.banEvasion()) {
    // своя реакция на обход бана
  }
}
```

## Пример: минимальный бан-плагин

```java
@Plugin(id = "mybans", name = "MyBans", version = "1.0", dependencies = {})
public final class MyBans {
  private final ProxyServer proxy;

  @Inject
  public MyBans(ProxyServer proxy) {
    this.proxy = proxy;
  }

  @Subscribe
  public void onInit(ProxyInitializeEvent event) {
    ThirdVelocityApi tv = ThirdVelocity.api();
    proxy.getCommandManager().register("ipban", (SimpleCommand) inv -> {
      String[] args = inv.arguments();
      tv.bans().ban(BanRequest.permanent(new BanTarget.Ip(IpRange.parse(args[0])),
          String.join(" ", Arrays.copyOfRange(args, 1, args.length)), "mybans"));
    });
  }
}
```
