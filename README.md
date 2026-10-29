# ThirdVelocity

Форк [Velocity](https://github.com/PaperMC/Velocity) с встроенной защитой сети: ранний
фильтр соединений, баны по IP/подсетям/ASN/странам/никам, GeoIP с автообновлением,
оценка репутации IP, поиск твинков и связанных адресов, определение клиентов, модов и
лаунчеров, защита от ботов и шифрование offline-входа. Ядро работает самостоятельно и
отдаёт всё через Java API — им пользуется плагин авторизации
[Selene](https://github.com/Th1rdPlanet/Selene), а свои плагины (баны, модерация)
могут строиться поверх того же API.

## Возможности

| Подсистема | Что делает |
|---|---|
| Ранний фильтр | Проверяет адрес в `initChannel`, до создания обработчиков Minecraft. Забаненный или флудящий IP получает RST (опционально — экран бана). С PROXY protocol проверяется реальный адрес, а заголовок принимается только от доверенных источников. |
| Баны | IP и CIDR (IPv4/IPv6), ник, UUID, AS, страна. Сроки, причины, история. Индекс в памяти (longest-prefix). Общая MySQL/MariaDB/PostgreSQL синхронизирует несколько прокси. Опциональный экспорт в nftables. |
| GeoIP | Базы `.mmdb`: по умолчанию бесплатные DB-IP Lite (страна, AS, город), можно MaxMind GeoLite2 с ключом. Обновление по таймеру и командой `/tv geoip update`, атомарная подмена без перезапуска. |
| IP-списки | Tor exit, VPN, дата-центры, FireHOL, Spamhaus DROP, свои файлы. Каждый список — набор тегов. |
| Репутация | Сумма очков: теги списков, страна, AS, новизна адреса, подтверждённые входы, адреса забаненных аккаунтов, частота подключений, число ников, события от плагинов (ошибки пароля/CAPTCHA) с затуханием, свои правила плагинов. Вердикт ALLOW / FLAG / DENY. |
| Твинки | Граф «аккаунт ↔ IP» с учётом подсетей, AS, отпечатков клиента и транзитивных связей; подавление общих адресов (NAT, мобильные сети, VPN). Обнаружение обхода бана. |
| Клиенты | Загрузчик (Vanilla/Fabric/Quilt/Forge/NeoForge), Lunar/Feather/LabyMod/Badlion, моды по неймспейсам каналов и списку Forge, нестандартный UUID лаунчера, язык и настройки. Правила с действиями none/flag/kick. |
| Антибот | Лимиты подключений на IP и подсеть, временные блокировки, лимит одновременных соединений, лимит пингов, политика host name, проверка ника, лимит ников на IP, уровни атаки NORMAL → STRONG с гистерезисом. |
| Соединение | Шифрование offline-входа для клиентов 1.20.5+ (`shouldAuthenticate=false`), доверенные источники PROXY protocol. |
| Метрики | Подключения, отказы по причинам, входы, пинги, трафик, уровень атаки, баны — в Java API (для экспорта в Prometheus — плагином, например Selene). |
| Поведение клиента | Мягкие сигналы ботов: нет brand или настроек, нестандартный формат языка, невозможная дальность прорисовки. |
| Сеть | Эскалация временных блокировок (5 мин → 1 ч → 1 сутки), опциональная выгрузка блокировок флуда в nftables, `TCP_DEFER_ACCEPT`, кэш ответа на пинг во время атаки. |

## Сборка и запуск

```sh
./gradlew build
java -jar proxy/build/libs/velocity-proxy-*-all.jar
```

Нужна Java 25 (как у upstream Velocity 4.x). При первом запуске создаётся папка
`thirdvelocity/` с конфигами: `config.yml`, `protection.yml`, `geoip.yml`, `ip-lists.yml`,
`reputation.yml`, `alts.yml`, `clients.yml`, `messages.yml`. Все параметры
прокомментированы. `/tv reload` применяет изменения без перезапуска (кроме `storage`).

Секреты можно не хранить в файлах: `THIRDVELOCITY_DB_USER`, `THIRDVELOCITY_DB_PASSWORD`,
`MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY`.

## Команда `/tv`

`ban`, `unban`, `bans`, `baninfo`, `check`, `alts`, `ip`, `history`, `client`, `geoip`,
`lists`, `attack`, `unblock`, `reload`. Права — `thirdvelocity.command.<подкоманда>`,
уведомления о твинках — `thirdvelocity.notify.alts`. Команду можно выключить целиком
или по подкомандам (`config.yml → commands`), применение банов ядром — `bans.enforce`.

```
/tv ban 1.2.3.0/24 7d Флуд ботами
/tv ban name Griefer perm Гриф
/tv ban asn AS12345 Хостинг ботов
/tv check Player
/tv alts Player
```

## Java API

Подробно — [docs/api.md](docs/api.md). Коротко:

```kotlin
repositories { maven("https://jitpack.io") }
dependencies { compileOnly("com.github.Th1rdPlanet.ThirdVelocity:thirdvelocity-api:v1.0.0") }
```

```java
ThirdVelocity.find().ifPresent(tv -> {
  tv.bans().ban(BanRequest.permanent(new BanTarget.Name("Griefer"), "Гриф", "MyPlugin"));
  tv.alts().alts("Player").thenAccept(report -> ...);
});
```

## Ограничения

- Всё, что сообщает клиент (brand, каналы, UUID при входе), можно подделать. Это сигналы, а не доказательства.
- Шифрование offline-входа защищает от пассивного перехвата. От активного MITM не защищает: ванильный клиент не умеет проверять ключ сервера без Mojang.
- Определение лаунчера эвристическое: в протоколе Minecraft нет User-Agent.
- Публичные списки (FireHOL, X4BNet) иногда содержат ложные срабатывания. Веса настраиваются в `reputation.yml`.

## Лицензия

GPL-3.0, как и Velocity. Оригинальный README upstream — [docs/UPSTREAM-README.md](docs/UPSTREAM-README.md).
