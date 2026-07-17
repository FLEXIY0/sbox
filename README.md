# sbox — «непробиваемый» TUI-клиент для sing-box

Легковесный отказоустойчивый терминальный клиент для управления ядром
[sing-box](https://github.com/SagerNet/sing-box). Один статический бинарник
(Go), никаких зависимостей на целевой машине. Работает на Linux (x86, **ARM**,
MIPS), **Windows** и macOS — от слабого роутера до удалённого сервера.

```
Subscription: https://raw.githubusercontent.com/.../subs.txt
Test URL:     http://cp.cloudflare.com/generate_204
Show limit:   15
AUTO-ROTATE:  [ON] (60s interval)
DAEMON:       [ACTIVE] (systemd)  |  SOURCE:  [LIVE / GITHUB]
VERSION:      v1.0.0              |  ALIAS:   [s] INSTALLED

----- SUBSCRIPTION STATUS (15 servers) --------------------------
      ID | TYPE                       | LATENCY
  ->  01 | REALITY-GERMANY            | [####.] 42ms  (* ACTIVE)
      02 | HYSTERIA2-FINLAND          | [###..] 65ms
      03 | VMESS-US-EAST              | [DEAD ] timed out
      04 | TUIC-SINGAPORE             | [#####] 38ms
-----------------------------------------------------------------

[ENTER] Apply | [U] Update Sub | [S] Self-Update | [R] Rotate On/Off | [D] Detach | [Up/Down] Navigate
```

## Установка одной командой

**Linux / macOS** (включая ARM: Raspberry Pi, роутеры, Apple Silicon):

```sh
curl -fsSL https://raw.githubusercontent.com/flexiy0/sbox/main/install.sh | sh
# или на системах без curl:
wget -qO- https://raw.githubusercontent.com/flexiy0/sbox/main/install.sh | sh
```

**Windows** (PowerShell, amd64 и Windows-on-ARM):

```powershell
irm https://raw.githubusercontent.com/flexiy0/sbox/main/install.ps1 | iex
```

Установщик кладёт бинарник в систему и прописывает альяс `s` — дальше просто
нажмите `s` + `Enter` в новой сессии терминала.

## Как это работает

Приложение разделено на два слоя внутри одного бинарника:

- **Daemon Engine** (`sbox --daemon`) — крутится в фоне: скачивает подписку,
  парсит ссылки (`vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`,
  `tuic://`), генерирует `config.json`, запускает sing-box, пингует ноды через
  clash_api и переключает трафик на живую ноду при аварии — без перезапуска
  ядра.
- **TUI** (`sbox`) — лёгкий интерфейс поверх текущего буфера терминала
  (raw mode + ANSI, без alternate screen — работает в любом SSH-клиенте).
  При нажатии `D` интерфейс закрывается, демон продолжает работать.

Если демон не запущен, TUI поднимет его автоматически. Если sing-box не
установлен, демон сам скачает его из официальных релизов под вашу архитектуру.

### Сплит-туннелирование для РФ

В генерируемый конфиг зашита маршрутизация: российские домены и IP
(rule-set'ы `geoip-ru.srs` и `ru-bundle.srs`) идут напрямую (`direct`),
весь остальной трафик — через выбранную ноду. Локальный прокси:
`127.0.0.1:2080` (mixed: HTTP + SOCKS5).

### Отказоустойчивость

- **Локальный кэш** — последняя рабочая подписка сохраняется в
  `last_good_sub.txt`; при недоступности сети приложение стартует на кэше
  (статус `SOURCE: [OFFLINE / LOCAL CACHE]`).
- **Авто-ротация** — каждые 60 секунд проверяется активная нода; если она
  умерла, трафик мгновенно переводится на живую ноду с минимальным пингом.
- **Аварийный режим** — если умерли все ноды, TUI показывает предупреждение
  и предлагает принудительно обновить подписку (`U`).

## CLI

| Команда | Действие |
|---|---|
| `sbox` | открыть TUI (первый запуск — мастер настройки) |
| `sbox --daemon` | запустить демон в foreground (для systemd) |
| `sbox --install-service` | автозапуск: systemd-юнит (Linux) / Task Scheduler (Windows) |
| `sbox --update` | самообновление из GitHub Releases |
| `sbox --sub URL` | сменить URL подписки |
| `sbox --stop` | остановить демон |
| `sbox --version` | версия и платформа |

## Клавиши TUI

- `↑ / ↓` — навигация по списку нод
- `Enter` — сделать выбранную ноду активной (в обход авто-ротации)
- `U` — принудительно обновить подписку
- `S` — самообновление бинарника «на лету»
- `R` — включить/выключить авто-ротацию
- `D` / `Q` — Detach: закрыть TUI, демон остаётся в фоне

## Сборка из исходников

```sh
go build .          # под текущую платформу
sh build.sh         # весь релизный набор: linux (amd64/arm64/armv7/mips/mipsle/386),
                    # windows (amd64/arm64), darwin (amd64/arm64) -> ./dist
```

Файлы данных: Linux (root) — `/var/lib/sbox/`, иначе — каталог конфигурации
пользователя (`~/.config/sbox`, `%AppData%\sbox`).
