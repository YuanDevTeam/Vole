# Vole

<p align="center">
  <a href="../README.md">English</a> · <a href="./README.zh_CN.md">简体中文</a> · Русский
</p>

Vole — прокси-ядро на Rust для VPN-клиентов и локальных прокси, доступное как нативная библиотека и CLI переднего плана. Оно маршрутизирует TCP/UDP-трафик через прямые соединения, прокси-узлы, группы и цепочки, объединяя DNS, GeoData и кроссплатформенную плоскость данных TUN.

Конфигурация использует **совместимый с Mihomo YAML в пределах поддерживаемых возможностей**. Vole ориентирован на клиентские функции и не реализует все поля Mihomo или его полный Dashboard API.

## Что умеет Vole

- **Принимать трафик приложений и VPN:** пересылка HTTP, CONNECT и Upgrade; SOCKS5 CONNECT и UDP ASSOCIATE; IPv4/IPv6-пакеты TUN, предоставленные хостом.
- **Маршрутизировать трафик:** режимы rule/global/direct; домены, IP и порты источника и назначения, TCP/UDP, GeoSite/GeoIP, наборы правил и логические условия, действия DIRECT и REJECT.
- **Выбирать прокси и строить цепочки:** вложенные группы select/url-test/fallback/load-balance, проверки доступности и сохранение выбора; `dialer-proxy` ссылается на узлы или группы. Существующие соединения сохраняют свой маршрут.
- **Обрабатывать DNS:** hosts, отдельные bootstrap/узловые/прямые резолверы, UDP/TCP/DoH/DoT, политики по доменам/GeoSite/rule-set, fallback, ограниченный кеш, redir-host и постоянные fake-IP; перехват DNS в TUN по конфигурации.
- **Определять трафик для маршрутизации:** HTTP/TLS для TUN и mixed TCP, QUIC для TUN UDP, условия принудительного анализа и исключения, настраиваемая замена назначения. Ответы на ICMPv4/ICMPv6 Echo формируются локально.
- **Управлять ресурсами:** HTTP/file/inline providers узлов и правил, динамические группы, фильтры и переопределения; YAML/Text и domain/ipcidr MRS. GeoData полностью загружает выбранные категории, поддерживает маршрутизируемые загрузки и периодические обновления; ошибки обновления сохраняют рабочее состояние. См. [границы GeoData](../docs/geodata.md#内存与安全边界).
- **Предоставлять управление:** состояние групп и ресурсов, список и закрытие соединений, счётчики правил, действующая конфигурация и ограниченная DNS-диагностика, а также метрики TUN и изолированное измерение задержки.

## Прокси-протоколы

Все десять протоколов ниже включены по умолчанию. HTTP CONNECT поддерживает только TCP; UDP для остальных протоколов настраивается на уровне узла.

| Протокол | Возможности |
| --- | --- |
| [VLESS](../docs/vless.md) | TCP, WebSocket / HTTPUpgrade, gRPC, HTTP-маскировка первого пакета, legacy H2, [XHTTP H1/H2/H3](../docs/xhttp.md); Vision, Encryption, REALITY, JLS, статический ECH и sing-mux в поддерживаемых сочетаниях |
| [VMess AEAD](../docs/outbounds.md#vmess-aead) | TCP, WebSocket / HTTPUpgrade, gRPC, HTTP-маскировка первого пакета и legacy H2; TCP/UDP, транспорт без TLS или со стандартным TLS |
| [Trojan](../docs/outbounds.md#trojan) | TCP/UDP через TLS TCP, WebSocket / HTTPUpgrade или gRPC |
| [Shadowsocks 2022](../docs/outbounds.md#shadowsocks-2022) | TCP/UDP; AES-128-GCM, AES-256-GCM и ChaCha20-Poly1305; цепочки идентификации AES; опциональный strict ShadowTLS v3 для TCP и UoT v2 |
| [AnyTLS](../docs/outbounds.md#anytls) | TLS-сессии и UDP over TCP v2 |
| [HTTP / HTTPS CONNECT](../docs/outbounds.md#http--https-connect) | TCP CONNECT, опциональная аутентификация прокси и TLS |
| [SOCKS5](../docs/outbounds.md#socks5) | CONNECT и UDP ASSOCIATE, с опциональной аутентификацией по имени пользователя и паролю |
| [Hysteria2](../docs/outbounds.md#hysteria2) | TCP/UDP через QUIC, управление пропускной способностью, Salamander, смена портов и mTLS |
| [TUIC v5](../docs/outbounds.md#tuic-v5) | TCP/UDP через QUIC, режимы передачи UDP native/quic и выбор алгоритма управления перегрузкой |
| [WireGuard](../docs/outbounds.md#wireguard) | TCP/UDP через стандартный WireGuard с пользовательским IP-стеком |

Стандартные TLS-соединения поддерживают проверку сертификатов и закрепление сертификата по SHA-256. Поддерживаемые TCP-пути с TLS могут использовать шаблоны ClientHello Chrome, Firefox или Safari; `client-fingerprint` не зависит от `fingerprint` сертификата. Точные имена и сочетания описаны в [профилях TLS и политике сертификатов](../docs/tls-client-fingerprint.md). Эти функции не гарантируют неотличимость от браузера или произвольные сочетания протоколов.

SS2022 использует официальную Rust-библиотеку без изменений; известные риски пустой первой записи, сценария server-first и padding описаны в [контракте Shadowsocks](../docs/outbounds.md#shadowsocks-2022).

## Конфигурация в стиле Mihomo

Используйте привычные структуры `proxies`, `proxy-groups`, `rules`, `dns`, `mixed-port` и `tun`. Например:

```yaml
mixed-port: 1080
allow-lan: false

proxies:
  - name: edge
    type: anytls
    server: proxy.example.com
    port: 443
    password: replace-with-your-password
    client-fingerprint: chrome
    udp: true

proxy-groups:
  - name: Proxy
    type: select
    proxies: [edge, DIRECT]

dns:
  enable: true
  nameserver:
    - "udp://223.5.5.5:53#DIRECT"

rules:
  - GEOSITE,cn,DIRECT
  - GEOIP,cn,DIRECT,no-resolve
  - MATCH,Proxy
```

Замените адрес сервера и учётные данные. GeoSite/GeoIP используют файлы в `<dataDir>/geodata`; отсутствующие необходимые ресурсы загружаются через заданный маршрут. До успешной загрузки соответствующие правила недоступны. См. [конфигурацию](../docs/config.yaml) и [поведение GeoData](../docs/geodata.md).

`mixed-port` принимает HTTP и SOCKS5 на одном TCP-порту и включает SOCKS5 UDP на том же порту. `allow-lan` управляет адресом привязки независимо от `authentication`: если `authentication` отсутствует или равен `[]`, аутентификация не требуется ни на loopback, ни на всех интерфейсах; заданные учётные данные проверяются HTTP и SOCKS5. Поля верхнего уровня `port`, `socks-port`, `udp` и `listeners` отклоняются; `port` и `udp` прокси-узла сохраняют смысл параметров исходящего соединения.

Поддерживается документированное подмножество конфигурации Mihomo. Неизвестные поля и неподдерживаемые сочетания отклоняются. Ограничения платформ и протоколов описаны в [границах совместимости](../docs/mihomo-compatibility.md) и соответствующих контрактах.

Хост запускает экземпляр библиотеки с inline `configYaml`; устройство TUN, дескриптор, MTU, перехват DNS и тайм-аут UDP задаются в `tun`. Платформенные callbacks регистрируются локально в runtime. CLI передаёт параметры через тот же Invoke API, чья операция foreground читает файл `-f`. Для собственного TUN в Linux ядро поддерживает автоматические маршруты и DNS через systemd-resolved; заимствованные fd и сеть платформ приложений остаются под управлением хоста.

## CLI

Сборка исполняемого файла: `uv run --project scripts --locked vole-scripts build cli`. Windows CLI всегда использует Wintun; для выбора backend FFI используйте `build windows --backend wintun|uwp` (по умолчанию UWP). Релизы по тегам публикуют CLI и FFI вместе: Windows CLI использует Wintun, а FFI предлагает оба backend. Цели и состав архивов описаны в [скриптах сборки](../scripts/README.md).

```sh
vole -f /path/to/config.yaml
vole -d /path/to/data -f ./config.yaml
vole -t -f ./config.yaml
```

`-d` задаёт каталог конфигурации и данных, а `-f` независимо выбирает файл конфигурации. Относительные пути отсчитываются от рабочего каталога при запуске. Без `-f` используется `<data-dir>/config.yaml`; каталог по умолчанию — `.config/vole` пользователя с переходом к `XDG_CONFIG_HOME` по правилам Mihomo. `-f -` читает стандартный ввод. `VOLE_HOME_DIR` / `VOLE_CONFIG_FILE` задают значения из окружения; явные параметры имеют приоритет. `-t` только проверяет конфигурацию, `-v` выводит версию и идентификатор сборки, `-h` — справку. См. [CLI и релизы по тегам](../docs/cli.md).

## Платформы и интеграция

| Платформа | Интеграция TUN |
| --- | --- |
| iOS / macOS | Дескриптор utun от хоста; macOS также может открыть или создать нативный utun |
| tvOS 17+ | Дескриптор файла utun, предоставленный хостом; ARM64-устройства и симулятор |
| Android | Дескриптор `VpnService` с защитой исходящих сокетов |
| Linux | Настоящий raw-IP TUN с одной очередью через заимствованный fd или устройство, открытое ядром; собственный TUN в Linux поддерживает автоматические маршруты и системный DNS |
| Windows | Взаимоисключающие сборки `windows-wintun` для настольного процесса и `windows-uwp` для пакетного Provider/Session Host; общее ядро |

Vole предоставляет нативные библиотеки и CLI. На Apple, Android и Windows системной сетью и жизненным циклом приложения управляет хост; собственный TUN в Linux дополнительно поддерживает автоматические маршруты и системный DNS. На Unix исходный дескриптор TUN принадлежит хосту; Vole использует и закрывает собственную копию. Публичный API packetFlow от Apple не гарантирует доступ к raw fd, поэтому интеграция с Network Extension и проверка на устройствах остаются ответственностью хоста. См. [интеграцию TUN](../docs/tun-platform.md) и [границы приёмки платформ](../docs/acceptance.md).

Настольный Wintun загружает предоставленный хостом `wintun.dll` из каталога исполняемого файла процесса. Адреса интерфейса, DNS, маршруты и физический выход настраивает хост; проверка Wintun на устройстве независима от результатов пакетного VPN. Использование CLI и поставка описаны в [документации CLI и релизов по тегам](../docs/cli.md).

Кроссплатформенный C ABI принимает JSON-запросы через Invoke API:

```c
char *VoleInvoke(const char *request_json);
void VoleFree(char *response);
```

Один публичный экземпляр проходит жизненный цикл `initialize → createInstance → start(configYaml) → stop → destroyInstance`; подготовка выполняется внутри `start`. `validateConfig` не требует инициализации. CLI использует явную операцию foreground Invoke для файлов, окружения, сигналов и очистки. API также предоставляет запросы состояния, статус GeoData и измерение задержки. См. [Invoke API](../docs/invoke-api.md), [Controller API](../docs/controller-api.md) и [пример интеграции Windows](../example/windows-uwp/README.md).

## Benchmark

[**TUN-бенчмарк Vole / Mihomo**](https://github.com/YuanDevTeam/container-benchmark) содержит воспроизводимую методику, результаты измерений и сравнительные графики для обоих ядер в одинаковой среде с нативным Linux TUN.

Проект benchmark также выполняет проверку совместимости протоколов (`interop`) и тесты нагрузки на память (`stress`), используя явно указанный checkout `--source vole=PATH`. Собственные скрипты Vole только компилируют ядро и платформенные артефакты.

Он измеряет смешанный TCP/UDP-трафик на **1 / 1,5 / 2 Гбит/с** с **1 000 DNS-запросов/с** и расширенными правилами `geosite:cn` / `geoip:cn`, показывая фактическую пропускную способность, CPU, наблюдаемый пиковый Linux RSS, потери UDP-пакетов и успешные DNS-запросы. Проверяется путь TUN/DNS/маршрутизации с выходом через DIRECT, а не пропускная способность зашифрованных прокси; Linux RSS не отражает потребление памяти Apple Network Extension.

Отдельная команда `stress` использует те же полные расширенные категории CN. CLI проверяет загрузку DAT при запуске и не предоставляет режим измерений `--geodata-update` во время работы. Фактические входные данные, метрики и ошибки приведены в результатах benchmark.

## Документация

- [Указатель документации](../docs/README.md)
- [Справочник конфигурации](../docs/config.yaml)
- [Границы совместимости с Mihomo](../docs/mihomo-compatibility.md)
- [Сборка ядра и платформенных артефактов](../scripts/README.md)
- [CLI и релизы по тегам](../docs/cli.md)
- [Регрессионные тесты ядра](../tests/README.md)
- [Политика ресурсов](../docs/runtime-resource-policy.md)
- [Приёмка и известные ограничения](../docs/acceptance.md)

## Благодарности

Vole использует публичные зависимости и опирается на реализации протоколов и примеры платформенной интеграции:

- Зависимости TUN: локальный [`vole-netstack`](../crates/vole-netstack/README.md) использует [smoltcp](https://github.com/smoltcp-rs/smoltcp), а пакетный I/O на Unix и Windows Wintun — [tun-rs](https://github.com/tun-rs/tun-rs) (Apache-2.0).
- WireGuard: [boringtun](https://github.com/cloudflare/boringtun) (BSD-3-Clause), без host-device, FFI и JNI.
- [Wintun](https://www.wintun.net/): DLL предоставляет хост; Vole её не включает. Исходный [заголовок API](https://github.com/tun-rs/tun-rs/blob/2.8.11/src/platform/windows/tun/wintun.h) в tun-rs имеет copyright 2018–2021 WireGuard LLC и лицензию `GPL-2.0 OR MIT`; при распространении связанных API bindings необходимо сохранить copyright и уведомление об альтернативной лицензии MIT.
- Архитектурные ориентиры для сети и маршрутизации: [clash-rs](https://github.com/Watfaq/clash-rs), [netstack-smoltcp](https://github.com/cavivie/netstack-smoltcp), [Mihomo](https://github.com/MetaCubeX/mihomo), [Xray-core](https://github.com/XTLS/Xray-core) и [Leaf](https://github.com/eycorsican/leaf). Эти проекты не являются зависимостями netstack.
- TLS и Shadowsocks: [rustls](https://github.com/rustls/rustls), [boring](https://github.com/cloudflare/boring), [BoringSSL](https://boringssl.googlesource.com/boringssl/) и [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust). Заимствованный код replay-window сохраняет [уведомления MIT](../src/outbound/shadowsocks/packet_window.rs).
- Интеграция Windows: [windows-rs](https://github.com/microsoft/windows-rs), [UWP VPN Plugin Sample](https://github.com/microsoft/UwpVpnPluginSample), [wireguard-uwp-rs](https://github.com/luqmana/wireguard-uwp-rs), [Maple](https://github.com/YtFlow/Maple) и [YtFlowCore](https://github.com/YtFlow/YtFlowCore).

## Лицензия

[MIT](../LICENSE).
