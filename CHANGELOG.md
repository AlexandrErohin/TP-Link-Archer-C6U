# Changelog

## [5.32.0] - 2026-08-29

### Added

- **TL-SG108E:** `get_port_status()` returns typed per-port status (`PortStatus`): enabled/link, auto-negotiation, configured and negotiated speed/duplex, flow control, LAG membership, and TX/RX packet counters ([#206](https://github.com/AlexandrErohin/TP-Link-Archer-C6U/pull/206)).
- **VR1200v:** `backup_config()` downloads router settings as bytes; shared `ConfigBackupMixin` for the `/cgi/*.bin?` backup path API ([#211](https://github.com/AlexandrErohin/TP-Link-Archer-C6U/pull/211), [#122](https://github.com/AlexandrErohin/TP-Link-Archer-C6U/issues/122)).
- **XDR / R series:** `pppoe_connect()` / `pppoe_disconnect()` to reset flaky PPPoE WAN sessions (e.g. TL-XDR6010) ([#207](https://github.com/AlexandrErohin/TP-Link-Archer-C6U/pull/207), [#80](https://github.com/AlexandrErohin/TP-Link-Archer-C6U/issues/80)).
- **Provider:** info log when `TplinkRouterProvider.get_client()` selects a client after a successful `supports()` check ([#215](https://github.com/AlexandrErohin/TP-Link-Archer-C6U/pull/215)).
- **Docs:** TL-XDR6010 in the supported routers list; README entries for `pppoe_*`, `backup_config`, and `get_port_status` / `PortStatus`.

### Fixed

- **C6U / wifi:** `get_wifi()` no longer crashes when the firmware reports channel as `'auto'`; non-numeric channels map to `None` ([#202](https://github.com/AlexandrErohin/TP-Link-Archer-C6U/pull/202), [#201](https://github.com/AlexandrErohin/TP-Link-Archer-C6U/issues/201)).
- **MR200 LTE:** `get_lte_status()` casts CGI string fields to `int` (and `total_statistics` via `int(float(...))`), so `network_type_info` / `sim_status_info` and arithmetic like `sig_level * 25` work correctly ([#214](https://github.com/AlexandrErohin/TP-Link-Archer-C6U/pull/214)).
- **MR / EX SMS:** embedded `\n` / `\r` in SMS (and USSD on MR) no longer corrupt the act/JSON wire format; MR uses TP-Link `\x11`/`\x12` escaping with decode on read; EX uses `json.dumps` for text fields. Invalid newlines in phone numbers raise `ClientException` ([home-assistant-tplink-router#389](https://github.com/AlexandrErohin/home-assistant-tplink-router/issues/389)).
