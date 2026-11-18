# Changelog

## Unreleased — 2026-11-18

- **Legacy launcher takeover**: `vpntui setup` now repoints
  `~/.local/bin/vpntui` to this installation (previous launcher is backed up
  in `desktop-backups/bin/`), and `vpntui doctor` warns when the command
  still resolves into the old `~/scripts/vpn` layout. The legacy app's TUN
  mode silently does nothing — its user-run Xray creates the tunnel device
  but cannot replace the default route, so sites show the real IP while the
  panel says «ПОДКЛЮЧЕНО». This made the whole VPN look broken even though
  this installation tunnels correctly.
- **Dashboard warns about live per-app sessions**: after the global VPN is
  switched off, the hero status now reads `ОТКЛЮЧЕНО · N сессий через VPN`
  instead of plain `ОТКЛЮЧЕНО`, and turning the global toggle off posts a
  warning when per-app sessions keep tunneling. Per-app sessions
  intentionally stay up when the main button is off, but before this change
  a browser opened through the VPN kept showing a VPN exit IP on
  ip-checking sites while the panel said the VPN was disconnected — the
  main reason sites like browserleaks still reported "VPN on" after the
  toggle.

## 1.0.2 — 2026-11-17

Focus: a laptop that already runs other network tools must not end up offline
or with a tunnel that silently does nothing.

- **Conflict scan before every TUN start** (`vpntui doctor`): Cloudflare WARP,
  zapret, Tailscale exit nodes, extra TUN devices, busy proxy ports, a legacy
  user `xray.service`, dead `systemd-resolved` and IPv6 bypass. WARP is
  disconnected automatically; a real blocker cancels the start with an
  explanation instead of leaving a half-broken tunnel behind.
- **zapret coexistence**: the root helper inserts `oifname "vpntui0" return`
  into zapret's nftables/iptables chains and installs
  `zapret.service.d/50-vpntui-exclude.conf`, so the exclusion survives
  `systemctl restart zapret` and reboot. This fixes TLS EOF on youtube/x/discord
  through the tunnel.
- **Tunnel verification**: after start the helper checks the default route and
  probes `api.ipify.org`. A dead tunnel is stopped automatically, so the
  connection comes back on its own.
- **Proxy ports move automatically** when `10808`/`10809` are taken (another
  Xray/Clash, a stale process); the chosen ports are remembered in
  `state.json` and shown in `vpntui status`.
- **Applications list is fully generic**: any program or command can be added
  (`a` in the TUI, `vpntui apps add --cmd …`); vpntui creates a launcher when
  the program has no `.desktop` file. The list is independent of the global
  mode — a marked app tunnels even when the main button is off. The old
  Qoder-only wording is gone.
- `vpntui doctor --fix` and `vpntui repair` apply the root-only fixes.
- `vpntui uninstall` removes the zapret drop-in and its helper.

## 1.0.1 — 2026-11-13

- Nix: add the missing `hatchling` build input, so the flake package and the
  nixpkgs recipe build.
- CI: build the Nix package in addition to evaluating the flake.
- Nix: follow nixpkgs conventions (`build-system`, `patchShebangs`) and run the
  self-contained test files during the package build.

## 1.0.0 — 2026-11-13

First public release.

- Per-application VPN through a network namespace and Xray TUN inbound.
- Textual TUI with eight sections: Dashboard, Profiles, Proxies, Connections,
  Rules, Logs, Settings, Applications.
- Installed-application rules: always-VPN toggle, per-app server (`Auto` uses
  the server selected on the Proxy page), desktop `Exec=` rewrite and restore.
  Read-only system shortcuts get a per-user override instead of being edited.
- Server names are matched to subscription entries by outbound content, so
  grouped or orphaned entries keep correct labels.
- `core install` extracts next to its target, so `/tmp` on another filesystem
  no longer breaks the install.
- Subscription import from URL/file/stdin: `vless`, `vmess`, `trojan`, `ss`,
  `hysteria2`, base64 lists and Xray JSON; selected server survives re-import.
- Xray core manager: system package first, official release download with
  SHA-256 verification, optional root-owned system installation.
- Global proxy/TUN mode as a systemd user service.
- One-time migration of the old `~/.config/xray` / `~/scripts/vpn` layout;
  existing Qoder desktop shortcut is preserved as-is.
- Nix flake, NixOS module and a nixpkgs-ready package recipe.
