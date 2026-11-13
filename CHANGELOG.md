# Changelog

## 1.0.1 — 2026-11-13

- Nix: add the missing `hatchling` build input, so the flake package and the
  nixpkgs recipe build.
- CI: build the Nix package in addition to evaluating the flake.

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
