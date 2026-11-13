# vpntui

A per-application VPN control panel for Linux, built on [Xray-core](https://github.com/XTLS/Xray-core).

`vpntui` runs selected applications in their own network namespace. All of
their TCP, UDP and DNS traffic goes through your Xray subscription while the
rest of the machine keeps using the normal network. A Textual TUI manages
servers, rules, sessions, logs and the optional global proxy/TUN mode.

```
normal network:  Brave (normal) ───────────────► internet
VPN network:     Roblox/Qoder ── netns ──► Xray ──► subscription ──► internet
```

## Features

* **Per-app VPN** — launch any installed application (or an arbitrary command)
  in an isolated netns through Xray; the host is untouched.
* **Installed-app rules** — on the **Applications** page every `.desktop`
  entry can be marked *always through VPN* and assigned a server (`Auto` uses
  the server currently selected on the **Proxy** page). Toggling the rule
  rewrites the application's `Exec=` line and restores it when disabled.
  System-wide entries in `/usr/share/applications` are never modified: a
  per-user copy is created in `~/.local/share/applications` instead.
* **Subscriptions** — import a URL or file with `vless://`, `vmess://`,
  `trojan://`, `ss://`, `hysteria2://` links, a base64 list, or raw Xray JSON.
  The selected server survives re-import when it still exists.
* **Server picker** — TCP reachability/latency, search, failover-friendly list.
* **Domain rules** — Clash-style `DOMAIN`, `DOMAIN-SUFFIX` and
  `DOMAIN-KEYWORD` rules with `proxy`, `direct` or `srv:N` targets.
* **Global mode** — system SOCKS/HTTP proxy (10808/10809) or a TUN interface,
  managed as a systemd user service.
* **Xray core manager** — uses a system `xray` when available; otherwise
  `vpntui core install` downloads an official release and verifies SHA-256
  before installing into the XDG data directory.
* **No polling daemons** — state is read on demand; sessions die together
  with their application.

## Requirements

* Linux with user namespaces, network namespaces and TUN support.
* Python 3.11+.
* `iproute2`, `util-linux` (`unshare`, `setpriv`), `slirp4netns`, `curl`,
  `libnotify` (optional notifications).
* Xray-core: a distribution package or `vpntui core install`.

Fedora:

```bash
sudo dnf install iproute2 util-linux slirp4netns curl libnotify
```

Debian/Ubuntu:

```bash
sudo apt install iproute2 util-linux slirp4netns curl libnotify-bin
```

Arch:

```bash
sudo pacman -S iproute2 util-linux slirp4netns curl libnotify
```

## Install

```bash
pipx install git+https://github.com/dodry-question/vpntui.git
# or: python3 -m pip install --user git+https://github.com/dodry-question/vpntui.git

vpntui core install      # optional when a system xray is already installed
vpntui sub import 'https://provider.example/sub/TOKEN'
vpntui setup             # installs the root helper and the desktop entry
vpntui
```

`vpntui setup` asks for `sudo` once. It installs:

* `/usr/local/lib/vpntui/run-vpn` — a small root helper that creates the
  namespace, TUN device and routes;
* `/etc/sudoers.d/vpntui` — permission to run **only that helper** without a
  password (required for desktop shortcuts);
* a desktop entry and a browser wrapper used by applications such as Qoder.

For a root-owned Xray installation (recommended with the helper):

```bash
vpntui core install --system
```

A user-owned core still works, but the helper deliberately refuses to execute
it as root and runs it as your user instead; TUN creation may then fail on
some kernels. Install a distribution package or use `--system` for reliable
operation.

### Nix / NixOS

```bash
nix run github:dodry-question/vpntui
```

Flake output includes `packages.<system>.default`, `overlays.default` and
`nixosModules.default`:

```nix
{
  inputs.vpntui.url = "github:dodry-question/vpntui";
  outputs = { self, nixpkgs, vpntui, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [
        vpntui.nixosModules.default
        {
          programs.vpntui = {
            enable = true;
            users = [ "alice" ];
          };
        }
      ];
    };
  };
}
```

The module installs the package (with Xray and runtime dependencies), the
root-owned helper and the sudo rule. Run `vpntui sub import …` as your user
afterwards; no `vpntui setup` is needed on NixOS.

## Usage

```bash
vpntui                          # TUI
vpntui status                   # short status
vpntui sub import <url|file>    # import a subscription
vpntui sub update               # refresh the saved URL
vpntui server list              # list servers
vpntui apps installed           # list installed .desktop applications
vpntui apps add brave --always  # enable "always through VPN" for Brave
vpntui apps launch qoder        # launch it now
vpntui core install             # download/verify Xray-core
vpntui doctor                   # diagnose paths, core, helper, sudo
```

### Keys

| Keys | Action |
|---|---|
| `1`–`8` | Dashboard, Profiles, Proxies, Connections, Rules, Logs, Settings, Applications |
| `↑`/`↓` | Move focus / table rows |
| `Enter` | Activate, select server, toggle app rule |
| `p` | Ping all servers (Proxies) |
| `a`/`d` | Add/delete rule (Rules); remove app rule (Applications) |
| `s` | Save default rule (Rules); cycle server (Applications) |
| `l` | Launch selected application through VPN (Applications) |
| `k` | Kill selected session (Connections) |
| `/` | Search/filter |
| `q` | Quit |

## How it works

1. The user helper asks the root helper (via `sudo -n`) to create a network
   namespace and start `slirp4netns` as the userspace uplink.
2. Xray starts inside the namespace with a TUN inbound. Its own sockets are
   marked with `fwmark 0x40000000` and routed outside the TUN, avoiding a loop.
3. The application starts as the invoking user. A private mount namespace
   replaces `/etc/resolv.conf` and `/etc/nsswitch.conf` so DNS cannot leak.
4. The helper checks the exit IP, writes a session record under
   `/run/vpntui/sessions/`, and tears everything down when the application
   exits.

Nothing on the host is changed: host routes, DNS, `xray.service` and WARP are
not touched. Global mode is separate and uses a systemd user service.

## Configuration

Everything is XDG-based and can be overridden with environment variables:

| Path | Contents |
|---|---|
| `~/.config/vpntui/` (`VPNTUI_CONFIG_DIR`) | servers, state, rules, apps, settings |
| `~/.local/share/vpntui/` (`VPNTUI_DATA_DIR`) | Xray core, desktop backups, browser wrapper |
| `~/.local/state/vpntui/` (`VPNTUI_STATE_DIR`) | launch logs |
| `/run/vpntui/` (`VPNTUI_RUNTIME_DIR`) | active sessions and the last Xray log |

Subscription URLs may contain access tokens: `subscription-source.json` and
`subscription.json` are written with mode `0600` and are ignored by git.

The old layout (`~/.config/xray`, `~/.config/vpn`, `~/scripts/vpn`) is
imported once, read-only. An existing Qoder desktop shortcut is preserved
exactly as it is; the rule only starts managing it if you toggle it in the new
Applications page.

## Security notes

* The root helper is a privilege boundary. It never executes a user-owned
  binary as root; the Xray binary must be root-owned (distribution package,
  `/usr/local/lib/vpntui`, or `/nix/store`).
* Applications themselves always run as the invoking user.
* `sudoers` grants NOPASSWD only for the single helper path.
* Subscription tokens are sensitive; do not commit `~/.config/vpntui`.
* Xray-core is downloaded from the official `XTLS/Xray-core` GitHub release
  and checked against the release SHA-256 digest. Pinning a version is
  supported: `vpntui core install v26.11.9`.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
```

The TUI is tested headlessly with Textual's `run_test`; no real network or
root operations are performed.

## Status

The project is being prepared for a nixpkgs submission. The package recipe
lives in [`nix/`](nix/) and the flake exposes a ready-to-use NixOS module.
See [`docs/NIXPKGS.md`](docs/NIXPKGS.md) for the submission checklist.

## License

MIT. Xray-core is a separate project licensed under MPL-2.0 and is not
bundled with vpntui.
