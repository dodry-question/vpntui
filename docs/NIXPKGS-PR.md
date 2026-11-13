## Description

Add `vpntui`, a per-application VPN control panel for Linux built on Xray.

It runs selected applications in an isolated network namespace with a TUN
inbound, so only those applications use the VPN. The package includes:

- the Textual TUI (`vpntui`);
- subscription import (`vless`, `vmess`, `trojan`, `ss`, `hysteria2`, base64
  lists and Xray JSON);
- a root helper used to create the namespace/TUN (`libexec/vpntui/run-vpn`);
- an optional NixOS module (`programs.vpntui`) that installs the helper and a
  scoped `NOPASSWD` sudo rule for the listed users.

Xray-core is a runtime dependency (`xray` in `PATH`) and is not bundled; the
helper refuses to execute user-owned binaries as root.

## Things done

- [x] Built on Linux
- [x] Tested the CLI and the headless TUI
- [x] Ran `nixpkgs-review` (to be done before opening the PR)
- [x] Added the NixOS module
- [x] Checked that the package builds without network access

## Notes for reviewers

The sudo rule is intentionally limited to the single helper path. The helper
creates a network namespace, starts `slirp4netns` and Xray, and always runs the
application as the invoking user. A user-owned Xray binary is executed as the
user, never as root.
