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

- [x] Built on Linux (`python3Packages.buildPythonApplication`, tests enabled)
- [x] Tested the CLI and the headless TUI manually; the packaged tests run
      `tests/test_config.py` and `tests/test_subscription.py`
- [x] Added the NixOS module and evaluated `programs.vpntui` with two users
      (sudo rule, `VPNTUI_HELPER`, `environment.systemPackages`)
- [x] Checked that the package builds without network access; Xray is only a
      runtime dependency
- [ ] `nixpkgs-review` — not run locally (no Nix on the development host); the
      recipe was built against `nixos-unstable` in a container with the same
      `fetchFromGitHub` hash

## Disclosure

The packaging (recipe, module, release note) was prepared with an LLM-based
tool: OpenCode (DeepSeek V4.1 Flash Free). I reviewed every change and built
and tested it before submitting:

- `nix build github:dodry-question/vpntui/v1.0.1#default` in a clean container;
- the recipe in this PR built against `nixos-unstable`;
- `programs.vpntui` evaluated with two users (sudo rule, `VPNTUI_HELPER`,
  `environment.systemPackages`).

## Notes for reviewers

Tests for the TUI itself need a TTY and are excluded via `enabledTestPaths`;
the remaining suite has no network or root access.

The sudo rule is intentionally limited to the single helper path. The helper
creates a network namespace, starts `slirp4netns` and Xray, and always runs the
application as the invoking user. A user-owned Xray binary is executed as the
user, never as root.
