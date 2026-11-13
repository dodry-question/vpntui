# Publishing to nixpkgs

The repository already contains everything needed for a nixpkgs submission:

| File | Purpose |
|---|---|
| `flake.nix` | `nix run`, overlay and NixOS module for early users |
| `nix/package.nix` | package recipe for the local tree |
| `nix/module.nix` | NixOS module (package + root helper + sudo rule) |
| `nix/pkgs-by-name/vp/vpntui/package.nix` | ready-to-copy nixpkgs recipe |

## 1. Tag a release

```bash
git tag -a v1.0.1 -m 'vpntui 1.0.1'
git push origin master --tags
```

nixpkgs builds from a GitHub tag, not from the working tree.

## 2. Source hash

The recipe pins the source hash for the `v1.0.1` tag:

```
hash = "sha256-PJPCHngyTeu8xZYWuzZ5yppGhPAwhi/2KjtTaiA5pcY=";
```

The tag must be pushed to GitHub first (`git push origin v1.0.1`); the hash was
computed with `nix store prefetch-file --unpack` from the GitHub tag
archive, which is exactly what `fetchFromGitHub` unpacks.

When the tag or any tracked file changes, recompute it. In a nixpkgs checkout:

```bash
nix build --impure --expr '
  let pkgs = import <nixpkgs> {};
  in pkgs.fetchFromGitHub {
    owner = "dodry-question";
    repo = "vpntui";
    tag = "v1.0.1";
    hash = "";
  }'
```

or simply build the package once and replace `lib.fakeHash` with the hash
reported by Nix.

Copy `nix/pkgs-by-name/vp/vpntui/package.nix` to:

```
pkgs/by-name/vp/vpntui/package.nix
```

The `by-name` layout needs no entry in `pkgs/top-level/all-packages.nix`.
Add the NixOS module to `nixos/modules/programs/vpntui.nix` and register it in
`nixos/modules/module-list.nix` if you want users to enable it declaratively.

## 3. Check

```bash
nix-build -A vpntui
nix-shell -p nixpkgs-review --run "nixpkgs-review pr <number>"
```

The recipe runs the two self-contained test files (`test_config.py`,
`test_subscription.py`); the TUI and system-integration tests need a TTY, root
or a live Xray core and are skipped. The packaged helper is rewritten with
`patchShebangs`, so it always runs the interpreter from the same package.

The copy in `nix/pkgs-by-name/` keeps `maintainers = [ ]` so the flake builds
against released nixpkgs; the submitted recipe additionally lists
`lib.maintainers.dodry-question` and adds that entry to
`maintainers/maintainer-list.nix` (name `dodry`, GitHub ID 208013669).

The package must build without network access at build time; the Xray core is
a runtime dependency (`xray` in `PATH`) and is never downloaded during the
build. `vpntui core install` is only for non-Nix installations.

## 4. Open the PR

```bash
git checkout -b vpntui
git add pkgs/by-name/vp/vpntui/package.nix nixos/modules/programs/vpntui.nix \
  nixos/modules/module-list.nix nixos/doc/manual/release-notes/rl-2611.section.md \
  maintainers/maintainer-list.nix
git commit -m 'vpntui: init at 1.0.1'
gh pr create --repo NixOS/nixpkgs --title 'vpntui: init at 1.0.1' --body-file docs/NIXPKGS-PR.md
```

The repository is public, which is required for `fetchFromGitHub`. CI runs
`nixpkgs-review`; expect requests about the module's sudo rule and about
running the helper only for listed users.

## Repository-local check

On a machine with Nix:

```bash
nix build .#default
nix run .#default -- --status
nix flake check
```
