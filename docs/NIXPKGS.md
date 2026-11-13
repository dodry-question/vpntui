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
git tag -a v1.0.0 -m 'vpntui 1.0.0'
git push origin master --tags
```

nixpkgs builds from a GitHub tag, not from the working tree.

## 2. Source hash

The recipe pins the source hash for the `v1.0.0` tag:

```
hash = "sha256-WQxoJAomGysJvdVlpKZqAh+NCmU4DIb7YfOztwMBzkI=";
```

The tag must be pushed to GitHub first (`git push origin v1.0.0`); the hash was
computed from the release tree with `nix hash path --sri` on a clean
`git archive` export, which matches `fetchFromGitHub` after root stripping.

When the tag or any tracked file changes, recompute it. In a nixpkgs checkout:

```bash
nix build --impure --expr '
  let pkgs = import <nixpkgs> {};
  in pkgs.fetchFromGitHub {
    owner = "dodry-question";
    repo = "vpntui";
    tag = "v1.0.0";
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

The package must build without network access at build time; the Xray core is
a runtime dependency (`xray` in `PATH`) and is never downloaded during the
build. `vpntui core install` is only for non-Nix installations.

## 4. Open the PR

```bash
git checkout -b vpntui
git add pkgs/by-name/vp/vpntui/package.nix nixos/modules/programs/vpntui.nix
git commit -m 'vpntui: init at 1.0.0'
gh pr create --repo NixOS/nixpkgs --title 'vpntui: init at 1.0.0' --body-file docs/NIXPKGS-PR.md
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
