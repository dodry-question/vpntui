{
  description = "vpntui — per-application VPN panel built on Xray";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems
        (system: fn nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.callPackage ./nix/package.nix { };
        vpntui = pkgs.callPackage ./nix/package.nix { };
      });

      overlays.default = final: prev: {
        vpntui = final.callPackage ./nix/package.nix { };
      };

      nixosModules.default = import ./nix/module.nix;
      nixosModules.vpntui = import ./nix/module.nix;
    };
}
