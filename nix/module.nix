{ config, lib, pkgs, ... }:

let
  cfg = config.programs.vpntui;
  helper = "${cfg.package}/libexec/vpntui/run-vpn";
  desktopItem = pkgs.makeDesktopItem {
    name = "vpntui";
    desktopName = "VPN (vpntui)";
    genericName = "Per-app VPN";
    comment = "Run selected applications through Xray";
    exec = "${cfg.package}/bin/vpntui";
    icon = "network-vpn";
    terminal = true;
    categories = [ "Network" "System" ];
    keywords = [ "vpn" "proxy" "xray" "vpntui" ];
  };
in
{
  options.programs.vpntui = {
    enable = lib.mkEnableOption "vpntui per-application VPN panel";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "The vpntui package to install.";
    };

    users = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "alice" ];
      description = ''
        Users allowed to run the root helper without a password.  The helper
        only creates a network namespace and runs Xray; it never executes
        user-owned binaries as root.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package desktopItem ];

    security.sudo.extraRules = map (user: {
      users = [ user ];
      commands = [{
        command = helper;
        options = [ "NOPASSWD" ];
      }];
    }) cfg.users;

    environment.sessionVariables.VPNTUI_HELPER = helper;
  };
}
