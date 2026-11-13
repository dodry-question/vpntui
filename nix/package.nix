{ lib
, python3
, xray
, iproute2
, util-linux
, slirp4netns
, curl
, libnotify
, coreutils
, makeWrapper
}:

python3.pkgs.buildPythonApplication rec {
  pname = "vpntui";
  version = "1.0.1";
  pyproject = true;

  src = lib.cleanSourceWith {
    src = lib.cleanSource ../.;
    filter = path: type:
      let base = builtins.baseNameOf path; in
      !(builtins.elem base [ ".venv" "__pycache__" "dist" "build" ".pytest_cache" ]);
  };

  dependencies = with python3.pkgs; [
    textual
    rich
  ];

  nativeBuildInputs = [
    python3.pkgs.hatchling
    makeWrapper
  ];

  postInstall = ''
    install -Dm755 ${../src/vpntui/privileged/run-vpn} $out/libexec/vpntui/run-vpn
    sed -i '1c #!${python3}/bin/python3' $out/libexec/vpntui/run-vpn
    wrapProgram $out/libexec/vpntui/run-vpn \
      --prefix PATH : ${lib.makeBinPath [ iproute2 util-linux slirp4netns libnotify coreutils ]}

    wrapProgram $out/bin/vpntui \
      --prefix PATH : ${lib.makeBinPath [ xray iproute2 util-linux slirp4netns curl libnotify ]}
  '';

  # Textual tests need a TTY; unit tests do not need network or root.
  doCheck = false;

  meta = with lib; {
    description = "Per-application VPN control panel built on Xray";
    homepage = "https://github.com/dodry-question/vpntui";
    license = licenses.mit;
    maintainers = [ ];
    platforms = platforms.linux;
    mainProgram = "vpntui";
  };
}
