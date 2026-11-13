{
  lib,
  python3Packages,
  xray,
  iproute2,
  util-linux,
  slirp4netns,
  curl,
  libnotify,
  coreutils,
  makeWrapper,
}:

python3Packages.buildPythonApplication (finalAttrs: {
  pname = "vpntui";
  version = "1.0.1";
  pyproject = true;

  src = lib.cleanSourceWith {
    src = lib.cleanSource ../.;
    filter =
      path: type:
      let
        base = builtins.baseNameOf path;
      in
      !(builtins.elem base [
        ".venv"
        "__pycache__"
        "dist"
        "build"
        ".pytest_cache"
      ]);
  };

  build-system = [ python3Packages.hatchling ];

  dependencies = with python3Packages; [
    textual
    rich
  ];

  nativeBuildInputs = [ makeWrapper ];

  postInstall = ''
    install -Dm755 $src/src/vpntui/privileged/run-vpn $out/libexec/vpntui/run-vpn
    patchShebangs $out/libexec/vpntui/run-vpn

    wrapProgram $out/libexec/vpntui/run-vpn \
      --prefix PATH : ${
        lib.makeBinPath [
          iproute2
          util-linux
          slirp4netns
          libnotify
          coreutils
        ]
      }

    wrapProgram $out/bin/vpntui \
      --prefix PATH : ${
        lib.makeBinPath [
          xray
          iproute2
          util-linux
          slirp4netns
          curl
          libnotify
        ]
      }
  '';

  nativeCheckInputs = [ python3Packages.pytestCheckHook ];

  # The remaining tests need a TTY, root or a live Xray core.
  enabledTestPaths = [
    "tests/test_config.py"
    "tests/test_subscription.py"
  ];

  meta = {
    description = "Per-application VPN control panel built on Xray";
    homepage = "https://github.com/dodry-question/vpntui";
    license = lib.licenses.mit;
    maintainers = [ ];
    platforms = lib.platforms.linux;
    mainProgram = "vpntui";
  };
})
