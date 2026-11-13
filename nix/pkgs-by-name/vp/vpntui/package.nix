{ lib
, fetchFromGitHub
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
  version = "1.0.0";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "dodry-question";
    repo = "vpntui";
    tag = "v${version}";
    hash = "sha256-WQxoJAomGysJvdVlpKZqAh+NCmU4DIb7YfOztwMBzkI=";
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
    install -Dm755 ${src}/src/vpntui/privileged/run-vpn $out/libexec/vpntui/run-vpn
    sed -i '1c #!${python3}/bin/python3' $out/libexec/vpntui/run-vpn
    wrapProgram $out/libexec/vpntui/run-vpn \
      --prefix PATH : ${lib.makeBinPath [ iproute2 util-linux slirp4netns libnotify coreutils ]}
    wrapProgram $out/bin/vpntui \
      --prefix PATH : ${lib.makeBinPath [ xray iproute2 util-linux slirp4netns curl libnotify ]}
  '';

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
