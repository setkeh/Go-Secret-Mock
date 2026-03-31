{
  description = "Go Secret Mock for Flutter Development";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            pkg-config
            dbus
          ];

          shellHook = ''
            eval $(dbus-launch --exit-with-session)
            echo "--- Go Secret Mock Build Environment ---"
          '';
        };
      });
}