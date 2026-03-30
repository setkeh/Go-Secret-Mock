{
  description = "Go Secret Mock for Flutter Development";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
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
            dbus
            dbus-glib
          ];

          shellHook = ''
            echo "--- Go Secret Mock Build Environment ---"

            echo "--- Starting DBUS for unit Tetsing ---"
            export $(dbus-launch --exit-with-session)
            
            echo "--- Running Go Mod Tidy ---"
            go mod tidy

            echo "--- Running Go Build ---"
            go build .
          '';
        };
      });
}