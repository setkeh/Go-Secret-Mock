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
          ];

          shellHook = ''
            echo "--- Go Secret Mock Build Environment ---"
            
            echo "--- Running Go Mod Tidy ---"
            go mod tidy

            echo "--- Running Go Build ---"
            go build .
          '';
        };
      });
}