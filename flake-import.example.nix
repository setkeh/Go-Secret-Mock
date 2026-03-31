# flake-import.example.nix
# Example flake.nix for a consumer project (e.g., a Flutter app)
# that imports and uses the go-secret-mock devShell.

{
  description = "My Flutter App with Go Secret Mock integration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    utils.url = "github:numtide/flake-utils";

    # Add the go-secret-mock project as an input
    go-secret-mock = {
      url = "github.com:setkeh/Go-Secret-Mock";
      flake = true;
    };
  };

  outputs = { self, nixpkgs, utils, go-secret-mock }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };

        # Inherit the devShell from the go-secret-mock flake
        # This will bring in 'go', 'dbus', 'pkg-config', and the dbus-launch shellHook
        # from your go-secret-mock project.
        go-secret-mock-shell = go-secret-mock.devShells.${system}.default;

      in
      {
        devShells.default = pkgs.mkShell {
          # Combine the devShells
          # This will merge the buildInputs and shellHook from go-secret-mock-shell
          inputsFrom = [ go-secret-mock-shell ];

          # Add any other buildInputs your main project (e.g., Flutter app) needs
          buildInputs = with pkgs; [
            flutter # Example: Add Flutter SDK
            # Add other dependencies specific to this consuming project
          ];

          shellHook = ''
            echo "--- Flutter App with Go Secret Mock Environment ---"
            # Any additional shell setup specific to your Flutter app can go here.
            # The shellHook from go-secret-mock will run before this,
            # ensuring the D-Bus session is set up.

            # Example: You might want to display info about the D-Bus session
            echo "DBUS_SESSION_BUS_ADDRESS: $DBUS_SESSION_BUS_ADDRESS"
          '';
        };
      });
}
