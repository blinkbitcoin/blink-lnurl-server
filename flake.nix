{
  description = "Blink LNURL server local development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rustVersion = pkgs.pkgsBuildHost.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        rustToolchain = rustVersion.override {
          extensions = [ "rust-analyzer" "rust-src" ];
        };
        batsLatest = pkgs.bats.overrideAttrs (_old: {
          version = "1.13.0";
          src = pkgs.fetchFromGitHub {
            owner = "bats-core";
            repo = "bats-core";
            rev = "v1.13.0";
            sha256 = "145s0ca5vy3bs50hvkk1qkbi8hdiyvc7jp2rmnyvnjihdsdq2p1n";
          };
        });
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            bashInteractive
            cargo-audit
            curl
            direnv
            docker
            docker-compose
            jq
            openssl
            pkg-config
            postgresql
            protobuf
            rustToolchain
            typos
            batsLatest
          ];

          shellHook = ''
            unset DEVELOPER_DIR
            export DATABASE_URL="postgres://user:password@127.0.0.1:5432/lnurl"
          '';
        };

        formatter = pkgs.alejandra;
      });
}
