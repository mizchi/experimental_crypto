{
  description = "mizchi/moonbit-crypto — MoonBit + Why3 (all-nix, no opam) for moon prove";

  inputs = {
    # Main pinned to unstable for cvc5 1.3.x / z3 4.16.x and the moonbit
    # overlay. Anything that doesn't need to match Why3's recognized-prover
    # database goes here.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Why3 was 1.7.2 on nixos-24.05; after that nixpkgs bumped to 1.8.x,
    # which `moon prove` does not accept. Pin Why3 (and Alt-Ergo, which
    # Why3 1.7.2 only recognizes up to 2.5.x) to this branch.
    nixpkgs-why3.url = "github:NixOS/nixpkgs/nixos-24.05";

    flake-utils.url = "github:numtide/flake-utils";
    moonbit-overlay.url = "github:moonbit-community/moonbit-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-why3,
      flake-utils,
      moonbit-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ moonbit-overlay.overlays.default ];
          config = {
            problems.handlers.tcc.broken = "ignore";
            allowUnfreePredicate =
              pkg: builtins.elem (nixpkgs.lib.getName pkg) [ "alt-ergo" ];
          };
        };

        pkgs-why3 = import nixpkgs-why3 {
          inherit system;
          config.allowUnfreePredicate =
            pkg: builtins.elem (nixpkgs-why3.lib.getName pkg) [ "alt-ergo" ];
        };

        # darwin moonbit-overlay toolchains install-phase tries to substitute
        # the bundled tcc with nixpkgs tinycc (broken on darwin). We don't use
        # MoonBit native backend here — `moon prove` only needs wasm-gc — so
        # we keep the bundled tcc as-is.
        toolchainsFixed =
          if pkgs.stdenv.isDarwin then
            pkgs.moonbit-bin.toolchains.latest.overrideAttrs (old: {
              buildInputs = builtins.filter
                (p: (p.pname or p.name or "") != "tcc")
                (old.buildInputs or [ ]);
              installPhase = ''
                runHook preInstall
                mkdir -p $out
                cp -a ./* $out/
                chmod +x $out/bin/* || true
                [ -f $out/bin/internal/tcc ] && chmod +x $out/bin/internal/tcc || true
                runHook postInstall
              '';
            })
          else
            pkgs.moonbit-bin.toolchains.latest;

        moonbit = pkgs.moonbit-bin.moonbit.latest.overrideAttrs (_old: {
          paths = [
            toolchainsFixed
            pkgs.moonbit-bin.core.latest
          ];
        });
      in
      {
        packages = {
          inherit moonbit;
          default = moonbit;
        };

        devShells.default = pkgs.mkShell {
          packages = [
            moonbit

            # Why3 1.7.2 (the only version `moon prove` accepts) + Alt-Ergo
            # 2.5.4 (which Why3 1.7.2 recognizes natively). Both from
            # nixos-24.05.
            pkgs-why3.why3
            pkgs-why3.alt-ergo

            # Newer Z3 / CVC5 from unstable. Why3 1.7.2 marks them as
            # "unrecognized version" but still dispatches via the closest
            # driver; the custom strategy in proofs/why3.conf names the
            # exact versions so this is fine.
            pkgs.z3
            pkgs.cvc5
          ];

          shellHook = ''
            export MOON_HOME=${moonbit}
            if [ ! -f proofs/why3.conf ]; then
              echo "[moonbit-crypto] First time: generate the multi-solver Why3 config:"
              echo "    bash proofs/setup.sh"
            else
              echo "[moonbit-crypto] dev shell ready: why3=$(why3 --version 2>/dev/null | head -1)"
            fi
          '';
        };
      }
    );
}
