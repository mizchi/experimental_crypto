{
  description = "mizchi/moonbit-crypto — MoonBit + Why3 (via opam) for moon prove";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    moonbit-overlay.url = "github:moonbit-community/moonbit-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
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
          # darwin: nixpkgs marks tinycc broken, which makes the moonbit-overlay
          # toolchains derivation fail at eval time. Allow the broken tcc through
          # so we can override install-phase to keep the tarball-shipped tcc.
          # alt-ergo's "ocamlpro_nc" license is unfree on nixpkgs; allow it for
          # non-commercial verification use.
          config = {
            problems.handlers.tcc.broken = "ignore";
            allowUnfreePredicate =
              pkg: builtins.elem (nixpkgs.lib.getName pkg) [ "alt-ergo" ];
          };
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

        # symlinkJoin of fixed toolchains + core, replacing the upstream
        # `paths` so the bundled tcc is preserved.
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

            # opam + OCaml build deps (why3 1.7.2 is installed into a
            # project-local opam switch — see proofs/setup.sh).
            pkgs.opam
            pkgs.gnumake
            pkgs.m4
            pkgs.gmp # zarith (why3 transitive dep)
            pkgs.zlib
            pkgs.pkg-config
            pkgs.unzip
            pkgs.rsync
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            # darwin: opam-installed dune needs fsevents → CoreFoundation /
            # CoreServices from apple-sdk.
            pkgs.apple-sdk
          ]
          ++ [
            # SMT solvers why3 will detect. z3 alone is enough for the
            # current proof goals; alt-ergo + cvc5 widen coverage for
            # future quantified-VC work.
            pkgs.z3
            pkgs.alt-ergo
            pkgs.cvc5
          ];

          shellHook = ''
            export OPAMROOT="$PWD/.opam"
            export MOON_HOME="${moonbit}"

            if [ -d "$OPAMROOT" ] && opam var --root="$OPAMROOT" root >/dev/null 2>&1; then
              eval "$(opam env --root="$OPAMROOT" --set-root --set-switch 2>/dev/null || true)"
              if command -v why3 >/dev/null 2>&1; then
                echo "[moonbit-crypto] dev shell ready: moon=${moonbit}, why3=$(why3 --version 2>/dev/null | head -1)"
              else
                echo "[moonbit-crypto] opam switch present but why3 missing; run: bash proofs/setup.sh"
              fi
            else
              cat <<'EOS'
[moonbit-crypto] First time: install Why3 1.7.2 into the project-local
opam switch:

    bash proofs/setup.sh

Subsequent shells will auto-activate the switch via this shellHook.
EOS
            fi
          '';
        };
      }
    );
}
