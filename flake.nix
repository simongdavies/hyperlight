{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.nixpkgs-mozilla.url = "github:mozilla/nixpkgs-mozilla/master";
  outputs = { self, nixpkgs, nixpkgs-mozilla, ... } @ inputs:
    rec {
      overlays.fix-rust = self: super: {
        # Work around the nixpkgs-mozilla equivalent of
        # https://github.com/NixOS/nixpkgs/issues/278508 and an
        # incompatibility between nixpkgs-mozilla and makeRustPlatform
        rustChannelOf = args: let
          orig = super.rustChannelOf args;
          patchRustPkg = pkg: (pkg.overrideAttrs (oA: {
            buildCommand = (builtins.replaceStrings
              [ "rustc,rustdoc" "librustc_driver-*.so" ]
              [ "rustc,rustdoc,clippy-driver,cargo-clippy,miri,cargo-miri" "librustc_driver-*.{so,dylib}" ]
              oA.buildCommand) + (let
                wrapperPath = self.path + "/pkgs/build-support/bintools-wrapper/ld-wrapper.sh";
                baseOut = self.clangStdenv.cc.bintools.out;
                getStdenvAttrs = drv: (drv.overrideAttrs (oA: {
                  passthru.origAttrs = oA;
                })).origAttrs;
                baseEnv = (getStdenvAttrs self.clangStdenv.cc.bintools).env;
                baseSubstitutedWrapper = self.replaceVars wrapperPath
                  {
                    inherit (baseEnv)
                      shell coreutils_bin suffixSalt mktemp rm;
                    use_response_file_by_default = "0";
                    prog = null;
                    out = null;
                  };
              in ''
                # work around a bug in the overlay
                ${oA.postInstall}

                # copy over helper scripts that the wrapper needs
                (cd "${baseOut}"; find . -type f \( -name '*.sh' -or -name '*.bash' \) -print0) | while read -d $'\0' script; do
                  mkdir -p "$out/$(dirname "$script")"
                  substitute "${baseOut}/$script" "$out/$script" --replace-quiet "${baseOut}" "$out"
                done

                # TODO: Work out how to make this work with cross builds
                ldlld="$out/lib/rustlib/${self.clangStdenv.targetPlatform.config}/bin/gcc-ld/ld.lld";
                if [ -e "$ldlld" ]; then
                  export prog="$(readlink -f "$ldlld")"
                  rm "$ldlld"
                  substitute ${baseSubstitutedWrapper} "$ldlld" --subst-var "out" --subst-var "prog"
                  chmod +x "$ldlld"
                fi
              '');
            passthru = (oA.passthru or {}) // {
              toolchainVersionAttrs = args;
            };
          })) // {
            targetPlatforms = [ "aarch64-linux" "x86_64-linux" "aarch64-darwin" ];
            badTargetPlatforms = [ ];
          };
          overrideRustPkg = pkg: self.lib.makeOverridable (origArgs:
            patchRustPkg (pkg.override origArgs)
          ) {};
        in builtins.mapAttrs (_: overrideRustPkg) orig;
      };
      gcroots =
        let gcrootForShell = pkg: pkg // derivation (pkg.drvAttrs // {
              origArgs = pkg.drvAttrs.args;
              # assume the builder is bash for now (it always is for
              # stdenv, which is the only thing that we will encounter
              # in this flake).
              args = [ "-c" "declare > $out" ];
            });
        in {
          shells.x86_64-linux.default = gcrootForShell devShells.x86_64-linux.default;
          shells.aarch64-linux.default = gcrootForShell devShells.aarch64-linux.default;
        };
      devShells = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (system: {
        default = let pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import (nixpkgs-mozilla + "/rust-overlay.nix")) overlays.fix-rust ];
        }; in with pkgs; let
          customisedRustChannelOf = args:
            lib.flip builtins.mapAttrs (rustChannelOf args) (_: pkg: pkg.override {
              targets = [
                "x86_64-unknown-linux-gnu"
                "x86_64-pc-windows-msvc" "x86_64-unknown-none"
                "wasm32-wasip1" "wasm32-wasip2" "wasm32-unknown-unknown"
                "aarch64-unknown-none" "aarch64-apple-darwin"
              ];
              extensions = [ "rust-src" "rustfmt-preview" "clippy-preview" ]
                ++ (if args.channel == "nightly" then [ "miri-preview" "llvm-tools-preview" ] else []);
            });

          # Hyperlight needs a variety of toolchains, since we use Nightly
          # for rustfmt and old toolchains to verify MSRV
          toolchains = lib.mapAttrs (_: customisedRustChannelOf) {
            stable = {
              date = "2026-04-16";
              channel = "stable";
              sha256 = "sha256-gh/xTkxKHL4eiRXzWv8KP7vfjSk61Iq48x47BEDFgfk=";
            };
            "1.94" = {
              date = "2026-03-05";
              channel = "stable";
              sha256 = "sha256-qqF33vNuAdU5vua96VKVIwuc43j4EFeEXbjQ6+l4mO4=";
            };
            nightly = {
              date = "2026-02-27";
              channel = "nightly";
              sha256 = "sha256-5twI9QsrPl0ryOZ4POGYAivSeI08jgmWnv0wVvzbjcE=";
            };
            "1.89" = {
              date = "2025-08-07";
              channel = "stable";
              sha256 = "sha256-+9FmLhAOezBZCOziO0Qct1NOrfpjNsXxc/8I0c7BdKE=";
            };
          };

          rust-platform = makeRustPlatform {
            cargo = toolchains.stable.rust;
            rustc = toolchains.stable.rust;
          };

          manifests = {
            "Cargo.toml" = {
              outputHashes = {
                "piet-0.8.0" = "sha256-yHF0axor+uaGC0RYhw1JmjvFLVTYZkTx1XzDtuN2KIk=";
                "mesh_process-0.0.0" = "sha256-q6FGSXMmCr68osL7p4HbniwOKJhjBL0X0aVc6kpyLYo=";
              };
            };
            "src/tests/rust_guests/Cargo.toml" = {
            };
          };
          manifestDeps = lib.mapAttrsToList (manifest: importArguments:
            let lockPath = builtins.replaceStrings [ "toml" ] [ "lock" ] manifest; in
            let lockFile = ./${lockPath}; in
            rust-platform.importCargoLock ({
              inherit lockFile;
            } // importArguments)) manifests;
          # when building a guest with cargo-hyperlight, or when
          # building a miri sysroot for the main workspace, we need to
          # include any crates.io dependencies of the standard library
          # (e.g. rustc-literal-escaper)
          stdlibLocks = lib.mapAttrsToList (_: toolchain:
            "${toolchain.rust}/lib/rustlib/src/rust/library/Cargo.lock"
          ) toolchains;
          stdlibDeps = builtins.map (lockFile:
            rust-platform.importCargoLock { inherit lockFile; }) stdlibLocks;
          deps = pkgs.symlinkJoin {
            name = "cargo-deps";
            paths = stdlibDeps ++ manifestDeps;
          };

          # Script snippet, used in the cargo wrapper below,
          # which creates a number of .cargo/config.toml files in
          # order to allow using Nix-fetched dependencies (this must
          # be done for the guests, as well as for the main
          # workspace).  Ideally, we would just use environment
          # variables or the --config option to Cargo, but
          # unfortunately that tends not to play well with subcommands
          # like `cargo clippy` and `cargo hyperlight` (see
          # https://github.com/rust-lang/cargo/issues/11031).
          materialiseDeps = let
            sortedManifests = lib.lists.sort (p: q: p > q) (lib.attrNames manifests);
            matchClause = path: ''  */${path}) root="''${manifest%${path}}" ;;'';
            matchClauses = lib.strings.concatStringsSep "\n"
              (builtins.map matchClause sortedManifests);
          in ''
            base_cargo() {
              PATH="$base/bin:$PATH" "$base/bin/cargo" "$@"
            }

            manifest=$(base_cargo locate-project --message-format plain --workspace)
            case "$manifest" in
              ${matchClauses}
            esac
            if [ -f ''${root}/flake.nix ]; then

              sed -i '/# vendor dependency configuration generated by nix/{N;N;N;N;N;d;}' $root/.cargo/config.toml
              cat >>$root/.cargo/config.toml <<EOF
            # vendor dependency configuration generated by nix
            [source.crates-io]
            replace-with = "vendored-sources"

            [source.vendored-sources]
            directory = "${deps}"
            EOF

              sed -i '/# vendor dependency configuration generated by nix/{N;d;}' $root/.git/info/exclude
              printf "# vendor dependency configuration generated by nix\n%s\n" "/.cargo" >> $root/.git/info/exclude
            fi

            # libgit2-sys copies a vendored git2 into the target/
            # directory somewhere. In certain, rare, cases,
            # libgit2-sys is rebuilt in the same incremental dep
            # directory as it was before, and then this copy fails,
            # because the files, copied from the nix store, already
            # exist and do not have w permission. Hack around this
            # issue by making any existing libgit2-sys vendored git2
            # files writable before a build can be run
            find "$(base_cargo metadata --format-version 1 | jq -r '.target_directory')" -path '*/build/libgit2-sys-*/out/include' -print0 | xargs -r -0 chmod u+w -R
          '';

          # Toolchains and components are supplied by Nix, not rustup.
          selectToolchain = let
              selectors = toolchains // { "1.95" = toolchains.stable; };
              clause = name: toolchain: ''
                ${name}|${name}-${toolchain.rust.toolchainVersionAttrs.date}) base="${toolchain.rust}" ;;
              '';
              clauses = lib.strings.concatStringsSep "\n"
                (lib.mapAttrsToList clause selectors);
            in ''
              fail() { echo "$*" >&2; exit 1; }
              select_toolchain() {
                case "$1" in
                  ${clauses}
                  *) fail "Unsupported Nix Rust toolchain: $1" ;;
                esac
              }
              toolchain="''${RUSTUP_TOOLCHAIN:-stable}"
              case "''${1:-}" in
                +*) toolchain="''${1#+}"; shift ;;
              esac
              select_toolchain "$toolchain"
            '';
          rustup-like-wrapper = name: pkgs.writeShellScriptBin name ''
              ${selectToolchain}
              ${lib.optionalString (name == "cargo") ''
                if [ "''${1:-}" = install ]; then exit 0; fi
                ${materialiseDeps}
              ''}
              export PATH="$base/bin:$PATH"
              exec "$base/bin/${name}" "$@"
            '';
          nix-rustup = pkgs.writeShellScriptBin "rustup" ''
            if [ "''${1:-}" = --quiet ]; then shift; fi
            ${selectToolchain}
            action="''${1:-}"
            shift || fail "Expected a rustup action"
            case "$action" in
              run)
                [ "$#" -ge 2 ] || fail "Expected a toolchain and command"
                toolchain="$1"
                select_toolchain "$toolchain"
                shift
                export RUSTUP_TOOLCHAIN="$toolchain"
                # Keep cargo's dependency wrapper ahead of the selected binaries.
                export PATH="$(dirname "$0"):$base/bin:$PATH"
                exec "$@"
                ;;
              component|toolchain|target) ;;
              *) fail "Unsupported Nix rustup action: $action" ;;
            esac
            operation="''${1:-}"
            shift || fail "Expected a rustup operation"
            items=()
            while [ "$#" -gt 0 ]; do
              case "$1" in
                --toolchain)
                  [ "$action" != toolchain ] && [ "$#" -ge 2 ] || fail "Invalid --toolchain"
                  toolchain="$2"; select_toolchain "$toolchain"; shift 2 ;;
                --no-self-update)
                  [ "$action/$operation" = toolchain/install ] || fail "Invalid --no-self-update"
                  shift ;;
                --profile)
                  [ "$action/$operation" = toolchain/install ] && [ "$#" -ge 2 ] || fail "Invalid --profile"
                  case "$2" in minimal|default|complete) ;; *) fail "Unsupported profile: $2" ;; esac
                  shift 2 ;;
                --installed)
                  [ "$operation" = list ] && [ "$action" != toolchain ] || fail "Invalid --installed"
                  shift ;;
                -*) fail "Unsupported Nix rustup option: $1" ;;
                *) items+=("$1"); shift ;;
              esac
            done
            case "$action/$operation" in
              toolchain/list)
                [ "''${#items[@]}" -eq 0 ] || fail "Unexpected toolchain list arguments"
                printf '%s\n' ${lib.escapeShellArgs (lib.attrNames toolchains ++ [ "1.95" ])}
                ;;
              toolchain/install)
                [ "''${#items[@]}" -gt 0 ] || fail "Expected a toolchain"
                for item in "''${items[@]}"; do select_toolchain "$item"; done
                ;;
              component/list)
                [ "''${#items[@]}" -eq 0 ] || fail "Unexpected component list arguments"
                for manifest in "$base"/lib/rustlib/manifest-*; do
                  [ -f "$manifest" ] || continue
                  printf '%s (installed)\n' "''${manifest##*/manifest-}"
                done
                ;;
              component/add)
                [ "''${#items[@]}" -gt 0 ] || fail "Expected a component"
                for item in "''${items[@]}"; do
                  case "$item" in
                    rustfmt|clippy|miri|llvm-tools) item="$item-preview" ;;
                    rust-src|rustfmt-preview|clippy-preview|miri-preview|llvm-tools-preview) ;;
                    *) fail "Unsupported Nix Rust component: $item" ;;
                  esac
                  compgen -G "$base/lib/rustlib/manifest-$item" >/dev/null ||
                    compgen -G "$base/lib/rustlib/manifest-$item-*" >/dev/null ||
                    fail "Component $item is not supplied by Nix for $toolchain"
                done
                ;;
              target/add)
                [ "''${#items[@]}" -gt 0 ] || fail "Expected a target"
                for item in "''${items[@]}"; do
                  [ -d "$base/lib/rustlib/$item/lib" ] ||
                    fail "Target $item is not supplied by Nix for $toolchain"
                done
                ;;
              *) fail "Unsupported Nix rustup action: $action $operation" ;;
            esac
          '';
          fake-rustup = pkgs.symlinkJoin {
            name = "fake-rustup";
            paths = [
              nix-rustup
              (rustup-like-wrapper "rustc")
              (rustup-like-wrapper "cargo")
            ];
          };

          buildRustPackageClang = rust-platform.buildRustPackage.override { stdenv = clangStdenv; };

          # Keep the version in lockstep with the one pinned in the Justfile.
          # `dev/update-cargo-hyperlight-version.sh` updates both.
          cargo-hyperlight = let
            version = "0.1.14";
            # The .crate tarball is hashed flat, so the pin can be refreshed
            # from the checksum crates.io publishes, without running Nix.
            src = fetchurl {
              url = "https://static.crates.io/crates/cargo-hyperlight/cargo-hyperlight-${version}.crate";
              name = "cargo-hyperlight-${version}.tar.gz";
              hash = "sha256-xS8cnUthc677Zv3C4+ES3bNZ/i+9uq/hubol96xXizk=";
            };
          in buildRustPackageClang {
            pname = "cargo-hyperlight";
            inherit version src;
            # The tarball ships a Cargo.lock, so the dependencies need no
            # vendor hash of their own.
            cargoDeps = rust-platform.importCargoLock {
              lockFile = runCommand "cargo-hyperlight-${version}-Cargo.lock" {}
                "tar -xzOf ${src} cargo-hyperlight-${version}/Cargo.lock > $out";
            };
            doCheck = false;
          };
        in (buildRustPackageClang (mkDerivationAttrs: {
          pname = "hyperlight";
          version = "0.0.0";
          src = lib.cleanSource ./.;
          cargoDeps = deps;

          nativeBuildInputs = [
            azure-cli
            just
            dotnet-sdk_9
            llvmPackages_18.llvm
            gh
            lld
            pkg-config
            ffmpeg
            mkvtoolnix
            wasm-tools
            jq
            jaq
            gdb
            zlib
            cargo-hyperlight
            typos
            flatbuffers
            cargo-fuzz
          ] ++ (if system == "x86_64-linux" || system == "aarch64-linux"
                then [ valgrind ]
                else []);
          buildInputs = [
            pango
            cairo
            openssl
          ];

          auditable = false;

          LIBCLANG_PATH = "${pkgs.llvmPackages_18.libclang.lib}/lib";
          # Use unwrapped clang for compiling guests
          HYPERLIGHT_GUEST_clang = "${clang.cc}/bin/clang";

          RUST_NIGHTLY = "${toolchains.nightly.rust}";
          # Set this through shellHook rather than nativeBuildInputs to be
          # really sure that it overrides the real cargo.
          postHook = ''
            export PATH="${fake-rustup}/bin:$PATH"
          '';
        })).overrideAttrs(oA: {
          hardeningDisable = [ "all" ];
        });
      });
    };
}
