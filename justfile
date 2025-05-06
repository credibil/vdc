#!/usr/bin/env -S just --justfile
# ^ shebang allows a justfile to be executed as a script, e.g. `./justfile test`.
# See https://just.systems/man/en/introduction.html

alias t := test

log := "warn"
export JUST_LOG := log
export RUSTFLAGS := "-Dwarnings"

# -----------------------------------------------------------------------------
# Build and test
# -----------------------------------------------------------------------------

[group: 'test']
test:
    cargo nextest run --no-fail-fast --all-features

#  e.g. `just test-one vci_pre_auth`
[group: 'test']
test-one target:
    cargo nextest run --no-fail-fast --all-features --test {{target}}

[group: 'test']
test-docs:
    cargo test doc 

# -----------------------------------------------------------------------------
# Basic hygiene
# -----------------------------------------------------------------------------

[group: 'check']
lint:
    cargo clippy --all-features -- -D warnings

[group: 'clean']
fmt:
    cargo fmt --all --check

[group: 'check']
check: lint fmt
