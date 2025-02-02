set positional-arguments

# Run linting
lint:
    cargo clippy --all-targets -- -D clippy::all -D clippy::nursery

# Check formatting
fmt:
    cargo fmt --check

# Verify all compiles
check:
    cargo check

# Verify all compiles with wasm
check-wasm:
    cargo check --target wasm32-unknown-unknown
    
# Run example
run PROJECT *FLAGS:
    if [[ " {{FLAGS}} " == *" --deploy "* ]]; then \
        DEPLOY=true cargo test -p {{PROJECT}} -- --nocapture; \
    else \
        cargo test -p {{PROJECT}} -- --nocapture; \
    fi

# Run all tests
test-all:
    cargo test --workspace --exclude bitcoin-signing-segwit --exclude bitcoin-signing-segwit-multiple-utxos --exclude bitcoin-signing-with-propagation-legacy -- --nocapture