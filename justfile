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
        cargo test -p {{PROJECT}} -- --nocapture --deploy; \
    else \
        cargo test -p {{PROJECT}} -- --nocapture; \
    fi

# Run all tests
test-all:
    cargo test --workspace -- --nocapture