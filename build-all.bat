@echo off
(
    echo "Installing npm dependencies..."
    call pnpm install

    echo "Building typescript packages..."
    call pnpm --filter @openai/codex-sdk build

    echo "Building Rust packages..."
    cd codex-rs
    cargo build --release
    cd ..

    echo "Build complete."
) > build.log 2>&1