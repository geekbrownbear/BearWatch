# Cross-compiles bw-agent.exe for 64-bit Windows from Linux, so building needs only Docker.
# Use agent/build.ps1 (Compose) to build and copy the exe out to dist/.
FROM rust:1.88-slim-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc-mingw-w64-x86-64 \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add x86_64-pc-windows-gnu
ENV CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
WORKDIR /src

# Dependencies first, against a stub main, so code edits rebuild only the agent itself.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
 && cargo build --release --target x86_64-pc-windows-gnu \
 && rm -rf src

COPY src ./src
RUN touch src/main.rs \
 && cargo build --release --target x86_64-pc-windows-gnu \
 && mkdir /out \
 && cp target/x86_64-pc-windows-gnu/release/bw-agent.exe Cargo.lock /out/

# Tiny stage that `docker compose cp` can copy the exe out of.
FROM busybox:1.36
COPY --from=build /out /out
CMD ["true"]
