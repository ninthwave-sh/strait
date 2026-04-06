# Feat: Auto-build container image from strait.toml config (H-DF2-3)

**Priority:** High
**Source:** Dogfooding review -- users should not need to maintain Dockerfiles
**Depends on:** None
**Domain:** dogfood
**Lineage:** e1ed7a81-534d-4141-a08f-16a779190e23

Add a `[container]` section to `strait.toml` that declaratively specifies what the container image needs. strait generates a Dockerfile, builds the image via bollard's build API, and caches it by content hash. Users add a tool by editing config instead of maintaining a Dockerfile.

Config:
```toml
[container]
base_image = "ubuntu:24.04"
apt = ["git", "curl", "ca-certificates"]
npm = ["@anthropic-ai/claude-code"]
# pip = ["ruff"]  # optional
```

Implementation:

1. Add `ContainerSpec` struct to `src/config.rs`:
   - `base_image: String` (required, no default)
   - `apt: Vec<String>` (optional, default empty)
   - `npm: Vec<String>` (optional, default empty)
   - `pip: Vec<String>` (optional, default empty)

2. Add `[container]` as optional field on `StraitConfig`. When present, it overrides `--image`.

3. Add image build logic in `src/container.rs`:
   - `generate_dockerfile(spec: &ContainerSpec) -> String` -- produces a Dockerfile from the spec
   - `build_or_reuse_image(docker: &Docker, spec: &ContainerSpec) -> Result<String>` -- hashes the spec, checks if `strait-cache:<hash>` exists locally, builds if not
   - Use bollard's `build_image()` with a tar context containing the generated Dockerfile
   - Stream build output to tracing logs

4. Hook into launch flow in `src/launch.rs`:
   - After loading config, before container creation
   - If `config.container` is Some, call `build_or_reuse_image()` and use the resulting tag
   - If `--image` is also provided, `--image` wins (explicit override)

The generated Dockerfile pattern:
```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN npm install -g @anthropic-ai/claude-code
```

Each package manager step is its own RUN layer for Docker layer caching.

**Test plan:**
- Unit test `generate_dockerfile`: verify output for apt-only, npm-only, combined specs
- Unit test content hash: same spec produces same hash, different spec different hash
- Unit test config parsing: `[container]` section deserializes correctly, optional fields default to empty
- Integration test: `build_or_reuse_image` with a minimal spec (just `base_image = "alpine"`) builds and tags
- Integration test: second call with same spec skips build (cache hit)
- Verify `--image` flag overrides `[container]` spec

Acceptance: `strait launch --config strait.toml --observe -- echo hello` with a `[container]` section in strait.toml auto-builds and caches the image. Subsequent launches with the same spec reuse the cached image (no rebuild). Changing the spec triggers a rebuild. `--image` overrides the auto-built image. `cargo test --all-features` passes.

Key files: `src/config.rs`, `src/container.rs`, `src/launch.rs`
