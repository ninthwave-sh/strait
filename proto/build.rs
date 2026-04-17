//! Build script for `strait-proto`.
//!
//! Compiles `strait_host.proto` via `tonic_build`. Generated code is emitted
//! into `OUT_DIR` and included by `src/lib.rs`. The vendored `protoc` binary
//! avoids a system dependency on a protoc install.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=strait_host.proto");

    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["strait_host.proto"], &["."])?;

    Ok(())
}
