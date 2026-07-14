fn main() {
    println!("cargo:rerun-if-changed=proto/qsw_channel.proto");
    #[cfg(feature = "grpc")]
    compile_grpc_proto();
}

// cfg on an item (not a block-statement) so the whole function, including
// its references to tonic-build/protoc-bin-vendored, is stripped when the
// grpc feature (and its optional build-dependencies) are disabled.
#[cfg(feature = "grpc")]
fn compile_grpc_proto() {
    if std::env::var("PROTOC").is_err() {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    }
    tonic_build::compile_protos("proto/qsw_channel.proto").expect("compile qsw_channel.proto");
}
