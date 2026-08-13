use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

fn main() {
    if env::var_os("CARGO_FEATURE_BPF").is_none() {
        return;
    }

    println!("cargo:rerun-if-changed=src/bpf/runtime.bpf.c");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    let object = out_dir.join("sentinel.o");
    let skeleton = out_dir.join("sentinel.skel.rs");

    SkeletonBuilder::new()
        .source("src/bpf/runtime.bpf.c")
        .obj(&object)
        .clang_args(["-Isrc/bpf"])
        .build_and_generate(&skeleton)
        .expect("failed to build eBPF skeleton");
}
