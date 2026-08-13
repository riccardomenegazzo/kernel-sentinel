use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

fn main() {
    if env::var_os("CARGO_FEATURE_BPF").is_none() {
        return;
    }

    println!("cargo:rerun-if-changed=src/bpf/process.bpf.c");

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join("process.skel.rs");

    SkeletonBuilder::new()
        .source("src/bpf/process.bpf.c")
        .clang_args(["-Isrc/bpf"])
        .build_and_generate(&out)
        .expect("failed to build eBPF skeleton");
}
