use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("sentinel.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/sentinel.bpf.c")
        .clang_args(["-Isrc/bpf"])
        .build_and_generate(&out)
        .unwrap();
}
