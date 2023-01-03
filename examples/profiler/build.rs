use std::env;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/profiler.bpf.c";

fn main() {
    let output = Command::new("bpftool")
        .arg("btf")
        .arg("dump")
        .arg("file")
        .arg("/sys/kernel/btf/vmlinux")
        .arg("format")
        .arg("c")
        .output()
        .unwrap();
    let mut f = std::fs::File::create("./src/bpf/vmlinux.h").unwrap();
    f.write_all(&output.stdout).unwrap();

    let mut skel =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    skel.push("profiler.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&skel)
        .unwrap();
    println!("cargo:rerun-if-changed={}", SRC);
}
