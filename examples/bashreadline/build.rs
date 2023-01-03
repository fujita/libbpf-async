use std::fs::create_dir_all;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/bashreadline.bpf.c";

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

    // It's unfortunate we cannot use `OUT_DIR` to store the generated skeleton.
    // Reasons are because the generated skeleton contains compiler attributes
    // that cannot be `include!()`ed via macro. And we cannot use the `#[path = "..."]`
    // trick either because you cannot yet `concat!(env!("OUT_DIR"), "/skel.rs")` inside
    // the path attribute either (see https://github.com/rust-lang/rust/pull/83366).
    //
    // However, there is hope! When the above feature stabilizes we can clean this
    // all up.
    create_dir_all("./src/bpf/.output").unwrap();
    let skel = Path::new("./src/bpf/.output/bashreadline.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&skel)
        .unwrap();
    println!("cargo:rerun-if-changed={}", SRC);
}
