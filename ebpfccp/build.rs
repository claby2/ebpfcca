use libbpf_cargo::SkeletonBuilder;
use std::{env, ffi::OsStr, path::PathBuf};

const BPF_SRC: &str = "src/bpf/datapath.bpf.c";

fn build_bpf() {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("datapath.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(BPF_SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
        ])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={}", BPF_SRC);
}

fn build_libccp() {
    let libccp_dir = PathBuf::from("libccp");

    let mut build = cc::Build::new();

    build.include(&libccp_dir);
    build.flag("-std=gnu99");

    let c_files = ["ccp.c", "machine.c", "serialize.c", "ccp_priv.c"];
    for file in c_files.iter() {
        build.file(libccp_dir.join(file));
    }

    build.compile("libccp");

    let bindings = bindgen::Builder::default()
        .header(libccp_dir.join("ccp.h").to_str().unwrap())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("libccp.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rustc-link-lib=static=libccp");
    println!("cargo:rustc-link-search=native={}", out_path.display());
}

fn main() {
    build_bpf();

    build_libccp();
}
