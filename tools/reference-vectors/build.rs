//! Links the reproduction utility to an explicitly selected libntruprime build.

use std::{env, path::PathBuf};

/// Validates the caller-selected archive and exposes it to the Rust linker.
fn main() {
    // Never search a system-default directory: the caller must identify the
    // exact checksum-verified build described in this utility's README.
    let library_directory = env::var_os("LIBNTRUPRIME_LIB_DIR").unwrap_or_else(|| {
        panic!("LIBNTRUPRIME_LIB_DIR must name the directory containing libntruprime.a")
    });
    let library_directory = PathBuf::from(library_directory);
    let archive = library_directory.join("libntruprime.a");
    assert!(
        archive.is_file(),
        "LIBNTRUPRIME_LIB_DIR does not contain libntruprime.a: {}",
        library_directory.display()
    );

    // Re-run only when the selected archive or its explicit location changes.
    println!("cargo:rerun-if-env-changed=LIBNTRUPRIME_LIB_DIR");
    println!("cargo:rerun-if-changed={}", archive.display());
    println!(
        "cargo:rustc-link-search=native={}",
        library_directory.display()
    );
    println!("cargo:rustc-link-lib=static=ntruprime");
}
