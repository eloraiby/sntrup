# Independent reference-vector reproduction

This utility reproduces `tests/reference_vectors.rs` against the upstream
libntruprime 20260717 C implementation. It provides byte-identical ChaCha20
streams to C and Rust, asserts that every public key, private key, ciphertext,
and shared key matches, and compares valid plus five invalid decapsulations.
The printed fingerprints make the compact checked-in fixtures independently
repeatable without checking generated secret-key files into the repository.

## Obtain the pinned reference

Download the release directly from the author's HTTPS archive and verify it
before extracting:

```sh
curl -LO https://libntruprime.cr.yp.to/libntruprime-20260717.tar.gz
printf '%s  %s\n' \
  '768350cd57a9395d80545d2091ed27cd7ccf93c09b41671e4e50e053bcb0bff1' \
  'libntruprime-20260717.tar.gz' | sha256sum --check
tar -xzf libntruprime-20260717.tar.gz
cd libntruprime-20260717
./configure
make -j8
```

libntruprime documents Python 3 and a C compiler as build prerequisites. It
also recommends Capstone and requires its full upstream tests for supported
compiled deployments; consult `doc/install.md` and `doc/test.md` in the pinned
archive before treating that C build as production-ready.

## Reproduce and compare

From this repository's root, point the build script at the archive directory
containing `libntruprime.a`. `build/0` is libntruprime's symlink to the selected
host build, so this command does not bake an architecture name into the recipe:

```sh
LIBNTRUPRIME_LIB_DIR=/path/to/libntruprime-20260717/build/0/package/lib \
  cargo run --release --locked \
  --manifest-path tools/reference-vectors/Cargo.toml \
  | diff -u tools/reference-vectors/expected.txt -
```

Success is silent after Cargo's build messages. The utility aborts before
printing a completed transcript if any C and Rust artifact differs. The
checked-in lockfile pins the Rust-side generator and hashing dependencies.

The deterministic streams are `[id; 32]` for key generation and
`[id ^ 0x80; 32]` for encapsulation, where the six IDs are `0x11`, `0x22`,
`0x33`, `0x44`, `0x55`, and `0x66` in ascending parameter-set order. These are
raw test streams, not this crate's domain-separated
`generate_key_deterministic` API and not a NIST `.rsp` DRBG seed.
