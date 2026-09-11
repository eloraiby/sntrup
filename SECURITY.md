# Security and conformance notes

This document records the security boundary of this implementation. It is not
a substitute for an independent cryptographic audit, deployment-specific risk
assessment, or platform side-channel testing.

## Specification and interoperability

The KEM core targets the six Streamlined NTRU Prime parameter sets in the
[NTRU Prime Round 3 submission](https://ntruprime.cr.yp.to/nist/ntruprime-20201007.pdf).
There is no standalone Internet Standards Track RFC defining all six KEMs.
[RFC 9941](https://www.rfc-editor.org/rfc/rfc9941.html) is an Informational RFC
for the hybrid `sntrup761x25519-sha512` SSH key exchange and normatively refers
to the Round 3 submission for sntrup761.

The repository checks conformance at three levels:

- `tests/reference_vectors.rs` pins complete key-generation and encapsulation
  transcripts for all six parameter sets. The expected outputs were produced
  by `libntruprime` 20260717 using the exact ChaCha20 byte streams documented in
  that test; the full outputs matched before their concatenation was reduced to
  compact SHA-512 fixtures.
- `tests/kat.rs` checks two historical sntrup761 algorithm vectors from
  `draft-josefsson-ntruprime-streamlined-00`.
- Unit tests compare specialized SIMD multiplication, inversion, codec, and
  reduction paths with portable or narrower-vector implementations. CI runs
  native x86 and AArch64/NEON tests, forced-scalar tests, AVX-512 functional
  tests under capability-asserting emulation, and sanitizers on both native
  architectures.

`generate_key_deterministic` is an extension provided by this crate. It expands
a 32-byte seed with `ChaCha20Rng`; it is not the NIST KAT deterministic random
bit generator and its seed cannot be substituted for a NIST `.rsp` seed.

## Input validation and rejection behavior

`EncapsulationKey::try_from` rejects non-canonical variable-radix public-key
encodings. `DecapsulationKey::try_from` additionally checks both packed ternary
fields and verifies that the embedded `Hash4(pk)` agrees with the embedded,
canonical public key. This structural validation does not prove that all
private-key fields were generated together.

`Ciphertext::try_from` intentionally checks only length. Arbitrary fixed-size
ciphertext contents must enter decapsulation, which always returns a 32-byte
key and uses implicit rejection. Adding a content-validation error at that
boundary would expose a rejection oracle and would not match the KEM contract.

Lengths and key-import validity are public API results and are checked before
cryptographic operations. Do not treat either parser as a constant-time secret
validation service.

## Timing and microarchitectural limitations

Encapsulation and decapsulation use fixed public loop bounds, branchless secret
selection, fixed-schedule sorting, and constant-time equality for private keys
and shared secrets. Those source-level properties do not establish constant
time on every target. In particular:

- key generation retries until a random ternary polynomial is invertible, so
  its running time reveals the number of rejected random candidates;
- key import may return early based on malformed private-key structure and is
  not intended to hide whether imported bytes are valid;
- integer multiplication instructions can have data-dependent latency on some
  processors, and compiler transformations are outside this crate's control;
- the first x86 operation includes public CPU-feature detection and cache
  initialization, which changes first-call timing; and
- CI verifies functional agreement and memory safety, but does not claim to be
  an empirical leakage test. A production target should be measured on its
  actual compiler, CPU, operating system, and calling context with a tool such
  as dudect or an equivalent methodology.

Do not convert decapsulation success into a branch or protocol error. The API
does not expose success: valid and invalid ciphertexts both produce a shared
key, and the surrounding authenticated protocol must determine whether that key
is accepted.

## Secret erasure limitations

Private-key and shared-secret wrappers implement zeroization on drop. Internal
secret-derived arrays, vectors, polynomial products, hash state, and rejected
key-generation candidates are held in drop guards and erased before release.
Those guards also run during Rust panic unwinding, including when a caller-
supplied random generator panics after partially filling a destination. Owned
private-key imports move their accepted allocation instead of cloning it, and
malformed owned inputs remain guarded throughout validation.

Calling `Zeroize::zeroize` explicitly preserves each secret wrapper's encoded
length. A zeroized shared secret contains 32 zero bytes. A zeroized private key
is no longer cryptographically valid and should only be dropped or replaced;
the stable length prevents accidental post-erasure method calls from violating
the wrapper's memory-safety invariants.

No in-process cleanup mechanism runs after `panic = "abort"`, forced process
termination, power loss, or operating-system failure. Deployments that require
post-crash secrecy must combine zeroization with disabled core dumps, locked or
encrypted memory where appropriate, and process-level containment.

Zeroization cannot erase copies outside the wrapper. This includes bytes made
through `AsRef`, serialized output, protocol buffers, exported `kem` trait
arrays, allocator or operating-system copies, swap, core dumps, and register
spills. `hybrid-array` zeroization support is enabled so callers can explicitly
erase exported fixed arrays. Avoid unnecessary `Clone` calls for secret types.

`generate_key_deterministic` has one additional limitation: `rand_chacha` does
not expose zeroization for its internal state, so the seed-expanded RNG state is
dropped without an explicit wipe. Prefer `generate_key` with a short-lived,
well-managed cryptographic RNG when deterministic derivation is not required.

## Production checklist

- Use a cryptographically secure, correctly seeded `CryptoRng`.
- Prefer sntrup761 or a larger parameter set; select the set based on the
  Round 3 security claims and the surrounding protocol's requirements.
- Authenticate the protocol transcript and preserve implicit rejection.
- Pin the crate, compiler, target features, and dependency lockfile.
- Run the supplied reference, scalar/SIMD, sanitizer, and RustSec checks in the
  deployment toolchain.
- Apply memory-locking, crash-dump, logging, and secret-lifetime controls at the
  application and operating-system layers.
- Obtain independent review and target-specific side-channel measurements for
  high-assurance deployments.
