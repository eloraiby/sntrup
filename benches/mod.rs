//! Criterion benchmarks for every standardized parameter set and KEM operation.

#![allow(missing_docs)]

use criterion::{Criterion, criterion_group, criterion_main};
use sntrup::*;

/// Invokes a benchmark-case macro once for every public parameter-set alias.
///
/// Keeping the list in one place prevents the operation groups from silently
/// drifting apart when a parameter set is added or removed.
macro_rules! for_each_parameter_set {
    ($case:ident, $group:ident) => {
        $case!($group, "sntrup653", Sntrup653);
        $case!($group, "sntrup761", Sntrup761);
        $case!($group, "sntrup857", Sntrup857);
        $case!($group, "sntrup953", Sntrup953);
        $case!($group, "sntrup1013", Sntrup1013);
        $case!($group, "sntrup1277", Sntrup1277);
    };
}

/// Adds one parameter set's key-generation measurement to a Criterion group.
macro_rules! bench_keygen_case {
    ($group:ident, $label:literal, $kem:ty) => {
        $group.bench_function($label, |b| {
            // Reuse the operating-system RNG handle; constructing it is not
            // part of the cryptographic operation being measured.
            let mut rng = rand::rng();
            b.iter(|| <$kem>::generate_key(&mut rng));
        });
    };
}

/// Adds one parameter set's encapsulation measurement to a Criterion group.
macro_rules! bench_encapsulate_case {
    ($group:ident, $label:literal, $kem:ty) => {
        $group.bench_function($label, |b| {
            let mut rng = rand::rng();
            // Generate the reusable public key outside the timed operation.
            let (ek, _dk) = <$kem>::generate_key(&mut rng);
            b.iter(|| ek.encapsulate(&mut rng));
        });
    };
}

/// Adds one parameter set's decapsulation measurement to a Criterion group.
macro_rules! bench_decapsulate_case {
    ($group:ident, $label:literal, $kem:ty) => {
        $group.bench_function($label, |b| {
            let mut rng = rand::rng();
            // Prepare one valid ciphertext outside the timed operation so the
            // measurement isolates decapsulation from setup and encapsulation.
            let (ek, dk) = <$kem>::generate_key(&mut rng);
            let (ct, _ss) = ek.encapsulate(&mut rng);
            b.iter(|| dk.decapsulate(&ct));
        });
    };
}

/// Benchmarks key generation for every supported parameter set.
fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");
    for_each_parameter_set!(bench_keygen_case, group);
    group.finish();
}

/// Benchmarks encapsulation for every supported parameter set.
fn bench_encapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("encapsulate");
    for_each_parameter_set!(bench_encapsulate_case, group);
    group.finish();
}

/// Benchmarks decapsulation for every supported parameter set.
fn bench_decapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("decapsulate");
    for_each_parameter_set!(bench_decapsulate_case, group);
    group.finish();
}

criterion_group!(benches, bench_keygen, bench_encapsulate, bench_decapsulate);
criterion_main!(benches);
