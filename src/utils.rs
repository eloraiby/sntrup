use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::params::SntrupParameters;
use crate::scratch::scratch_array;
use crate::wipe::SecretBuffer;
use crate::{r3, rq, zx};

/// Hash prefix helper: SHA-512(prefix || input), truncated to 32 bytes.
pub(crate) fn hash_prefix(out: &mut [u8; 32], prefix: u8, input: &[u8]) {
    let mut hasher = Sha512::new();
    hasher.update([prefix]);
    hasher.update(input);
    let mut digest = hasher.finalize();
    out.copy_from_slice(&digest[..32]);
    // No fallible operation follows the fixed-size copy; erase the discarded,
    // possibly secret-derived upper half before returning.
    digest.zeroize();
}

/// hash_confirm: Hash(2 || Hash(3 || r_enc) || cache)
/// where cache = Hash4(pk) stored in the secret key.
pub(crate) fn hash_confirm(out: &mut [u8; 32], r_enc: &[u8], cache: &[u8; 32]) {
    let mut inner = SecretBuffer::new([0u8; 32]);
    hash_prefix(&mut inner, 3, r_enc);

    let mut hasher = Sha512::new();
    hasher.update([2u8]);
    hasher.update(&inner[..]);
    hasher.update(&cache[..]);
    let mut digest = hasher.finalize();
    out.copy_from_slice(&digest[..32]);
    // `inner` is guarded; no fallible operation separates this copy and wipe.
    digest.zeroize();
}

/// hash_session: Hash(b || Hash(3 || y) || z)
pub(crate) fn hash_session(out: &mut [u8; 32], b: u8, y: &[u8], z: &[u8]) {
    let mut inner = SecretBuffer::new([0u8; 32]);
    hash_prefix(&mut inner, 3, y);

    let mut hasher = Sha512::new();
    hasher.update([b]);
    hasher.update(&inner[..]);
    hasher.update(z);
    let mut digest = hasher.finalize();
    out.copy_from_slice(&digest[..32]);
    // `inner` is guarded; no fallible operation separates this copy and wipe.
    digest.zeroize();
}

/// Constant-time: returns 0 if x == 0, -1 (0xFFFFFFFF) otherwise.
#[allow(clippy::cast_sign_loss)]
fn int16_nonzero_mask(x: i16) -> i32 {
    let u = x as u16;
    let mut r = u.wrapping_neg() | u;
    r >>= 15;
    -(r as i32)
}

/// Constant-time check if weight of `r` equals `w`.
/// Returns 0 if weight == w, -1 otherwise.
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
pub(crate) fn weightw_mask(r: &[i8], w: usize) -> i32 {
    debug_assert!(
        r.len() <= crate::params::MAX_P,
        "KEM polynomial exceeds the largest supported parameter set"
    );
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2()
        unsafe {
            return weightw_mask_avx2(r, w);
        }
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return weightw_mask_neon(r, w);
    }
    #[allow(unreachable_code)]
    weightw_mask_scalar(r, w)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn weightw_mask_scalar(r: &[i8], w: usize) -> i32 {
    let mut weight: i32 = 0;
    for &val in r.iter() {
        weight += (val & 1) as i32;
    }
    int16_nonzero_mask((weight - w as i32) as i16)
}

/// Count non-zero elements 32 at a time using AVX2.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx2")]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
unsafe fn weightw_mask_avx2(r: &[i8], w: usize) -> i32 {
    unsafe {
        use core::arch::x86_64::*;
        let p = r.len();
        let ones = _mm256_set1_epi8(1);
        let mut acc = _mm256_setzero_si256();
        let mut i = 0usize;
        while i + 32 <= p {
            let v = _mm256_loadu_si256(r.as_ptr().add(i) as *const __m256i);
            let masked = _mm256_and_si256(v, ones);
            acc = _mm256_add_epi8(acc, masked);
            i += 32;
        }
        // Horizontal sum: sad against zero gives sum of abs values in each 8-byte lane
        let sad = _mm256_sad_epu8(acc, _mm256_setzero_si256());
        // sad has 4 u64 lanes with partial sums
        let lo = _mm256_castsi256_si128(sad);
        let hi = _mm256_extracti128_si256(sad, 1);
        let sum128 = _mm_add_epi64(lo, hi);
        let sum_hi = _mm_srli_si128(sum128, 8);
        let total = _mm_add_epi64(sum128, sum_hi);
        let mut weight = _mm_cvtsi128_si64(total) as i32;
        // Handle remainder
        while i < p {
            weight += (r[i] & 1) as i32;
            i += 1;
        }
        int16_nonzero_mask((weight - w as i32) as i16)
    }
}

/// Count non-zero elements 16 at a time using NEON.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
unsafe fn weightw_mask_neon(r: &[i8], w: usize) -> i32 {
    unsafe {
        use core::arch::aarch64::*;
        let p = r.len();
        let ones = vdupq_n_s8(1);
        let mut acc = vdupq_n_u8(0);
        let mut i = 0usize;
        while i + 16 <= p {
            let v = vld1q_s8(r.as_ptr().add(i));
            let masked = vreinterpretq_u8_s8(vandq_s8(v, ones));
            acc = vaddq_u8(acc, masked);
            i += 16;
        }
        // Progressive horizontal sum: u8 -> u16 -> u32 -> u64
        let sum16 = vpaddlq_u8(acc);
        let sum32 = vpaddlq_u16(sum16);
        let sum64 = vpaddlq_u32(sum32);
        let mut weight = (vgetq_lane_u64(sum64, 0) + vgetq_lane_u64(sum64, 1)) as i32;
        // Handle remainder
        while i < p {
            weight += (r[i] & 1) as i32;
            i += 1;
        }
        int16_nonzero_mask((weight - w as i32) as i16)
    }
}

/// Constant-time comparison of two byte slices.
/// Returns 0 if equal, -1 otherwise.
#[allow(unsafe_code, clippy::cast_possible_wrap)]
fn ciphertexts_diff_mask(a: &[u8], b: &[u8]) -> i32 {
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2()
        unsafe {
            return ciphertexts_diff_mask_avx2(a, b);
        }
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return ciphertexts_diff_mask_neon(a, b);
    }
    #[allow(unreachable_code)]
    ciphertexts_diff_mask_scalar(a, b)
}

/// Collapses unequal public slice lengths to one without a data-dependent branch.
///
/// Ciphertext wrapper lengths are fixed before this internal comparison, but
/// including length in the primitive's result prevents future callers from
/// accidentally treating equal prefixes as equal complete ciphertexts.
#[allow(clippy::cast_possible_truncation)]
fn lengths_diff_bit(a: &[u8], b: &[u8]) -> u16 {
    let difference = a.len() ^ b.len();
    ((difference | difference.wrapping_neg()) >> (usize::BITS - 1)) as u16
}

#[allow(clippy::cast_possible_wrap)]
fn ciphertexts_diff_mask_scalar(a: &[u8], b: &[u8]) -> i32 {
    let mut diff = lengths_diff_bit(a, b);
    let len = a.len().min(b.len());
    for i in 0..len {
        diff |= (a[i] ^ b[i]) as u16;
    }
    int16_nonzero_mask(diff as i16)
}

/// XOR-accumulate 32 bytes at a time, then horizontal OR.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx2")]
#[allow(unsafe_code, clippy::cast_possible_wrap, clippy::cast_sign_loss)]
unsafe fn ciphertexts_diff_mask_avx2(a: &[u8], b: &[u8]) -> i32 {
    unsafe {
        use core::arch::x86_64::*;
        let len = a.len().min(b.len());
        let mut acc = _mm256_setzero_si256();
        let mut i = 0usize;
        while i + 32 <= len {
            let av = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
            let bv = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
            acc = _mm256_or_si256(acc, _mm256_xor_si256(av, bv));
            i += 32;
        }
        // Horizontal OR reduction.
        // movemask bit i is 1 iff byte i of acc == 0; mask == 0xFFFFFFFF iff equal.
        // Collapse to 0/1 branchlessly — a source-level branch here would leak,
        // via the branch predictor, whether the ciphertexts matched (the secret
        // the implicit-rejection comparison must hide).
        let inv = !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(acc, _mm256_setzero_si256())) as u32);
        let mut diff: u16 = ((inv | inv.wrapping_neg()) >> 31) as u16;
        diff |= lengths_diff_bit(a, b);
        // Handle remainder
        while i < len {
            diff |= (a[i] ^ b[i]) as u16;
            i += 1;
        }
        int16_nonzero_mask(diff as i16)
    }
}

/// XOR-accumulate 16 bytes at a time, then horizontal OR.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[allow(unsafe_code, clippy::cast_possible_wrap, clippy::cast_sign_loss)]
unsafe fn ciphertexts_diff_mask_neon(a: &[u8], b: &[u8]) -> i32 {
    unsafe {
        use core::arch::aarch64::*;
        let len = a.len().min(b.len());
        let mut acc = vdupq_n_u8(0);
        let mut i = 0usize;
        while i + 16 <= len {
            let av = vld1q_u8(a.as_ptr().add(i));
            let bv = vld1q_u8(b.as_ptr().add(i));
            acc = vorrq_u8(acc, veorq_u8(av, bv));
            i += 16;
        }
        // Horizontal max: any-nonzero check
        let mut diff: u16 = vmaxvq_u8(acc) as u16;
        diff |= lengths_diff_bit(a, b);
        // Handle remainder
        while i < len {
            diff |= (a[i] ^ b[i]) as u16;
            i += 1;
        }
        int16_nonzero_mask(diff as i16)
    }
}

/// Derive a keypair from secret polynomials.
///
/// Returns `(pk_bytes, sk_bytes)` as `Vec<u8>`.
///
/// SK layout: `f_enc || ginv_enc || pk || rho || Hash4(pk)`
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
pub(crate) fn derive_key(
    f: &[i8],
    g: &[i8],
    gr: &[i8],
    rho: &[u8],
    params: &SntrupParameters,
) -> (Vec<u8>, Vec<u8>) {
    let p = params.p;

    let f3r = SecretBuffer::new(rq::reciprocal3(f, params));
    let mut h = SecretBuffer::new(vec![0i16; p]);
    rq::mult(&mut h, &f3r, g, params);
    let pk = rq::encoding::rq_encode(&h, params);

    // SK layout: f_enc || ginv_enc || pk || rho || Hash4(pk)
    let mut sk = SecretBuffer::new(vec![0u8; params.sk_size]);
    let f_enc = SecretBuffer::new(zx::encoding::encode(f, p, params.small_encode_size));
    let ginv_enc = SecretBuffer::new(zx::encoding::encode(gr, p, params.small_encode_size));

    let ses = params.small_encode_size;
    sk[..ses].copy_from_slice(&f_enc);
    sk[ses..(2 * ses)].copy_from_slice(&ginv_enc);
    sk[(2 * ses)..(2 * ses + params.pk_size)].copy_from_slice(&pk);
    sk[(2 * ses + params.pk_size)..(2 * ses + params.pk_size + ses)].copy_from_slice(rho);

    // Hash4(pk) = Hash(4 || pk) truncated to 32 bytes
    let mut cache = SecretBuffer::new([0u8; 32]);
    hash_prefix(&mut cache, 4, &pk);
    sk[(2 * ses + params.pk_size + ses)..].copy_from_slice(&cache[..]);

    // Drop guards erase every private-key intermediate on ordinary return and
    // on unwinding from allocation, encoding, or arithmetic.
    (pk, sk.take())
}

/// Encrypt a small polynomial `r` under a public key.
///
/// Returns `(ciphertext_bytes, shared_secret)`.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
pub(crate) fn create_cipher(
    r: &[i8],
    h: &[i16],
    pk_hash: &[u8; 32],
    params: &SntrupParameters,
) -> (Vec<u8>, [u8; 32]) {
    let p = params.p;

    use crate::params::MAX_P;

    // Multiplication overwrites the active coefficient range; the remainder is
    // initialized padding owned by this frame.
    scratch_array!(c_buf: [i16; MAX_P]);
    let c = &mut c_buf[..p];
    rq::mult(c, h, r, params);

    const MAX_SES: usize = MAX_P.div_ceil(4) + 1;
    let ses = params.small_encode_size;
    // Encoding overwrites the complete active byte range.
    scratch_array!(r_enc_buf: [u8; MAX_SES]);
    let r_enc = &mut r_enc_buf[..ses];
    zx::encoding::encode_into(r, r_enc, p, ses);

    // Compute confirm hash: Hash(2 || Hash(3 || r_enc) || Hash4(pk)); Hash4(pk) is
    // the caller-cached `pk_hash`.
    let mut confirm = SecretBuffer::new([0u8; 32]);
    hash_confirm(&mut confirm, r_enc, pk_hash);

    // Ciphertext layout: rounded(rounded_encode_size) || confirm_hash(32)
    let mut cstr = vec![0u8; params.ct_size];
    rq::encoding::round_and_encode_into(c, &mut cstr[..params.rounded_encode_size], params);
    cstr[params.rounded_encode_size..].copy_from_slice(&confirm[..]);

    // Shared key: hash_session(1, r_enc, cstr)
    let mut k = SecretBuffer::new([0u8; 32]);
    hash_session(&mut k, 1, r_enc, &cstr);

    // The scratch and confirmation guards erase whole frames (including
    // padding) on return or unwind. `pk_hash` is public and caller-owned.
    (cstr, k.take())
}

/// Decapsulate a ciphertext with a secret key.
///
/// Implements implicit rejection (IND-CCA2): on failure, returns a pseudorandom
/// key derived from `rho`, indistinguishable from a valid key.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
pub(crate) fn decapsulate_inner(
    cstr: &[u8],
    sk: &[u8],
    h: &[i16],
    params: &SntrupParameters,
) -> [u8; 32] {
    let p = params.p;
    let w = params.w;
    let ses = params.small_encode_size;

    use crate::params::MAX_P;

    // Parse SK: f(ses) || ginv(ses) || pk(pk_size) || rho(ses) || cache(32)
    // All working buffers live on this frame, bounded by MAX_P — decapsulation
    // performs no heap allocation.
    // Decode the private polynomial into the initialized active range.
    scratch_array!(f_buf: [i8; MAX_P]);
    let f = &mut f_buf[..p];
    zx::encoding::decode_into(&sk[..ses], f, p);
    // Decode the inverse polynomial into its independent working buffer.
    scratch_array!(ginv_buf: [i8; MAX_P]);
    let ginv = &mut ginv_buf[..p];
    zx::encoding::decode_into(&sk[ses..(2 * ses)], ginv, p);
    let pk_start = 2 * ses;
    let pk_end = pk_start + params.pk_size;
    let rho_start = pk_end;
    let rho_end = rho_start + ses;
    let cache_start = rho_end;

    let mut cache = SecretBuffer::new([0u8; 32]);
    cache.copy_from_slice(&sk[cache_start..cache_start + 32]);

    // Decrypt: Rounded_decode, multiply by f, Rq_mult3, R3_fromRq, R3_mult by ginv
    // Decode the public ciphertext prefix into coefficient form.
    scratch_array!(c_buf: [i16; MAX_P]);
    let c = &mut c_buf[..p];
    rq::encoding::rounded_decode_into(&cstr[..params.rounded_encode_size], c, params);
    // Multiply into a distinct buffer so ciphertext and key inputs never alias.
    scratch_array!(cf_buf: [i16; MAX_P]);
    let cf = &mut cf_buf[..p];
    rq::mult(cf, c, f, params);
    // Scale and reduce every active coefficient into the ternary ring.
    scratch_array!(t3_buf: [i8; MAX_P]);
    let t3 = &mut t3_buf[..p];
    rq::scale3_freeze3(t3, cf, params);
    // Recover the candidate input polynomial in a separate working buffer.
    scratch_array!(r_buf: [i8; MAX_P]);
    let r = &mut r_buf[..p];
    r3::mult(r, t3, ginv, p);

    // Weight mask: on failure, set r to default weight-W vector
    // (W ones followed by P-W zeros), matching PQClean's Decrypt
    let w_mask = weightw_mask(r, w);
    let not_mask = (!w_mask) as i8;
    for val in r[..w].iter_mut() {
        *val = ((*val ^ 1) & not_mask) ^ 1;
    }
    for val in r[w..p].iter_mut() {
        *val &= not_mask;
    }

    // Hide: encode r, re-encrypt with pk, compute confirm hash
    const MAX_SES: usize = MAX_P.div_ceil(4) + 1;
    // Encode the complete candidate input used by confirmation and selection.
    scratch_array!(r_enc_buf: [u8; MAX_SES]);
    let r_enc = &mut r_enc_buf[..ses];
    zx::encoding::encode_into(r, r_enc, p, ses);
    // Re-encrypt the candidate into initialized coefficient storage.
    scratch_array!(hr_buf: [i16; MAX_P]);
    let hr = &mut hr_buf[..p];
    rq::mult(hr, h, r, params);

    // `ct_size` already includes the 32-byte confirmation hash and is bounded
    // by the largest complete ciphertext.
    use crate::params::MAX_CT;
    // SAFETY: `round_and_encode_into` fills the rounded prefix and the confirm
    // hash is copied over the remainder, together covering all of `..ct_size`.
    scratch_array!(cnew_buf: [u8; MAX_CT]);
    let cnew = &mut cnew_buf[..params.ct_size];
    rq::encoding::round_and_encode_into(hr, &mut cnew[..params.rounded_encode_size], params);
    let mut confirm = SecretBuffer::new([0u8; 32]);
    hash_confirm(&mut confirm, r_enc, &cache);
    cnew[params.rounded_encode_size..].copy_from_slice(&confirm[..]);

    // Compare full ciphertexts (rounded + confirm hash)
    let mask = ciphertexts_diff_mask(cstr, cnew);

    // Constant-time select: r_enc on success (mask=0), rho on failure (mask=-1)
    let rho = &sk[rho_start..rho_end];
    // Begin with the valid-ciphertext candidate; the constant-time loop below
    // replaces it with rho under the rejection mask.
    scratch_array!(selected_buf: [u8; MAX_SES]);
    let selected = &mut selected_buf[..ses];
    selected.copy_from_slice(r_enc);
    let mask_byte = mask as u8;
    for i in 0..ses {
        selected[i] ^= mask_byte & (selected[i] ^ rho[i]);
    }

    // Hash session: prefix=1 on success (mask=0), prefix=0 on failure (mask=-1)
    let prefix = (1 + mask) as u8;
    let mut k = SecretBuffer::new([0u8; 32]);
    hash_session(&mut k, prefix, selected, cstr);

    // Every scratch binding and fixed secret copy is guarded, so the entire
    // decapsulation frame is erased on both ordinary return and unwinding.
    k.take()
}

#[cfg(test)]
mod tests {
    use super::{
        ciphertexts_diff_mask, ciphertexts_diff_mask_scalar, weightw_mask, weightw_mask_scalar,
    };

    /// Every weight implementation must count exactly the provided slice,
    /// including tails that do not fill a SIMD register.
    #[test]
    fn weight_comparison_uses_slice_length() {
        for length in [0usize, 1, 15, 16, 31, 32, 33, 653, 761, 1277] {
            let polynomial: Vec<i8> = (0..length)
                .map(|index| if index % 3 == 0 { -1 } else { 0 })
                .collect();
            let weight = polynomial.iter().filter(|&&value| value != 0).count();

            assert_eq!(weightw_mask_scalar(&polynomial, weight), 0);
            assert_eq!(weightw_mask(&polynomial, weight), 0);
            assert_eq!(weightw_mask_scalar(&polynomial, weight + 1), -1);
            assert_eq!(weightw_mask(&polynomial, weight + 1), -1);
        }
    }

    /// Equal prefixes with different lengths must never compare as complete
    /// ciphertexts, on either the scalar oracle or the runtime dispatcher.
    #[test]
    fn ciphertext_comparison_includes_length() {
        let cases: &[(&[u8], &[u8], i32)] = &[
            (b"", b"", 0),
            (b"same", b"same", 0),
            (b"same", b"same-tail", -1),
            (b"same-tail", b"same", -1),
            (b"same", b"sand", -1),
        ];

        for &(left, right, expected) in cases {
            assert_eq!(ciphertexts_diff_mask_scalar(left, right), expected);
            assert_eq!(ciphertexts_diff_mask(left, right), expected);
        }
    }
}
