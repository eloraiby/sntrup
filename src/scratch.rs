//! Safe, initialized stack scratch buffers for the arithmetic kernels.
//!
//! Large fixed-size arrays keep the codec and KEM hot paths allocation-free.
//! Every scratch array starts at the additive identity so it is valid Rust from
//! the moment it is borrowed. Producers are still expected to overwrite their
//! active range, while zero initialization makes padding deterministic and
//! avoids exposing uninitialized storage through a reference.

/// Declares an initialized stack array and exposes it as a mutable array
/// reference.
///
/// Keeping the reference-shaped binding preserves concise call sites: it
/// coerces to a mutable slice for arithmetic helpers and can be passed directly
/// to the crate's wiping routine. The backing array remains owned by the
/// surrounding stack frame.
macro_rules! scratch_array {
    ($name:ident: [$element:ty; $length:expr]) => {
        let mut $name: [$element; $length] = [0; $length];
        let $name = &mut $name;
    };
}

pub(crate) use scratch_array;

#[cfg(test)]
mod tests {
    /// Scratch storage must be initialized before any safe reference exposes
    /// it, and callers must retain ordinary mutable-array behavior.
    #[test]
    fn scratch_arrays_start_zeroed_and_remain_writable() {
        scratch_array!(buf: [i16; 64]);
        assert!(buf.iter().all(|&value| value == 0));

        buf.fill(7);
        assert!(buf.iter().all(|&value| value == 7));
    }
}
