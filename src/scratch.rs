//! Safe, initialized and unwind-erased stack scratch for arithmetic kernels.
//!
//! Large fixed-size arrays keep the codec and KEM hot paths allocation-free.
//! Every scratch array starts at the additive identity so it is valid Rust from
//! the moment it is borrowed. Producers are still expected to overwrite their
//! active range, while zero initialization makes padding deterministic and
//! avoids exposing uninitialized storage through a reference. A drop guard
//! erases the complete allocation on both ordinary return and panic unwinding.

/// Declares a guarded, initialized stack array and exposes a mutable reference.
///
/// Keeping the reference-shaped binding preserves concise call sites: it
/// coerces to a mutable slice for arithmetic helpers. The shadowed drop guard
/// retains ownership of the backing array and erases it when the surrounding
/// scope ends, including when a downstream operation unwinds.
macro_rules! scratch_array {
    ($name:ident: [$element:ty; $length:expr]) => {
        let $name: [$element; $length] = [0; $length];
        let mut $name = $crate::wipe::SecretBuffer::new($name);
        let $name = &mut *$name;
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
