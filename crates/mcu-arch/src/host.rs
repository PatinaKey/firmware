//! Stubs for every target other than `none`.
//!
//! The PRIMASK functions have no stub. A hosted OS exposes no interrupt mask.
//! A stub would have to invent an answer.

use core::sync::atomic::compiler_fence;
use core::sync::atomic::Ordering;

/// Does nothing. A host `loop { wfi() }` would spin.
#[inline]
pub(crate) fn wfi()
{
}

/// Emits the compiler fence half of a data synchronisation barrier.
#[inline]
pub(crate) fn dsb()
{
    compiler_fence(Ordering::SeqCst);
}

/// Emits the compiler fence half of an instruction synchronisation barrier.
#[inline]
pub(crate) fn isb()
{
    compiler_fence(Ordering::SeqCst);
}

/// Does nothing. A host build has no core-clock cycle to count.
#[inline]
pub(crate) fn delay(_cycles: u32)
{
}
