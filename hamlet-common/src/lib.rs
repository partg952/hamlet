#![no_std]

/// Key used to bucket a captured stack trace sample in the `HIST` map.
///
/// Shared between `hamlet-ebpf` (which writes it) and `hamlet` (which reads
/// it), so it must have a stable, C-compatible layout.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StackKey {
    pub pid: u64,
    pub kspace_id: i64,
    pub uspace_id: i64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for StackKey {}
