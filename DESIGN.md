# Design Notes

This document tracks the major design decisions made in `hamlet`, and why
they were made. It's meant to be updated as the project evolves, alongside
code changes, not written once and left stale.

## Overview

`hamlet` is a CPU profiler built on eBPF. A `PerfEvent` program
(`hamlet-ebpf`) samples the CPU at 1Hz on every online CPU, capturing both
the kernel-space and user-space call stack for whatever is executing at that
instant. Samples are bucketed by `(pid, kernel stack id, user stack id)` into
a histogram map, which the userspace binary (`hamlet`) reads back, resolves
to symbol names, and prints.

## Workspace layout

- `hamlet-ebpf` — the eBPF program (`no_std`, compiled to BPF bytecode).
- `hamlet` — the userspace loader/reader binary (normal `std` Rust).
- `hamlet-common` — types shared between the two, notably `StackKey`.

**Why a separate `hamlet-common` crate:** the eBPF program and the userspace
program are different compilation targets (BPF bytecode vs. the host
architecture) and can't share a dependency graph directly. A `no_std` crate
with `#[cfg(feature = "user")]` gates (see below) is the standard `aya`
pattern for sharing map key/value struct definitions between the two sides
without duplicating the struct (and risking the two copies drifting out of
sync).

## Map design

### `STRACE_MAP` (`StackTrace`)

Stores raw stack traces (arrays of instruction pointers), keyed by an id the
kernel assigns via `bpf_get_stackid`. Both kernel-space and user-space
stacks are stored in the *same* map — `get_stackid` is called twice per
sample, once with `BPF_F_USER_STACK` and once without, giving two
independent ids into the same map.

### `HIST` (`HashMap<StackKey, u64>`)

Bucket key is `(pid, kspace_id, uspace_id)`, value is a hit count. Using the
stack *ids* rather than the raw stack contents as the key keeps the key size
small (three integers) and avoids duplicating large stack arrays as map
values — `STRACE_MAP` already stores those once per unique stack.

**Why `#[map]` was required on all three maps:** only annotating one map
(originally just `SAMPLE_COUNT`) with `#[map]` meant the other two were
plain Rust statics, never registered as real BPF maps with the loader. Every
map that needs to be visible to the eBPF loader (and thus readable from
userspace via `ebpf.map("NAME")`) needs the attribute.

### `StackKey` layout (`hamlet-common`)

```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StackKey {
    pub pid: u64,
    pub kspace_id: i64,
    pub uspace_id: i64,
}
```

**Why `#[repr(C)]`:** the eBPF side and the userspace side both need to
agree on the exact byte layout of this struct, since BPF maps treat keys as
raw bytes (`key_size` is derived from `size_of::<K>()`). The default Rust
representation (`repr(Rust)`) makes no layout guarantees — field order and
padding can change across compiler versions. `repr(C)` pins the layout down
so both sides read/write the same bytes consistently.

**Why `unsafe impl aya::Pod for StackKey`:** the userspace `aya::maps::HashMap<T, K, V>`
requires `K: Pod` and `V: Pod` — `Pod` (Plain Old Data) is `aya`'s marker
trait asserting a type is safe to treat as a raw byte blob when copying to/from
the kernel. This impl is gated behind `#[cfg(feature = "user")]` since `Pod`
comes from the `aya` crate, which is only a dependency of `hamlet-common`
when the `user` feature is enabled (it's not available/needed in the
`no_std` eBPF build).

## Stack id semantics

`bpf_get_stackid` returns a signed integer (`c_long`/`i64`) because, like
most BPF helpers and Unix syscalls, it overloads a single return value for
both success and failure: non-negative on success (the stack id), negative
on failure (a negated errno). There's no separate error channel available
to a BPF helper limited to one 64-bit return register.

Both `kspace_id` and `uspace_id` in `StackKey` are stored as `i64` rather
than `u32` (`StackTrace`'s actual key type) to preserve this signedness —
`try_hamlet` only ever inserts ids from *successful* `get_stackid` calls
(the `?` operator aborts the sample on failure before insertion), so in
practice stored ids are always non-negative, but the type keeps that
invariant visible rather than silently narrowing to `u32` at the point of
capture.

## Userspace symbol resolution

### Kernel-space frames

Resolved via `aya::util::kernel_symbols()`, which parses `/proc/kallsyms`
once into a `BTreeMap<u64, String>` (address -> symbol name). Lookup for a
given instruction pointer `ip` is:

```rust
ksyms.range(..=ip).next_back()
```

**Why this pattern, not a direct `.get(&ip)`:** `/proc/kallsyms` only
records where each function *starts*, not its length. A captured `ip` is
almost always a return address in the middle of some function, not the
first instruction, so an exact-key lookup would almost never hit. The
correct query is "the closest symbol start at or before this address" —
`range(..=ip).next_back()` finds exactly that in `O(log n)` thanks to
`BTreeMap`'s sorted-key structure (a `HashMap` couldn't answer this kind of
ordered/nearest-match query at all).

**Why load once, not per-frame:** the core kernel image's symbol addresses
are fixed for the life of a boot (KASLR randomizes the base once at boot,
not continuously). The only source of drift is kernel modules being
loaded/unloaded at runtime, which is an accepted limitation for now given
this profiler's short, fixed-duration collection window.

### User-space frames (planned)

Not yet implemented as of this writing (frames currently print as raw hex
addresses only). Plan, in order:

1. Parse `/proc/<pid>/maps` to find which file-backed mapping contains a
   given `ip`, giving a `(file path, mapping start, file_offset)` triple.
2. Convert `ip` to a file-relative offset:
   `offset = ip - mapping.start + mapping.file_offset`.
3. Resolve `offset` against that file's own symbol table using
   `addr2line::Loader::find_symbol`.

**Why this is fundamentally different from the kernel case:** there is no
single global symbol table for user space. An address only means something
relative to *which binary or shared library* was mapped at that address in
*that specific process* — the same virtual address can be a different
instruction in every process. Hence the extra indirection through
`/proc/<pid>/maps` before any symbol lookup can happen at all.

**Why `addr2line::Loader` over hand-rolled ELF parsing:** `Loader` wraps the
`object` crate (ELF/Mach-O/PE parsing) and `gimli` (DWARF parsing),
handling file mmap-ing, symbol table extraction, and optional debug-info
loading in one `Loader::new(path)` call. `Loader::find_symbol(offset)` does
the same "closest preceding symbol" lookup as the kernel case, just against
one file's symbol table instead of `/proc/kallsyms`. DWARF-based resolution
(`find_frames`, for inlined-function-aware attribution) is available from
the same crate but out of scope for now — `find_symbol` alone matches the
level of detail already used for kernel frames, and works even on binaries
built without debug info (DWARF), as long as they aren't fully stripped.

**Why per-file/per-pid caching is required:** both `Loader::new` (mmaps +
parses the whole symbol table, and DWARF if present) and reading/parsing
`/proc/<pid>/maps` are too expensive to redo per stack frame. The plan calls
for a `HashMap<PathBuf, Option<Loader>>` and a per-dump-pass
`HashMap<u32, Vec<Mapping>>` cache, built lazily on first use.

**Known limitation:** `/proc/<pid>/maps` only exists while the process is
alive. Given the collection window is a fixed, short duration, resolving
after the fact can race with process exit — this degrades to printing the
raw address rather than failing the whole dump.

## CLI: `--pid` filter

Added `clap` (`derive` feature) for argument parsing:

```rust
#[derive(clap::Parser)]
struct Args {
    #[arg(long)]
    pid: Option<u32>,
}
```

**Why filtering happens in userspace, not in the eBPF program:** the eBPF
program still samples and counts every process system-wide; `--pid` only
controls what's *displayed* after collection. This was a deliberate scope
choice to keep the first working version small — pushing the filter into
the eBPF program (e.g. via a config map so only matching pids get counted)
is a possible later optimization if per-sample overhead for irrelevant pids
becomes a concern, but wasn't needed to validate the feature.

## Known rough edges / deliberately deferred

- `strace_map.get(...)?` in the display loop aborts the entire dump if a
  single stack id lookup fails (e.g. evicted from the fixed-capacity
  `STRACE_MAP` by the time of display). Not yet hardened to skip and
  continue per-entry.
- `SAMPLE_COUNT` (an `Array<u64>` counter) is populated by the eBPF program
  but no longer read from userspace after the histogram-based display loop
  replaced the original simple counter print. Currently orphaned; kept in
  case a simple aggregate "total samples" figure is wanted again later.
- Collection duration is a hardcoded 10 one-second ticks, not configurable.
