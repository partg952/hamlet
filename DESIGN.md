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
```./

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

### User-space frames

Implemented as: parse `/proc/<pid>/maps` to find which file-backed mapping
contains a given `ip`, giving a `(file path, mapping start, file_offset)`
triple; convert `ip` to a file-relative offset:
`offset = ip - mapping.start + mapping.file_offset`; resolve `offset`
against that file's own symbol table using `addr2line::Loader::find_symbol`.

**Known bug — wrong for non-PIE executables (confirmed):** the offset
formula above is only correct when a binary's `PT_LOAD` segments have
`p_vaddr == p_offset`, which holds for *position-independent* executables
and shared libraries, but not for traditional non-PIE executables (e.g.
anything linked with `-no-pie`, which is `gcc`'s default on some
toolchains/targets). For those, symbol addresses in the ELF symbol table
are absolute virtual addresses matching `ip` directly — subtracting
`mapping.start` and adding `file_offset` produces a small, bogus number
that matches no symbol.

This was caught by testing against `burn2.c` (a non-PIE binary): every one
of `burn2`'s own frames (`run_primes`, `is_prime`, `fib`, `mix`, ...)
resolved to `None` and printed as raw hex, while libc frames (`qsort_r`,
`msort_with_tmp.part.0`, `__libc_start_main`) *did* resolve correctly,
because glibc on this system is a PIE shared object. This split — libc
symbols resolving, the profiled program's own symbols not — is the
diagnostic signature of this bug and is the first thing to check if a
flamegraph is missing its own hot path.

**Fix (not yet implemented):** read each mapping's underlying ELF headers
to get the real `PT_LOAD` segment's `p_vaddr`/`p_offset`, and compute
`ip - mapping.start + mapping.file_offset - p_offset + p_vaddr` instead of
assuming the two are equal. Equivalently: detect non-PIE (`ET_EXEC`, not
`ET_DYN`) binaries and pass `ip` to `addr2line` unmodified for those.

**Unverified — shared libraries other than glibc:** the same formula should
hold for *any* correctly mapped shared library (libm, libpthread, etc.)
since those are all PIE/`ET_DYN`, but this has only been spot-checked
against libc symbols so far; a raw-hex frame inside e.g. `libm.so` (seen in
one `burn2` run for a `sin`/`cos` call) has not been root-caused and may be
this same bug manifesting differently, or may be a `vdso`/`vsyscall`
mapping, which has no backing file on disk for `addr2line::Loader::new` to
open.

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

## Output: folded stacks

Output is in the "folded stack" format consumed by `flamegraph.pl`,
`inferno-flamegraph`, speedscope, etc.: one line per unique stack,
`root;frame;...;leaf <count>`.

**Why folding happens in userspace by symbol name:** `HIST` buckets by stack
*id*, and the kernel assigns a different id whenever the raw instruction
pointers differ (e.g. samples landing at different offsets inside the same
function). Those buckets resolve to identical names, so printing them
per-bucket showed the same logical stack several times. Resolving first and
summing counts into a `BTreeMap<String, u64>` merges them.

Stack order is `process comm;user frames (root to leaf);kernel frames (root
to leaf)`. The kernel stores frames leaf-first, so each is reversed. Status
messages go to stderr so stdout can be piped straight into a flamegraph tool.

## Known issues

Split into issues confirmed by running the profiler against test workloads
(`burn.c`, `burn2.c`), versus issues suspected from reading the code but
not yet reproduced.

### Confirmed, by testing

- **User-space symbols don't resolve for non-PIE binaries.** See "Known
  bug" under User-space frames above. Confirmed against `burn2`: own-binary
  frames print as raw hex, libc frames resolve fine.
- **1Hz sampling is too sparse to be useful.** A 10-second run against
  `burn2` (which has five distinct hot call paths plus a second thread)
  produced only ~17 total samples total - too few to make the relative
  widths in a flamegraph meaningful, and too few to reliably catch every
  code path at all. Needs to go up to something like 99Hz per CPU; tracked
  as a follow-up, not yet changed in code.
- **`/proc/<pid>/maps` path parsing takes only the first whitespace-split
  token of the path field** (`hamlet/src/main.rs`, `read_maps`). This
  breaks for mapped paths containing spaces, and doesn't special-case
  `(deleted)` suffixes (a mapping whose backing file was removed/replaced
  after being mapped, e.g. during a redeploy) - the resulting `PathBuf`
  won't exist on disk, so `addr2line::Loader::new` silently returns `None`
  via `.ok()` and the frame falls back to raw hex, with no indication to
  the user *why* that frame didn't resolve.

### Suspected, not yet reproduced

- **Frame-pointer-based stack walking can be incomplete.** `get_stackid`
  (both kernel and user variants) walks frame pointers, not DWARF CFI. Any
  library in the mapped address space built without frame pointers
  (`-fomit-frame-pointer`, the default in many release builds/distro
  packages) can produce truncated stacks or emit a bogus frame.
  `burn`/`burn2` are built with `-O0` specifically to avoid this, so it
  hasn't been observed here, but it will affect profiling real-world
  optimized binaries.
- **A frame inside `libm.so` printed as raw hex in one `burn2` run** (a
  `sin`/`cos` call site). Not yet root-caused - candidates are the same
  PIE/non-PIE offset bug manifesting some other way, a stripped libm on
  this system, or the call landing in the `vdso` (which has no on-disk file
  for `addr2line::Loader` to open, since it's synthesized by the kernel and
  mapped directly from memory, not read from a file).
- **`comm` (used as the root frame of each folded stack, via
  `/proc/<pid>/comm`) is per-thread, not per-process, and capped at 15
  bytes by the kernel.** For a multi-threaded program where worker threads
  call `pthread_setname_np` to rename themselves (common in real-world
  servers), samples from different threads of the *same logical process*
  would fold under different root frame names instead of grouping under one
  process-level root. `burn2`'s worker thread doesn't rename itself, so
  this hasn't shown up in testing yet.
- **Kernel-then-user frame ordering in a folded stack is an assumed
  invariant, not something the code verifies.** The folding logic places
  all user frames before all kernel frames on the theory that a sample
  landing in the kernel always arrived via "user code enters kernel at
  exactly one point, then kernel runs deeper from there" (matches the
  `getpid;entry_SYSCALL_64_after_hwframe;do_syscall_64` tail seen in
  `burn2`'s syscall path). This should hold for the ordinary
  syscall/page-fault/interrupt case, but hasn't been checked against signal
  handlers (user code pushed onto the user stack *by* the kernel,
  interleaved with kernel delivery machinery) or kernel threads (no user
  stack at all, so `uspace_id` should always be `-1` - assumed rather than
  asserted).

### Deliberately deferred

- `strace_map.get(...)?` in the display loop aborts the entire dump if a
  single stack id lookup fails (e.g. evicted from the fixed-capacity
  `STRACE_MAP` by the time of display). Not yet hardened to skip and
  continue per-entry.
- `SAMPLE_COUNT` (an `Array<u64>` counter) is populated by the eBPF program
  but no longer read from userspace after the histogram-based display loop
  replaced the original simple counter print. Currently orphaned; kept in
  case a simple aggregate "total samples" figure is wanted again later.
- Collection duration is a hardcoded 10 one-second ticks, not configurable.

### Operational / environment constraints

- Requires root, or `CAP_BPF` + `CAP_PERFMON`, to load the eBPF program and
  attach perf events - confirmed by testing: running unprivileged fails at
  the first map-creation call (`failed to create map SAMPLE_COUNT:
  Operation not permitted`).
- Building `hamlet-ebpf` requires a `bpf-linker` binary on `PATH` whose
  linked LLVM major version matches the nightly Rust toolchain used to
  compile the eBPF target (`aya_build` shells out to `rustup run
  <toolchain>`). A mismatch (e.g. a `nightly` built against LLVM 23 next to
  a system `bpf-linker` built against LLVM 22) fails at the link step with
  `ERROR llvm: Invalid record`, not at `bpf-linker` install time, making it
  a confusing failure to debug. Worked around by pinning `hamlet/build.rs`
  to `Toolchain::Custom("nightly-2026-04-15")`, a nightly release matching
  the LLVM version the locally installed `bpf-linker` was built against -
  this pin will need to be revisited if `bpf-linker` is reinstalled against
  a different LLVM version.
