#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_USER_STACK,
    helpers::bpf_get_current_pid_tgid,
    macros::{map, perf_event},
    maps::{Array, HashMap, StackTrace},
    programs::{PerfEventContext, tracing::StackIdContext},
};
use hamlet_common::StackKey;

#[map]
static SAMPLE_COUNT: Array<u64> = Array::with_max_entries(1, 0);
#[map]
static HIST: HashMap<StackKey, u64> = HashMap::with_max_entries(65592, 0);
#[map]
static STRACE_MAP: StackTrace = StackTrace::with_max_entries(65592, 0);

#[perf_event]
pub fn hamlet(ctx: PerfEventContext) -> u32 {
    match try_hamlet(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_hamlet(ctx: PerfEventContext) -> Result<u32, u32> {
    // A failed stack walk (kernel or userspace) shouldn't drop the whole
    // sample - record -1 for that half and keep whichever half succeeded.
    // main.rs already checks `>= 0` before resolving either stack.
    let uspace_stack_id = ctx
        .get_stackid(&STRACE_MAP, BPF_F_USER_STACK as u64)
        .unwrap_or(-1);
    let kspace_stack_id = ctx.get_stackid(&STRACE_MAP, 0).unwrap_or(-1);
    let pid = bpf_get_current_pid_tgid() >> 32;
    let stack_key = StackKey {
        pid,
        kspace_id: kspace_stack_id,
        uspace_id: uspace_stack_id,
    };

    
    if let Some(count) = HIST.get_ptr_mut(&stack_key) {
        unsafe { *count += 1 };
    } else {
        HIST.insert(&stack_key, &1u64, 0).map_err(|_| 1u32)?;
    };

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
