use aya::{
    maps::{HashMap, StackTraceMap},
    programs::{PerfEvent, perf_event},
    util::{kernel_symbols, online_cpus},
};
use clap::Parser;
use hamlet_common::StackKey;
use std::{
    collections::{BTreeMap, HashMap as StdHashMap},
    fs,
    path::PathBuf,
    time::Duration,
};
#[rustfmt::skip]
use log::{debug, warn};

use tokio::{signal, time::interval};

#[derive(clap::Parser)]
struct Args {
    #[arg(long)]
    pid: Option<u32>,
}
struct Mapping {
    start: u64,
    end: u64,
    offset: u64,
    path: PathBuf,
}

fn read_maps(pid: u32) -> anyhow::Result<Vec<Mapping>> {
    let content = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut mappings = Vec::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let range = match parts.next() {
            Some(r) => r,
            None => continue,
        };
        parts.next();
        let offset_str = match parts.next() {
            Some(o) => o,
            None => continue,
        };
        parts.next();
        parts.next();
        let path_str = match parts.next() {
            Some(s) => s,
            None => continue,
        };

        let (start, end) = match range.split_once("-") {
            Some(pair) => pair,
            None => continue,
        };
        let start = match u64::from_str_radix(start, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let end = match u64::from_str_radix(end, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let file_offset = match u64::from_str_radix(offset_str, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let mapping_instance = Mapping {
            start,
            end,
            offset: file_offset,
            path: PathBuf::from(path_str),
        };
        mappings.push(mapping_instance);
    }
    return Ok(mappings);
}

struct UserSymbolResolver {
    maps_cache: StdHashMap<u32, Vec<Mapping>>,
    loader: StdHashMap<PathBuf, Option<addr2line::Loader>>,
}

impl UserSymbolResolver {
    fn new() -> UserSymbolResolver {
        return Self {
            maps_cache: StdHashMap::new(),
            loader: StdHashMap::new(),
        };
    }
    fn resolve(&mut self, pid: u32, ip: u64) -> Option<String> {
        let mappings = self
            .maps_cache
            .entry(pid)
            .or_insert_with(|| read_maps(pid).unwrap_or_default());

        let mapping = find_mapping(mappings, ip)?;

        let file_offset = to_file_offset(mapping, ip);
        let path = mapping.path.clone();

        let loader = self
            .loader
            .entry(path.clone())
            .or_insert_with(|| addr2line::Loader::new(&path).ok());

        let loader = loader.as_ref()?;
        loader.find_symbol(file_offset).map(String::from)
    }
}

fn find_mapping<'a>(mappings: &'a Vec<Mapping>, ip: u64) -> Option<&'a Mapping> {
    mappings.iter().find(|map| ip >= map.start && ip < map.end)
}

fn to_file_offset(mapping: &Mapping, ip: u64) -> u64 {
    ip - mapping.start + mapping.offset
}

/// Name used as the root frame of every folded stack. Falls back to the pid
/// if the process has already exited.
fn process_name(pid: u64) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|comm| comm.trim().replace(';', "_"))
        .ok()
        .filter(|comm| !comm.is_empty())
        .unwrap_or_else(|| pid.to_string())
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/hamlet"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based
    // on clock ticks.
    let program: &mut PerfEvent = ebpf.program_mut("hamlet").unwrap().try_into()?;
    program.load()?;
    for cpu in online_cpus().map_err(|(_, error)| error)? {
        program.attach(
            perf_event::PerfEventConfig::Software(perf_event::SoftwareEvent::CpuClock),
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
            perf_event::SamplePolicy::Frequency(1),
            true,
        )?;
    }
    // let sample_count : Array<_, u64> = ebpf.map_mut("SAMPLE_COUNT").into()?;

    let strace_map: StackTraceMap<_> = ebpf
        .map("STRACE_MAP")
        .ok_or_else(|| anyhow::anyhow!("STRACE_MAP not found"))?
        .try_into()?;
    let histogram: HashMap<_, StackKey, u64> = ebpf
        .map("HIST")
        .ok_or_else(|| anyhow::anyhow!("HIST not found"))?
        .try_into()?;
    let mut ticker = interval(Duration::from_secs(1));
    let mut time = 10;
    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);
    eprintln!("Waiting for Ctrl-C...");
    loop {
        if time == 0 {
            break;
        }
        tokio::select! {
            _ = ticker.tick() => {
                time-=1;
            }
            _ = &mut ctrl_c => {
                eprintln!("exiting");
                break;
            }
        }
    }
    let ksyms = kernel_symbols()?;
    let mut user_sym = UserSymbolResolver::new();

    // Samples are bucketed by stack *id*, so the same logical stack can show up
    // under several ids (e.g. different instruction offsets inside one function).
    // Folding by resolved symbol names merges them back together.
    let mut folded: BTreeMap<String, u64> = BTreeMap::new();
    for entry in histogram.iter() {
        let (stack_key, count) = entry?;
        if let Some(arg_pid) = args.pid {
            if arg_pid as u64 != stack_key.pid {
                continue;
            }
        }

        // Folded format is root-first, but the kernel stores frames leaf-first.
        // A sampled stack runs: process -> user frames -> kernel frames (leaf).
        let mut frames = vec![process_name(stack_key.pid)];
        if stack_key.uspace_id >= 0 {
            let userspace_trace = strace_map.get(&(stack_key.uspace_id as u32), 0)?;
            for frame in userspace_trace.frames().iter().rev() {
                frames.push(
                    user_sym
                        .resolve(stack_key.pid as u32, frame.ip)
                        .unwrap_or_else(|| format!("{:#x}", frame.ip)),
                );
            }
        }
        if stack_key.kspace_id >= 0 {
            let kernel_trace = strace_map.get(&(stack_key.kspace_id as u32), 0)?;
            for frame in kernel_trace.frames().iter().rev() {
                frames.push(match ksyms.range(..=frame.ip).next_back() {
                    Some((_, name)) => name.clone(),
                    None => format!("{:#x}", frame.ip),
                });
            }
        }
        *folded.entry(frames.join(";")).or_default() += count;
    }

    for (stack, count) in folded {
        println!("{stack} {count}");
    }

    Ok(())
}
