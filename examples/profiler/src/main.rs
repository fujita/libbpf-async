// Copyright (C) 2021 and 2022 The libbpf-async Authors.
//
// Licensed under LGPL-2.1 or BSD-2-Clause.

use chrono::Utc;
use clap::Parser;
use perf_event_open_sys as sys;
use plain::Plain;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::process::Command;
use std::u64;

mod profiler {
    include!(concat!(env!("OUT_DIR"), "/profiler.skel.rs"));
}
use profiler::*;

const RINGBUF_NAME: &str = "rb";
const MAX_FRAME: usize = 32;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct Stack {
    pub ip: [u64; MAX_FRAME],
}

unsafe impl Plain for Stack {}

impl Stack {
    fn copy_from_bytes(buf: &[u8]) -> Stack {
        let mut e = Stack::default();
        e.copy_from_bytes(buf).expect("buffer is short");
        e
    }
}

struct Area<T: addr2line::gimli::Reader> {
    start: u64,
    end: u64,
    ctx: addr2line::Context<T>,
}

const PERF_EVENT_IOC_MAGIC: u8 = b'$';
const PERF_EVENT_IOC_SET_BPF: u8 = 8;
nix::ioctl_write_int!(
    perf_event_set_bpf,
    PERF_EVENT_IOC_MAGIC,
    PERF_EVENT_IOC_SET_BPF
);

const PERF_EVENT_IOC_ENABLE: u8 = 0;
nix::ioctl_none!(
    perf_event_enable,
    PERF_EVENT_IOC_MAGIC,
    PERF_EVENT_IOC_ENABLE
);

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    command: String,

    /// debug bpf
    #[clap(long)]
    debug: bool,
}

fn addr2func<T: addr2line::gimli::Reader>(range: &[Area<T>], addr: u64) -> String {
    let idx = match range.binary_search_by_key(&addr, |x| x.start) {
        Ok(i) => i,
        Err(i) => {
            if i == 0 {
                return "<out-of-range>".to_string();
            }
            i - 1
        }
    };
    let area = &range[idx];
    if area.end < addr {
        return "<out-of-range>".to_string();
    }

    if let Ok(mut frames) = area.ctx.find_frames(addr - area.start) {
        let mut func_name = "<empty frame>".to_string();
        while let Ok(Some(f)) = frames.next() {
            if let Some(name) = f.function {
                func_name = format!("{}", name.demangle().unwrap());
            }
        }
        func_name
    } else {
        format!("\"<invalid frame>\" {:x}", addr - area.start)
    }
}

fn main() {
    let args = Args::parse();

    rlimit::setrlimit(
        rlimit::Resource::MEMLOCK,
        rlimit::INFINITY,
        rlimit::INFINITY,
    )
    .unwrap();

    let mut builder = ProfilerSkelBuilder::default();
    if args.debug {
        builder.obj_builder.debug(true);
    }
    let mut skel = builder.open().unwrap().load().unwrap();
    let prog_fd = skel.obj.prog("do_perf_event").unwrap().fd();
    let hmap = skel.obj.map_mut("hmap").unwrap();

    for cpu in 0..num_cpus::get() {
        let mut attrs = sys::bindings::perf_event_attr {
            size: std::mem::size_of::<sys::bindings::perf_event_attr>() as u32,
            type_: sys::bindings::perf_type_id_PERF_TYPE_SOFTWARE,
            config: sys::bindings::perf_sw_ids_PERF_COUNT_SW_CPU_CLOCK as u64,
            __bindgen_anon_1: sys::bindings::perf_event_attr__bindgen_ty_1 { sample_freq: 99 },
            ..Default::default()
        };
        attrs.set_freq(1);
        let event_fd = unsafe {
            sys::perf_event_open(
                &mut attrs,
                -1,
                cpu as i32,
                -1,
                sys::bindings::PERF_FLAG_FD_CLOEXEC as u64,
            )
        };
        if event_fd < 0 {
            panic!("perf_event_open failed {}", event_fd);
        }

        unsafe {
            if let Err(ret) = perf_event_set_bpf(event_fd, prog_fd as u64) {
                panic!("{:?}", ret);
            }
        }
        unsafe {
            if let Err(ret) = perf_event_enable(event_fd) {
                panic!("{:?}", ret);
            }
        }
    }

    let child = Command::new(args.command)
        .spawn()
        .expect("failed to execute");
    let pid = child.id();

    let mut memmaps: HashMap<String, Vec<(u64, u64)>> = HashMap::default();
    let reader =
        BufReader::new(File::open(format!("/proc/{}/maps", pid)).expect("failed to open maps"));
    for line in reader.lines() {
        if let Ok(line) = line {
            let v: Vec<&str> = line.split_ascii_whitespace().collect();
            if v.len() != 6 {
                continue;
            }
            let object = v[5].to_string();
            if object.starts_with('[') {
                continue;
            }
            let entry = memmaps.entry(object).or_default();
            let range: Vec<&str> = v[0].split('-').collect();
            let start = u64::from_str_radix(range[0], 16).unwrap();
            let end = u64::from_str_radix(range[1], 16).unwrap();
            entry.push((start, end));
        } else {
            break;
        }
    }

    let mut range = Vec::new();
    for (obj, r) in memmaps {
        let bin_data = fs::read(&obj).expect("failed to read");

        if let Ok(ctx) = addr2line::Context::new(
            &addr2line::object::read::File::parse(&*bin_data).expect("failed to parse elf"),
        ) {
            range.push(Area {
                start: r[0].0,
                end: r[r.len() - 1].1,
                ctx,
            });
        }
    }

    range.sort_by_key(|x| x.start);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    hmap.update(
        &pid.to_ne_bytes(),
        &pid.to_ne_bytes(),
        libbpf_rs::MapFlags::ANY,
    )
    .expect("failed to update pid map");

    rt.block_on(async move {
        use tokio::io::AsyncReadExt;

        let mut rb = libbpf_async::RingBuffer::new(skel.obj.map_mut(RINGBUF_NAME).unwrap());
        loop {
            let mut buf = [0; std::mem::size_of::<Stack>()];
            let n = rb.read(&mut buf).await.unwrap();
            let e = Stack::copy_from_bytes(&buf[0..n]);
            println!("{} {}", pid, Utc::now());
            for i in 0..MAX_FRAME {
                if e.ip[i] == 0 {
                    break;
                }
                println!("{:x} {}", e.ip[i], addr2func(&range, e.ip[i]));
            }
            println!();
        }
    });
}
