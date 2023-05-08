// Copyright (C) 2021 and 2022 The libbpf-async Authors.
//
// Licensed under LGPL-2.1 or BSD-2-Clause.

use chrono::prelude::*;
use object::{Object, ObjectSymbol};
use plain::Plain;
use std::fs;
use tokio::io::AsyncReadExt;

mod bashreadline {
    include!(concat!(env!("OUT_DIR"), "/bashreadline.skel.rs"));
}
use bashreadline::*;

const BINARY_NAME: &str = "/bin/bash";
const SYM_NAME: &str = "readline";
const RINGBUF_NAME: &str = "rb";

#[repr(C)]
#[derive(Copy, Clone)]
struct Entry {
    pub pid: u64,
    pub str: [u8; 120],
}

unsafe impl Plain for Entry {}

impl Entry {
    fn copy_from_bytes(buf: &[u8]) -> Entry {
        let mut e = Entry {
            pid: 0,
            str: [0; 120],
        };
        e.copy_from_bytes(buf).expect("buffer is short");
        e
    }
}

#[tokio::main]
async fn main() {
    rlimit::setrlimit(
        rlimit::Resource::MEMLOCK,
        rlimit::INFINITY,
        rlimit::INFINITY,
    )
    .unwrap();

    let mut builder = BashreadlineSkelBuilder::default();
    builder.obj_builder.debug(true);
    let mut skel = builder.open().unwrap().load().unwrap();

    let bin_data = fs::read(BINARY_NAME).unwrap();
    let obj_file = object::File::parse(&*bin_data).unwrap();
    let mut offset = 0;
    for s in obj_file.dynamic_symbols() {
        if s.name().unwrap() == SYM_NAME {
            offset = s.address();
        }
    }
    assert_ne!(offset, 0);

    let _link = skel
        .obj
        .prog_mut("printret")
        .unwrap()
        .attach_uprobe(true, -1, BINARY_NAME, offset as usize)
        .unwrap();

    let mut rb = libbpf_async::RingBuffer::new(skel.obj.map(RINGBUF_NAME).unwrap());
    println!("TIME      PID    COMMAND");
    loop {
        let mut buf = [0; 128];
        let n = rb.read(&mut buf).await.unwrap();
        let e = Entry::copy_from_bytes(&buf[0..n]);
        let mut s: Vec<u8> = e.str.iter().take_while(|x| **x != 0).cloned().collect();
        s.push(0);

        let local: DateTime<Local> = Local::now();
        println!(
            "{:0>2}:{}:{}  {:>6} {}",
            local.hour(),
            local.minute(),
            local.second(),
            e.pid,
            String::from_utf8(s).unwrap()
        );
    }
}
