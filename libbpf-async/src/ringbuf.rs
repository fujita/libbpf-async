// Copyright (C) 2021 and 2022 The libbpf-async Authors.
//
// Licensed under LGPL-2.1 or BSD-2-Clause.

use core::task::{Context, Poll};
use libbpf_rs::query::MapInfoIter;
use std::io::Result;
use std::num::NonZeroUsize;
use std::os::unix::io::{AsRawFd, BorrowedFd, OwnedFd};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, ReadBuf};

const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;
const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;
const BPF_RINGBUF_HDR_SZ: u32 = 8;

pub struct RingBuffer {
    mask: u64,
    async_fd: AsyncFd<OwnedFd>,
    consumer: *mut core::ffi::c_void,
    producer: *mut core::ffi::c_void,
    data: *mut core::ffi::c_void,
}

impl RingBuffer {
    pub fn new(map: &libbpf_rs::Map) -> Self {
        // Borrowing this FD is safe: libbpf-rs returns only valid FDs and this borrow won't outlive the map reference
        let original_map_fd = unsafe { BorrowedFd::borrow_raw(map.fd()) };
        let map_fd = original_map_fd
            .try_clone_to_owned()
            .expect("Failed to duplicate FD");
        let mut max_entries = 0;
        for m in MapInfoIter::default() {
            if m.name == map.name() {
                max_entries = m.max_entries;
            }
        }
        let psize = NonZeroUsize::new(page_size::get()).expect("page size must not be zero");
        let consumer = unsafe {
            nix::sys::mman::mmap(
                None,
                psize,
                nix::sys::mman::ProtFlags::PROT_WRITE | nix::sys::mman::ProtFlags::PROT_READ,
                nix::sys::mman::MapFlags::MAP_SHARED,
                map_fd.as_raw_fd(),
                0,
            )
            .unwrap()
        };
        let producer = unsafe {
            nix::sys::mman::mmap(
                None,
                psize.saturating_add((2 * max_entries) as usize),
                nix::sys::mman::ProtFlags::PROT_READ,
                nix::sys::mman::MapFlags::MAP_SHARED,
                map_fd.as_raw_fd(),
                psize.get() as i64,
            )
            .unwrap()
        };

        let async_fd = AsyncFd::with_interest(map_fd, tokio::io::Interest::READABLE).unwrap();
        RingBuffer {
            mask: (max_entries - 1) as u64,
            async_fd,
            consumer,
            producer,
            data: unsafe { producer.add(psize.get()) },
        }
    }

    fn roundup_len(mut len: u32) -> u32 {
        len <<= 2;
        len >>= 2;
        len += BPF_RINGBUF_HDR_SZ;
        (len + 7) / 8 * 8
    }
}

impl Drop for RingBuffer {
    fn drop(&mut self) {
        let psize = page_size::get();
        unsafe {
            let _ = nix::sys::mman::munmap(self.consumer, psize);
            let _ = nix::sys::mman::munmap(self.producer, psize + 2 * (self.mask as usize + 1));
        }
    }
}

impl AsyncRead for RingBuffer {
    fn poll_read(
        self: core::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        loop {
            let mut cons_pos =
                unsafe { std::ptr::read_volatile(self.consumer as *const std::os::raw::c_ulong) };
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            let prod_pos =
                unsafe { std::ptr::read_volatile(self.producer as *const std::os::raw::c_ulong) };
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            if cons_pos < prod_pos {
                let len_ptr = unsafe { self.data.offset((cons_pos & self.mask) as isize) };
                let mut len = unsafe { std::ptr::read_volatile(len_ptr as *const u32) };
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

                if (len & BPF_RINGBUF_BUSY_BIT) == 0 {
                    cons_pos += RingBuffer::roundup_len(len) as u64;
                    if (len & BPF_RINGBUF_DISCARD_BIT) == 0 {
                        let sample = unsafe {
                            std::slice::from_raw_parts_mut(
                                len_ptr.offset(BPF_RINGBUF_HDR_SZ as isize) as *mut u8,
                                len as usize,
                            )
                        };
                        len = std::cmp::min(len, buf.capacity() as u32);
                        buf.put_slice(&sample[..len as usize]);
                    }
                    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
                    unsafe {
                        std::ptr::write_volatile(
                            self.consumer as *mut std::os::raw::c_ulong,
                            cons_pos,
                        )
                    };
                    if (len & BPF_RINGBUF_DISCARD_BIT) == 0 {
                        return Poll::Ready(Ok(()));
                    } else {
                        continue;
                    }
                }
            }
            let mut ev = futures::ready!(self.async_fd.poll_read_ready(cx))?;
            ev.clear_ready();
        }
    }
}
