# libbpf-async

A library for writing BPF programs in Async Rust, complementary for [libbpf-rs](https://github.com/libbpf/libbpf-rs), Rust wrapper for [libbpf](https://github.com/libbpf/libbpf).

Currently, this provides Async-friendly APIs for [BPF ring buffer](https://www.kernel.org/doc/html/latest/bpf/ringbuf.html).

To use in your project, add into your `Cargo.toml`:

```toml
[dependencies]
libbpf-async = "0.2"
```

## Example

```rust,no_run
#[tokio::main]
async fn main() {
    let mut builder = TracerSkelBuilder::default();
    let mut skel = builder.open().unwrap().load().unwrap();

    let mut rb = libbpf_async::RingBuffer::new(skel.obj.map_mut("ringbuf").unwrap());
    loop {
        let mut buf = [0; 128];
        let n = rb.read(&mut buf).await.unwrap();
        // do something useful with the buffer
    }
}
```

A working example code can be found [here](https://github.com/fujita/libbpf-async/tree/master/examples).

## License

This work is dual-licensed under BSD 2-clause license and GNU LGPL v2.1 license. You can choose between one of them if you use this work.
