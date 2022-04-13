# BFP profiler

The BPF code sends the results of `bpf_get_stack()` to user space via BPF ring buffer. The user space code converts the instruction pointers to human-readable function names.

## Usage

```bash
$ ./target/debug/profiler --help
profiler 0.1.0

USAGE:
    profiler [OPTIONS] <COMMAND>

ARGS:
    <COMMAND>    

OPTIONS:
        --debug      debug bpf
    -h, --help       Print help information
    -V, --version    Print version information
```

```bash
# sudo ./target/debug/profiler ~/git/foo/target/debug/foo
353885 2022-04-13 00:24:57.416099734 UTC
55f6a6137734 compiler_builtins::int::specialized_div_rem::u128_div_rem
55f6a610233e fib::exec
55f6a610225f fib::main
55f6a6102f2e core::ops::function::FnOnce::call_once
55f6a6101f01 std::sys_common::backtrace::__rust_begin_short_backtrace
55f6a6101e54 std::rt::lang_start::{{closure}}
55f6a6116501 std::rt::lang_start_internal

353885 2022-04-13 00:24:57.426197765 UTC
55f6a6137613 __divti3
55f6a610233e fib::exec
55f6a610225f fib::main
55f6a6102f2e core::ops::function::FnOnce::call_once
55f6a6101f01 std::sys_common::backtrace::__rust_begin_short_backtrace
55f6a6101e54 std::rt::lang_start::{{closure}}
55f6a6116501 std::rt::lang_start_internal
```

## Caveat

`bpf_get_stack()` needs frame pointers. You need to compile a binary with the following option:

```bash
RUSTFLAGS=-Cforce-frame-pointers=yes cargo build
```
