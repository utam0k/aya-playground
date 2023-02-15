#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use killsnoop_common::SignalLog;

#[tracepoint(name = "killsnoop")]
pub fn killsnoop(ctx: TracePointContext) -> u32 {
    match unsafe { try_killsnoop(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<SignalLog> =
    PerfEventArray::<SignalLog>::with_max_entries(1024, 0);

/*
$ sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_kill/format
name: sys_enter_kill
ID: 177
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:pid_t pid;        offset:16;      size:8; signed:0;
        field:int sig;  offset:24;      size:8; signed:0;

print fmt: "pid: 0x%08lx, sig: 0x%08lx", ((unsigned long)(REC->pid)), ((unsigned long)(REC->sig))
*/
unsafe fn try_killsnoop(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32).try_into().unwrap();
    let tid = bpf_get_current_pid_tgid() as u32;
    let tpid = ctx.read_at::<i64>(16).unwrap() as i32;
    let tsig = ctx.read_at::<i64>(24).unwrap() as u32;
    let comm = bpf_get_current_comm().unwrap();

    let log = SignalLog {
        pid,
        tid,
        tpid,
        tsig,
        comm,
    };
    EVENTS.output(&ctx, &log, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
