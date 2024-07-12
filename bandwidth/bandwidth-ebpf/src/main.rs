#![no_std]
#![no_main]

use aya_bpf::{
    bpf_printk,
    macros::{cgroup_skb, map},
    maps::{HashMap, PerfEventArray},
    programs::SkBuffContext,
};
use aya_bpf_bindings::helpers::{bpf_ktime_get_ns, bpf_skb_cgroup_id};

use bandwidth_common::{Info, PacketLog, NSEC_PER_SEC};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

#[map(name = "INGRESS_EVENTS")]
static mut INGRESS_EVENTS: PerfEventArray<PacketLog> = PerfEventArray::with_max_entries(1024, 0);

#[map(name = "EGRESS_EVENTS")]
static mut EGRESS_EVENTS: PerfEventArray<PacketLog> = PerfEventArray::with_max_entries(1024, 0);

#[map(name = "INGRESS_INFO")]
static mut INGRESS_INFO: HashMap<u64, Info> = HashMap::with_max_entries(100, 0);

#[map(name = "EGRESS_INFO")]
static mut EGRESS_INFO: HashMap<u64, Info> = HashMap::with_max_entries(100, 0);

// const BPS: u64 = 120;
const BPS: u64 = 1048576 * 10; // 1 MB * N

// #[cgroup_skb(name = "ingress_bandwidth")]
#[cgroup_skb]
pub fn ingress_bandwidth(ctx: SkBuffContext) -> i32 {
    return unsafe { ingress_try_bandwidth(ctx) }.unwrap_or_default();
}

unsafe fn ingress_try_bandwidth(ctx: SkBuffContext) -> Result<i32, i64> {
    let mut action = 1; // pass
    let now_ns = unsafe { bpf_ktime_get_ns() };

    let mut socket_ts = unsafe { (*ctx.skb.skb).tstamp };
    if socket_ts > now_ns {
        socket_ts = now_ns;
    }

    let i = &mut Info {
        t_last: socket_ts,
        previous: now_ns,
    } as *mut Info;
    let cgid = unsafe { bpf_skb_cgroup_id(ctx.skb.skb) };
    let info = match unsafe { EGRESS_INFO.get_ptr_mut(&cgid) } {
        Some(info) => info,
        None => {
            let i2 = &Info {
                t_last: now_ns,
                previous: now_ns,
            };
            EGRESS_INFO.insert(&cgid, &i2, 0)?;
            i
        }
    };

    if ctx.len() as u64 > BPS {
        action = 0; // drop
        INGRESS_INFO.insert(
            &cgid,
            &Info {
                t_last: socket_ts,
                previous: now_ns,
            },
            0,
        )?;
        return Ok(action);
    }

    let delay_nsec = (ctx.len() as u64 * NSEC_PER_SEC) / BPS;

    if now_ns - (*info).previous > NSEC_PER_SEC {
        (*info).t_last = socket_ts;
    }

    let next_ts_nsec = (*info).t_last + delay_nsec;

    let mut log_entry = PacketLog {
        action,
        tot_len: ctx.len(),
        now: next_ts_nsec - now_ns,
    };

    if next_ts_nsec <= socket_ts {
        INGRESS_INFO.insert(
            &cgid,
            &Info {
                t_last: socket_ts,
                previous: now_ns,
            },
            0,
        )?;
        INGRESS_EVENTS.output(&ctx, &log_entry, 0);
        return Ok(action);
    }

    if next_ts_nsec - now_ns >= NSEC_PER_SEC {
        action = 0; // drop
        log_entry.action = action;
        INGRESS_EVENTS.output(&ctx, &log_entry, 0);
        return Ok(action);
    }

    if next_ts_nsec <= now_ns || ctx.len() as u64 > BPS {
        action = 0; // drop
    }

    INGRESS_INFO.insert(
        &cgid,
        &Info {
            t_last: next_ts_nsec,
            previous: now_ns,
        },
        0,
    )?;

    INGRESS_EVENTS.output(&ctx, &log_entry, 0);
    Ok(action)
}

#[cgroup_skb]
pub fn egress_bandwidth(ctx: SkBuffContext) -> i32 {
    return unsafe { egress_try_bandwidth(ctx) }.unwrap_or_default();
}

unsafe fn egress_try_bandwidth(ctx: SkBuffContext) -> Result<i32, i64> {
    let mut action = 1; // pass
                        //
    let mut socket_timestamp = unsafe { (*ctx.skb.skb).tstamp };
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let mut none_skts = false;
    if socket_timestamp > now_ns {
        none_skts = true;
        socket_timestamp = now_ns;
    }

    let i = &mut Info {
        t_last: socket_timestamp,
        previous: now_ns,
    } as *mut Info;

    let cgid = unsafe { bpf_skb_cgroup_id(ctx.skb.skb) };
    let mut init = false;
    let info = match unsafe { EGRESS_INFO.get_ptr_mut(&cgid) } {
        Some(info) => info,
        None => {
            init = true;
            i
        }
    };

    let delay_nsec = (ctx.len() as u64 * NSEC_PER_SEC) / BPS;

    // should refresh because of the time window is over
    if now_ns - (*info).previous > NSEC_PER_SEC {
        (*info).t_last = socket_timestamp;
    }

    let next_ts_nsec = (*info).t_last + delay_nsec;

    if init {
        bpf_printk!(
            b"init, (*info).t_last: %lu, now: %lu",
            (*info).t_last,
            now_ns
        );
        let i2 = &Info {
            t_last: next_ts_nsec,
            previous: now_ns,
        };
        EGRESS_INFO.insert(&cgid, &i2, 0)?;
    }

    let mut log_entry = PacketLog {
        action,
        tot_len: ctx.len(),
        now: next_ts_nsec - now_ns,
    };

    // TODO: socket_timestampがnowになって進みすぎている
    // 最初の1秒間はなぜかsocket_timestampがない
    if next_ts_nsec <= socket_timestamp {
        EGRESS_INFO.insert(
            &cgid,
            &Info {
                t_last: socket_timestamp,
                previous: now_ns,
            },
            0,
        )?;
        EGRESS_EVENTS.output(&ctx, &log_entry, 0);
        bpf_printk!(b"OK, socket_ts: %lu", socket_timestamp);
        return Ok(action);
    }

    // normally over
    if next_ts_nsec - now_ns >= NSEC_PER_SEC {
        action = 0; // drop
        log_entry.action = action;
        EGRESS_EVENTS.output(&ctx, &log_entry, 0);
        return Ok(action);
    }

    if next_ts_nsec < now_ns || ctx.len() as u64 > BPS {
        action = 0; // drop
    }

    EGRESS_INFO.insert(
        &cgid,
        &Info {
            t_last: next_ts_nsec,
            previous: now_ns,
        },
        0,
    )?;

    EGRESS_EVENTS.output(&ctx, &log_entry, 0);
    Ok(action)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
