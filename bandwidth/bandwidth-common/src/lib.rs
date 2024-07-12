#![no_std]

pub const NSEC_PER_SEC: u64 = 1_000_000_000;

#[repr(C)]
pub struct PacketLog {
    pub now: u64,
    pub action: i32,
    pub tot_len: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Info {
    pub t_last: u64,
    pub previous: u64,
}

impl Info {
    pub fn new(t_last: u64, previous: u64) -> Self {
        Self { t_last, previous }
    }
}
