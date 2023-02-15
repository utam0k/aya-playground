#![no_std]

use core::fmt::Debug;

use aya_bpf::cty::c_uchar;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SignalLog {
    pub pid: u32,
    pub tid: u32,
    pub tpid: i32,
    pub tsig: u32,
    pub comm: [c_uchar; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SignalLog {}

impl Debug for SignalLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let comm = core::str::from_utf8(&self.comm).unwrap();
        write!(
            f,
            "pid: {}, tid: {}, tpid: {}, tsig: {}, comm: {}",
            self.pid, self.tid, self.tpid, self.tsig, comm
        )
    }
}
