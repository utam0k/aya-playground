use std::{fs::File, os::fd::AsRawFd};

use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::{CgroupSkb, CgroupSkbAttachType},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use clap::Parser;
use log::info;
use tokio::{signal, task};

use bandwidth_common::{PacketLog, NSEC_PER_SEC};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup/test")]
    cgroup_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/bandwidth"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/bandwidth"
    ))?;

    let cgroup = File::open(&opt.cgroup_path)?;

    let egress_program: &mut CgroupSkb = bpf.program_mut("egress_bandwidth").unwrap().try_into()?;
    egress_program.load()?;
    egress_program.attach(cgroup.as_raw_fd(), CgroupSkbAttachType::Egress)?;

    // let ingress_program: &mut CgroupSkb =
    //     bpf.program_mut("ingress_bandwidth").unwrap().try_into()?;
    // ingress_program.load()?;
    // ingress_program.attach(cgroup.as_raw_fd(), CgroupSkbAttachType::Ingress)?;

    let mut ingress_events = AsyncPerfEventArray::try_from(bpf.map_mut("INGRESS_EVENTS")?)?;
    let mut egress_events = AsyncPerfEventArray::try_from(bpf.map_mut("EGRESS_EVENTS")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = ingress_events.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    info!(
                        "ingress: {}s - {} bytes {}",
                        data.now / NSEC_PER_SEC,
                        data.tot_len,
                        if data.action == 1 { "PASS" } else { "DROP" },
                    );
                }
            }
        });
    }

    for cpu_id in online_cpus()? {
        let mut buf = egress_events.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    info!(
                        "egress: {}s - {} bytes {}",
                        data.now / NSEC_PER_SEC,
                        data.tot_len,
                        if data.action == 1 { "PASS" } else { "DROP" },
                    );
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
