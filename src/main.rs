use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use std::{mem::MaybeUninit, path::PathBuf, sync::mpsc, time::Duration};
use tracing::{info, warn};

use kernel_sentinel::{
    container,
    detection::Detector,
    event::{KernelEvent, RawKernelEvent},
    output::{OutputMode, Renderer},
    policy::PolicySet,
    process::ProcessTable,
};

mod sentinel {
    include!(concat!(env!("OUT_DIR"), "/sentinel.skel.rs"));
}

use sentinel::SentinelSkelBuilder;

#[derive(Debug, Parser)]
#[command(name = "kernel-sentinel", version)]
struct Cli {
    #[arg(short, long, default_value = "policies/default.yaml")]
    policy: PathBuf,

    #[arg(long, value_enum, default_value_t = OutputMode::Pretty)]
    output: OutputMode,

    #[arg(long)]
    verbose_events: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let cli = Cli::parse();
    let policies = PolicySet::load(&cli.policy)
        .with_context(|| format!("failed to load {}", cli.policy.display()))?;
    let (tx, rx) = mpsc::sync_channel::<RawKernelEvent>(8192);

    let builder = SentinelSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let callback_tx = tx.clone();
    let mut ring = RingBufferBuilder::new();
    ring.add(&skel.maps.events, move |data: &[u8]| {
        let mut raw = RawKernelEvent::default();
        if plain::copy_from_bytes(&mut raw, data).is_err() {
            warn!("invalid event payload");
            return 0;
        }
        let _ = callback_tx.try_send(raw);
        0
    })?;
    let ring = ring.build()?;

    let mut processes = ProcessTable::default();
    let detector = Detector::new(policies);
    let renderer = Renderer::new(cli.output);
    info!("kernel-sentinel started");

    loop {
        ring.poll(Duration::from_millis(100))?;
        while let Ok(raw) = rx.try_recv() {
            let mut event = KernelEvent::from(raw);
            processes.enrich(&mut event);
            container::enrich_container(&mut event);
            processes.observe(&event);

            if cli.verbose_events {
                renderer.event(&event)?;
            }

            for item in detector.evaluate(&event, &processes) {
                println!("{}", serde_json::to_string(&item)?);
            }
        }
    }
}
