use crate::event::KernelEvent;
use anyhow::Result;
use clap::ValueEnum;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum OutputMode {
    Pretty,
    Json,
}

pub struct Renderer {
    mode: OutputMode,
}

impl Renderer {
    pub fn new(mode: OutputMode) -> Self {
        Self { mode }
    }

    pub fn event(&self, event: &KernelEvent) -> Result<()> {
        match self.mode {
            OutputMode::Json => println!("{}", serde_json::to_string(event)?),
            OutputMode::Pretty => println!("event={:?} pid={} comm={}", event.kind, event.tgid, event.comm),
        }
        Ok(())
    }
}
