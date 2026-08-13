use crate::{detection::Detection, event::KernelEvent};
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
            OutputMode::Pretty => println!(
                "event={:?} pid={} ppid={} comm={} exe={} container={}",
                event.kind,
                event.tgid,
                event.ppid,
                event.comm,
                event.exe.as_deref().unwrap_or("-"),
                event.container.detected
            ),
        }
        Ok(())
    }

    pub fn detection(&self, item: &Detection) -> Result<()> {
        match self.mode {
            OutputMode::Json => println!("{}", serde_json::to_string(item)?),
            OutputMode::Pretty => {
                let binary = item
                    .event
                    .exe
                    .as_deref()
                    .or(item.event.path.as_deref())
                    .unwrap_or("-");
                let lineage = item
                    .lineage
                    .iter()
                    .rev()
                    .map(|process| process.comm.as_str())
                    .collect::<Vec<_>>()
                    .join(" -> ");

                println!("[{:?}] {} ({})", item.severity, item.rule_name, item.rule_id);
                println!("  score:   {}", item.score);
                println!("  process: {} ({})", item.event.comm, item.event.tgid);
                println!("  binary:  {binary}");
                if !lineage.is_empty() {
                    println!("  lineage: {lineage} -> {}", item.event.comm);
                }
                if item.event.container.detected {
                    println!(
                        "  container: {}",
                        item.event.container.id.as_deref().unwrap_or("unknown")
                    );
                }
                if !item.description.is_empty() {
                    println!("  why:     {}", item.description);
                }
            }
        }
        Ok(())
    }
}
