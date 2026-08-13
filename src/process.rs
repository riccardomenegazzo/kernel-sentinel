use crate::event::{EventKind, KernelEvent};
use procfs::process::Process;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub exe: Option<String>,
    pub uid: u32,
    pub cgroup_id: u64,
    pub pid_ns: u64,
    pub mnt_ns: u64,
}

#[derive(Default)]
pub struct ProcessTable {
    entries: HashMap<u32, ProcessIdentity>,
}

impl ProcessTable {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn lineage(&self, pid: u32, max_depth: usize) -> Vec<ProcessIdentity> {
        let mut out = Vec::new();
        let mut current = pid;

        for _ in 0..max_depth {
            let Some(proc) = self.entries.get(&current) else {
                break;
            };
            out.push(proc.clone());
            if proc.ppid == 0 || proc.ppid == current {
                break;
            }
            current = proc.ppid;
        }

        out
    }

    pub fn enrich(&self, event: &mut KernelEvent) {
        if let Some(parent) = self.entries.get(&event.ppid) {
            event.parent_comm = Some(parent.comm.clone());
            event.parent_exe = parent.exe.clone();
        }

        if let Ok(proc) = Process::new(event.tgid as i32) {
            event.exe = proc.exe().ok().map(|p| p.display().to_string());
            event.cmdline = proc.cmdline().unwrap_or_default();
        }

        if event.exe.is_none() && event.kind == EventKind::Exec {
            event.exe = event.path.clone();
        }
    }

    pub fn observe(&mut self, event: &KernelEvent) {
        match event.kind {
            EventKind::Exec | EventKind::Fork => {
                self.entries.insert(
                    event.tgid,
                    ProcessIdentity {
                        pid: event.tgid,
                        ppid: event.ppid,
                        comm: event.comm.clone(),
                        exe: event.exe.clone().or_else(|| event.path.clone()),
                        uid: event.euid,
                        cgroup_id: event.cgroup_id,
                        pid_ns: event.pid_ns,
                        mnt_ns: event.mnt_ns,
                    },
                );
            }
            EventKind::Exit => {
                self.entries.remove(&event.tgid);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::ContainerContext;
    use chrono::Utc;

    fn event(pid: u32, ppid: u32) -> KernelEvent {
        KernelEvent {
            observed_at: Utc::now(),
            monotonic_ns: 0,
            kind: EventKind::Exec,
            pid,
            tgid: pid,
            ppid,
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
            cgroup_id: 1,
            pid_ns: 1,
            mnt_ns: 1,
            comm: format!("p{pid}"),
            path: Some(format!("/bin/p{pid}")),
            exit_code: None,
            target_uid: None,
            parent_comm: None,
            parent_exe: None,
            exe: Some(format!("/bin/p{pid}")),
            cmdline: vec![],
            container: ContainerContext {
                detected: false,
                runtime: None,
                id: None,
                cgroup_path: None,
            },
        }
    }

    #[test]
    fn reconstructs_lineage() {
        let mut table = ProcessTable::default();
        table.observe(&event(1, 0));
        table.observe(&event(10, 1));
        table.observe(&event(11, 10));

        let chain = table.lineage(11, 8);
        assert_eq!(chain.iter().map(|p| p.pid).collect::<Vec<_>>(), vec![11, 10, 1]);
    }
}
