use chrono::{DateTime, Utc};
use plain::Plain;
use serde::{Deserialize, Serialize};

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawKernelEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid_ns: u64,
    pub mnt_ns: u64,
    pub kind: u32,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub exit_code: i32,
    pub flags: u32,
    pub target_uid: u32,
    pub reserved: u32,
    pub comm: [u8; COMM_LEN],
    pub path: [u8; PATH_LEN],
}

unsafe impl Plain for RawKernelEvent {}

impl Default for RawKernelEvent {
    fn default() -> Self {
        Self {
            timestamp_ns: 0,
            cgroup_id: 0,
            pid_ns: 0,
            mnt_ns: 0,
            kind: 0,
            pid: 0,
            tgid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            exit_code: 0,
            flags: 0,
            target_uid: 0,
            reserved: 0,
            comm: [0; COMM_LEN],
            path: [0; PATH_LEN],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Exec,
    Fork,
    Exit,
    Setuid,
    FileOpen,
    LsmDeny,
    Unknown,
}

impl From<u32> for EventKind {
    fn from(value: u32) -> Self {
        match value {
            1 => Self::Exec,
            2 => Self::Fork,
            3 => Self::Exit,
            4 => Self::Setuid,
            5 => Self::FileOpen,
            6 => Self::LsmDeny,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ContainerContext {
    pub detected: bool,
    pub runtime: Option<String>,
    pub id: Option<String>,
    pub cgroup_path: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct KernelEvent {
    pub observed_at: DateTime<Utc>,
    pub monotonic_ns: u64,
    pub kind: EventKind,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub cgroup_id: u64,
    pub pid_ns: u64,
    pub mnt_ns: u64,
    pub comm: String,
    pub path: Option<String>,
    pub exit_code: Option<i32>,
    pub target_uid: Option<u32>,
    pub parent_comm: Option<String>,
    pub parent_exe: Option<String>,
    pub exe: Option<String>,
    pub cmdline: Vec<String>,
    pub container: ContainerContext,
}

fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

impl From<RawKernelEvent> for KernelEvent {
    fn from(raw: RawKernelEvent) -> Self {
        let kind = EventKind::from(raw.kind);
        let path = cstr(&raw.path);

        Self {
            observed_at: Utc::now(),
            monotonic_ns: raw.timestamp_ns,
            kind,
            pid: raw.pid,
            tgid: raw.tgid,
            ppid: raw.ppid,
            uid: raw.uid,
            gid: raw.gid,
            euid: raw.euid,
            egid: raw.egid,
            cgroup_id: raw.cgroup_id,
            pid_ns: raw.pid_ns,
            mnt_ns: raw.mnt_ns,
            comm: cstr(&raw.comm),
            path: (!path.is_empty()).then_some(path),
            exit_code: (kind == EventKind::Exit).then_some(raw.exit_code),
            target_uid: (kind == EventKind::Setuid).then_some(raw.target_uid),
            parent_comm: None,
            parent_exe: None,
            exe: None,
            cmdline: Vec::new(),
            container: ContainerContext {
                detected: false,
                runtime: None,
                id: None,
                cgroup_path: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_event_layout_matches_kernel_abi() {
        assert_eq!(std::mem::size_of::<RawKernelEvent>(), 352);
    }
}
