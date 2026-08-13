use crate::{
    event::KernelEvent,
    policy::{Match, PolicySet, Rule, Severity},
    process::{ProcessIdentity, ProcessTable},
};
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Detection {
    pub detected_at: DateTime<Utc>,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: SeverityOut,
    pub score: u32,
    pub description: String,
    pub tags: Vec<String>,
    pub event: KernelEvent,
    pub lineage: Vec<ProcessIdentity>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityOut {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<Severity> for SeverityOut {
    fn from(value: Severity) -> Self {
        match value {
            Severity::Info => Self::Info,
            Severity::Low => Self::Low,
            Severity::Medium => Self::Medium,
            Severity::High => Self::High,
            Severity::Critical => Self::Critical,
        }
    }
}

pub struct Detector {
    policies: PolicySet,
}

impl Detector {
    pub fn new(policies: PolicySet) -> Self {
        Self { policies }
    }

    pub fn evaluate(&self, event: &KernelEvent, processes: &ProcessTable) -> Vec<Detection> {
        self.policies
            .rules
            .iter()
            .filter(|rule| matches_rule(&rule.r#match, event))
            .map(|rule| detection(rule, event, processes))
            .collect()
    }
}

fn detection(rule: &Rule, event: &KernelEvent, processes: &ProcessTable) -> Detection {
    Detection {
        detected_at: Utc::now(),
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        severity: rule.severity.into(),
        score: rule.score.min(100),
        description: rule.description.clone(),
        tags: rule.tags.clone(),
        event: event.clone(),
        lineage: processes.lineage(event.ppid, 8),
    }
}

fn matches_rule(m: &Match, e: &KernelEvent) -> bool {
    if m.event.is_some_and(|v| v != e.kind) {
        return false;
    }
    if m.uid.is_some_and(|v| v != e.uid) {
        return false;
    }
    if m.euid.is_some_and(|v| v != e.euid) {
        return false;
    }
    if m.target_uid.is_some_and(|v| e.target_uid != Some(v)) {
        return false;
    }
    if m.container.is_some_and(|v| v != e.container.detected) {
        return false;
    }
    if m.comm.as_deref().is_some_and(|v| v != e.comm) {
        return false;
    }
    if m.parent_comm
        .as_deref()
        .is_some_and(|v| e.parent_comm.as_deref() != Some(v))
    {
        return false;
    }

    let executable = e.exe.as_deref().or(e.path.as_deref()).unwrap_or("");
    if m.executable_prefix
        .as_deref()
        .is_some_and(|v| !executable.starts_with(v))
    {
        return false;
    }
    if m.executable_suffix
        .as_deref()
        .is_some_and(|v| !executable.ends_with(v))
    {
        return false;
    }
    if m.parent_executable_suffix.as_deref().is_some_and(|v| {
        !e.parent_exe.as_deref().unwrap_or("").ends_with(v)
    }) {
        return false;
    }

    let path = e.path.as_deref().unwrap_or("");
    if m.path_prefix.as_deref().is_some_and(|v| !path.starts_with(v)) {
        return false;
    }
    if m.path_exact.as_deref().is_some_and(|v| path != v) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ContainerContext, EventKind};

    fn base() -> KernelEvent {
        KernelEvent {
            observed_at: Utc::now(),
            monotonic_ns: 1,
            kind: EventKind::Exec,
            pid: 10,
            tgid: 10,
            ppid: 9,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            cgroup_id: 42,
            pid_ns: 1,
            mnt_ns: 2,
            comm: "sh".into(),
            path: Some("/bin/sh".into()),
            exit_code: None,
            target_uid: None,
            parent_comm: Some("nginx".into()),
            parent_exe: Some("/usr/sbin/nginx".into()),
            exe: Some("/bin/sh".into()),
            cmdline: vec!["sh".into()],
            container: ContainerContext {
                detected: true,
                runtime: Some("docker".into()),
                id: Some("abc".into()),
                cgroup_path: Some("/docker/abc".into()),
            },
        }
    }

    #[test]
    fn matches_shell_spawned_by_nginx_in_container() {
        let m = Match {
            event: Some(EventKind::Exec),
            executable_suffix: Some("/sh".into()),
            parent_comm: Some("nginx".into()),
            container: Some(true),
            ..Default::default()
        };
        assert!(matches_rule(&m, &base()));
    }

    #[test]
    fn rejects_wrong_uid() {
        let m = Match {
            uid: Some(1000),
            ..Default::default()
        };
        assert!(!matches_rule(&m, &base()));
    }
}
