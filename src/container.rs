use crate::event::KernelEvent;
use std::fs;

pub fn enrich_container(event: &mut KernelEvent) {
    let path = format!("/proc/{}/cgroup", event.tgid);
    let Ok(contents) = fs::read_to_string(path) else {
        return;
    };

    let cgroup_path = contents
        .lines()
        .find_map(|line| line.split_once("::").map(|(_, path)| path))
        .or_else(|| contents.lines().find_map(|line| line.splitn(3, ':').nth(2)))
        .unwrap_or("");

    if cgroup_path.is_empty() {
        return;
    }

    let runtime = if cgroup_path.contains("kubepods") {
        Some("kubernetes")
    } else if cgroup_path.contains("docker") {
        Some("docker")
    } else if cgroup_path.contains("containerd") {
        Some("containerd")
    } else if cgroup_path.contains("libpod") {
        Some("podman")
    } else {
        None
    };

    let id = cgroup_path
        .split(|c: char| matches!(c, '/' | '-' | '.'))
        .filter(|part| part.len() >= 12 && part.chars().all(|c| c.is_ascii_hexdigit()))
        .max_by_key(|part| part.len())
        .map(str::to_owned);

    if runtime.is_some() || id.is_some() {
        event.container.detected = true;
        event.container.runtime = runtime.map(str::to_owned);
        event.container.id = id;
        event.container.cgroup_path = Some(cgroup_path.to_owned());
    }
}
