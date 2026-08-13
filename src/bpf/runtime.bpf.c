// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define KS_COMM_LEN 16
#define KS_PATH_LEN 256

enum ks_event_kind {
    KS_EVENT_EXEC = 1,
    KS_EVENT_FORK = 2,
    KS_EVENT_EXIT = 3,
    KS_EVENT_SETUID = 4,
    KS_EVENT_FILE_OPEN = 5,
    KS_EVENT_POLICY_DENY = 6,
};

struct ks_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u64 pid_ns;
    __u64 mnt_ns;
    __u32 kind;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 euid;
    __u32 egid;
    __s32 exit_code;
    __u32 flags;
    __u32 target_uid;
    __u32 reserved;
    char comm[KS_COMM_LEN];
    char path[KS_PATH_LEN];
};

struct ks_enforcement_policy {
    __u8 deny_tmp_exec;
    __u8 reserved[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct ks_enforcement_policy);
} enforcement SEC(".maps");

static __always_inline __u64 read_pid_ns(struct task_struct *task)
{
    struct nsproxy *proxy = BPF_CORE_READ(task, nsproxy);
    if (!proxy)
        return 0;
    struct pid_namespace *ns = BPF_CORE_READ(proxy, pid_ns_for_children);
    return ns ? BPF_CORE_READ(ns, ns.inum) : 0;
}

static __always_inline __u64 read_mnt_ns(struct task_struct *task)
{
    struct nsproxy *proxy = BPF_CORE_READ(task, nsproxy);
    if (!proxy)
        return 0;
    struct mnt_namespace *ns = BPF_CORE_READ(proxy, mnt_ns);
    return ns ? BPF_CORE_READ(ns, ns.inum) : 0;
}

static __always_inline void fill_common(struct ks_event *e, __u32 kind)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    const struct cred *cred = BPF_CORE_READ(task, cred);

    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->kind = kind;
    e->pid = (__u32)pid_tgid;
    e->tgid = (__u32)(pid_tgid >> 32);
    e->uid = (__u32)uid_gid;
    e->gid = (__u32)(uid_gid >> 32);
    if (cred) {
        e->euid = BPF_CORE_READ(cred, euid.val);
        e->egid = BPF_CORE_READ(cred, egid.val);
    }
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->pid_ns = read_pid_ns(task);
    e->mnt_ns = read_mnt_ns(task);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct ks_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    fill_common(e, KS_EVENT_EXEC);
    bpf_probe_read_str(e->path, sizeof(e->path), (char *)ctx + (ctx->__data_loc_filename & 0xffff));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct ks_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    fill_common(e, KS_EVENT_FORK);
    e->pid = ctx->child_pid;
    e->tgid = ctx->child_pid;
    e->ppid = ctx->parent_pid;
    bpf_probe_read_str(e->comm, sizeof(e->comm), (char *)ctx + (ctx->__data_loc_child_comm & 0xffff));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct ks_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    fill_common(e, KS_EVENT_EXIT);
    e->exit_code = BPF_CORE_READ((struct task_struct *)bpf_get_current_task_btf(), exit_code);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct ks_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    fill_common(e, KS_EVENT_SETUID);
    e->target_uid = (__u32)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(audit_file_open, struct file *file, int ret)
{
    if (ret != 0)
        return ret;

    struct ks_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, KS_EVENT_FILE_OPEN);
    if (bpf_d_path(&file->f_path, e->path, sizeof(e->path)) < 0)
        e->path[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(enforce_exec, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct ks_enforcement_policy *policy = bpf_map_lookup_elem(&enforcement, &cgroup_id);
    if (!policy || !policy->deny_tmp_exec)
        return 0;

    char path[KS_PATH_LEN] = {};
    if (bpf_d_path(&bprm->file->f_path, path, sizeof(path)) < 0)
        return 0;

    if (path[0] == '/' && path[1] == 't' && path[2] == 'm' && path[3] == 'p' && path[4] == '/') {
        struct ks_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            fill_common(e, KS_EVENT_POLICY_DENY);
            __builtin_memcpy(e->path, path, sizeof(e->path));
            bpf_ringbuf_submit(e, 0);
        }
        return -1;
    }

    return 0;
}
