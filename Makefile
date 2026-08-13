.PHONY: bootstrap build test fmt

bootstrap:
	@test -r /sys/kernel/btf/vmlinux
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h

build: bootstrap
	cargo build

test: bootstrap
	cargo test --lib

fmt:
	cargo fmt --all -- --check
