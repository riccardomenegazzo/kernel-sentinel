.PHONY: bootstrap build release test fmt clippy

bootstrap:
	@test -r /sys/kernel/btf/vmlinux
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h

build: bootstrap
	cargo build --features bpf

release: bootstrap
	cargo build --release --features bpf

test:
	cargo test --lib

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --lib -- -D warnings
