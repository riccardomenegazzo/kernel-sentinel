.PHONY: bootstrap build release test fmt clippy run demo clean

bootstrap:
	@command -v bpftool >/dev/null || (echo "error: bpftool is required"; exit 1)
	@command -v clang >/dev/null || (echo "error: clang is required"; exit 1)
	@test -r /sys/kernel/btf/vmlinux || (echo "error: kernel BTF missing at /sys/kernel/btf/vmlinux"; exit 1)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h

build: bootstrap
	cargo build

release: bootstrap
	cargo build --release

test:
	cargo test --lib

fmt:
	cargo fmt --all -- --check

clippy: bootstrap
	cargo clippy --all-targets --all-features -- -D warnings

run: build
	sudo ./target/debug/kernel-sentinel --policy policies/default.yaml

demo: build
	sudo ./target/debug/kernel-sentinel --policy policies/default.yaml --pretty

clean:
	cargo clean
	rm -f src/bpf/vmlinux.h
