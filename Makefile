GO ?= go
CARGO ?= cargo

.PHONY: bootstrap build release test test-rust cortex-test cortex-build demo doctor fmt clippy check clean

bootstrap:
	@./scripts/bootstrap.sh

build: bootstrap
	$(CARGO) build --features bpf

release: bootstrap
	$(CARGO) build --release --features bpf

test: test-rust cortex-test

test-rust:
	$(CARGO) test --lib

cortex-test:
	cd cortex && $(GO) test ./...

cortex-build:
	@mkdir -p bin
	cd cortex && $(GO) build -trimpath -o ../bin/cortex ./cmd/cortex

demo:
	@./scripts/demo-cortex.sh

doctor:
	@./scripts/doctor.sh

fmt:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --lib -- -D warnings

check: fmt clippy test

clean:
	$(CARGO) clean
	rm -rf bin dist
