.PHONY: audit build check-code e2e release-check reset-deps start start-deps stop-deps test-e2e test-in-ci test-integration test-rust

build:
	cargo build --locked --all-targets

check-code:
	sh ./ci_probe.sh
