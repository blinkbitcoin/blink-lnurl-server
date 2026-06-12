.PHONY: audit build check-code e2e release-check reset-deps start start-deps stop-deps test-e2e test-in-ci test-integration test-rust

build:
	cargo build --locked --all-targets

check-code:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets -- -D warnings

audit:
	cargo audit

test-rust:
	env -u LNURL_TEST_POSTGRES_URL cargo test --locked

start-deps:
	docker compose up -d postgres

stop-deps:
	docker compose down --remove-orphans

reset-deps: stop-deps start-deps

start:
	./scripts/start-local-stack.sh

test-e2e:
	cargo build --locked --bin lnurl-server --bin e2e_auth --bin blink_graphql_mock --bin e2e_zap_request
	bats -t bats

e2e: test-e2e

test-integration: reset-deps
	LNURL_TEST_POSTGRES_URL=postgres://user:password@127.0.0.1:5432/lnurl cargo test --locked postgres_tests -- --test-threads=1

test-in-ci: test-rust test-integration

release-check:
	$(MAKE) check-code
	$(MAKE) test-rust
	$(MAKE) test-integration
	$(MAKE) test-e2e
	$(MAKE) audit
