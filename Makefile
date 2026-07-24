PNPM ?= pnpm

.PHONY: fmt lint test frontend-check frontend-test frontend-build check build cli tauri-dev tauri-build verify build-macos clean-macos build-linux clean-linux

fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

frontend-check:
	$(PNPM) --dir apps/desktop check

frontend-test:
	$(PNPM) --dir apps/desktop test

frontend-build:
	$(PNPM) --dir apps/desktop build:web

check: fmt lint test frontend-check frontend-test

build: frontend-build
	cargo build --workspace

cli:
	cargo build -p vam-dev
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		codesign --force --sign - --identifier org.archuser.vpnappliancemanager.cli target/debug/vam-dev; \
	fi

tauri-dev:
	$(PNPM) --dir apps/desktop dev

tauri-build:
	$(PNPM) --dir apps/desktop build

verify: check build

build-macos:
	./build-helpers/mac/build.sh

clean-macos:
	./build-helpers/mac/clean.sh

build-linux:
	./build-helpers/linux/build.sh

clean-linux:
	./build-helpers/linux/clean.sh
