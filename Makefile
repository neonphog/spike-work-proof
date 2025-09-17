.PHONY: all test wasm

all: test

test:
	cargo test

wasm:
	wasm-pack build --target web --features wasm
