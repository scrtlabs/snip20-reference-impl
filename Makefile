SECRETCLI = docker exec -it secretdev /usr/bin/secretcli

SECRET_GRPC_PORT ?= 9090
SECRET_LCD_PORT ?= 1317
SECRET_RPC_PORT ?= 26657
LOCALSECRET_VERSION ?= v1.15.0

.PHONY: all
all: clippy test

.PHONY: check
check:
	cargo check

.PHONY: check-receiver
check-receiver:
	$(MAKE) -C tests/example-receiver check

.PHONY: clippy
clippy:
	cargo clippy

.PHONY: clippy-receiver
clippy-receiver:
	$(MAKE) -C tests/example-receiver clippy

.PHONY: test
test: unit-test unit-test-receiver integration-test

.PHONY: unit-test
unit-test:
	RUST_BACKTRACE=1 cargo test

.PHONY: unit-test-nocapture
unit-test-nocapture:
	RUST_BACKTRACE=1 cargo test -- --nocapture

.PHONY: unit-test-receiver
unit-test-receiver:
	$(MAKE) -C tests/example-receiver unit-test

.PHONY: integration-test
integration-test: compile-optimized compile-optimized-receiver
	if tests/integration.sh; then echo -n '\a'; else echo -n '\a'; sleep 0.125; echo -n '\a'; fi

compile-optimized-receiver:
	$(MAKE) -C tests/example-receiver compile-optimized

.PHONY: list-code
list-code:
	$(SECRETCLI) query compute list-code

.PHONY: compile _compile
compile: _compile contract.wasm.gz
_compile:
	cargo build --target wasm32-unknown-unknown --locked
	cp ./target/wasm32-unknown-unknown/debug/*.wasm ./contract.wasm

.PHONY: compile-integration _compile-integration
compile-integration: _compile-integration contract.wasm.gz
_compile-integration:
	DWB_CAPACITY=64 BTBE_CAPACITY=64 RUSTFLAGS='-C link-arg=-s' cargo build --features "gas_tracking" --release --target wasm32-unknown-unknown
	@# The following line is not necessary, may work only on linux (extra size optimization)
	wasm-opt -Oz ./target/wasm32-unknown-unknown/release/*.wasm -o ./contract.wasm

.PHONY: compile-optimized _compile-optimized
compile-optimized: _compile-optimized contract.wasm.gz
_compile-optimized:
	RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown
	@# The following line is not necessary, may work only on linux (extra size optimization)
	wasm-opt -Oz ./target/wasm32-unknown-unknown/release/*.wasm -o ./contract.wasm

.PHONY: compile-optimized-reproducible
compile-optimized-reproducible:
	docker run --rm -v "$$(pwd)":/contract \
		--mount type=volume,source="$$(basename "$$(pwd)")_cache",target=/code/target \
		--mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
		ghcr.io/scrtlabs/secret-contract-optimizer:1.0.12

contract.wasm.gz: contract.wasm
	cat ./contract.wasm | gzip -9 > ./contract.wasm.gz

contract.wasm:
	cp ./target/wasm32-unknown-unknown/release/snip20_reference_impl.wasm ./contract.wasm

.PHONY: start-server
start-server: # CTRL+C to stop
	docker run -it --rm \
		-e FAST_BLOCKS=true \
		-p $(SECRET_RPC_PORT):26657 \
		-p $(SECRET_LCD_PORT):1317 \
		-p $(SECRET_GRPC_PORT):9090 \
		-p 5000:5000 \
		-v $$(pwd):/root/code \
		--name secretdev \
		ghcr.io/scrtlabs/localsecret:$(LOCALSECRET_VERSION)

.PHONY: schema
schema:
	cargo run --example schema

.PHONY: clean
clean:
	cargo clean
	rm -f ./contract.wasm ./contract.wasm.gz
	$(MAKE) -C tests/example-receiver clean
