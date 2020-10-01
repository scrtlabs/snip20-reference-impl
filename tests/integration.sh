#!/bin/bash

set -eu
set -o pipefail # If anything in a pipeline fails, the pipe's exit status is a failure
#set -x # Print all commands for debugging

KEY_A='a'
KEY_B='b'
KEY_C='c'
KEY_D='d'
CLI_FLAGS="-y --from $KEY_A"

# This means we don't need to configure the cli since it uses the preconfigured cli in the docker.
# We define this as a function rather than as an alias because it has more flexible expansion behavior.
# In particular, it's not possible to dynamically expand aliases, but `tx_of` dynamically executes whatever
# we specify in its arguments.
function secretcli() {
    docker exec -it secretdev /usr/bin/secretcli "$@"
}

# Just like `echo`, but prints to stderr
function log() {
    echo "$@" >&2
}

function trim_newlines() {
    local input="$1"
    tr --delete '\r\n' <<< "$input"
}

ADDRESS_A="$(trim_newlines "$(secretcli keys show --address "$KEY_A")")"
ADDRESS_B="$(trim_newlines "$(secretcli keys show --address "$KEY_B")")"
ADDRESS_C="$(trim_newlines "$(secretcli keys show --address "$KEY_C")")"
ADDRESS_D="$(trim_newlines "$(secretcli keys show --address "$KEY_D")")"

# Generate a label for a contract with a given code id
# This just adds "contract_" before the code id.
function label_by_id() {
    local id="$1"
    echo "contract_$id"
}

# Keep polling the blockchain until the tx completes.
# The first argument is the tx hash.
# The second argument is a message that will be logged after every failed attempt.
# The tx information will be returned.
function wait_for_tx() {
    local tx_hash="$1"
    local message="$2"
    local result

    # For some reason, secretcli started writing errors to stdout??
    # so we capture the output until we make sure the command succeeded
    until result="$(secretcli query tx "$tx_hash")"; do
        log "$message"
        sleep 1
    done

    echo "$result"
}

# This is a wrapper around `wait_for_tx` that also decrypts the response,
# and returns a nonzero status code if the tx failed
function wait_for_compute_tx() {
    local tx_hash="$1"
    local message="$2"
    local return_value=0
    local result

    result="$(wait_for_tx "$tx_hash" "$message")"
    if jq -e '.logs == null' <<< "$result" > /dev/null; then
        return_value=1
    fi
    secretcli query compute tx "$tx_hash"

    return "$return_value"
}

# If the tx failed, return a nonzero status code.
# The decrypted error or message will be echoed
function check_tx() {
    local tx_hash="$1"
    local result
    local return_value=0

    result="$(secretcli query tx "$tx_hash")"
    if jq -e '.logs == null' <<< "$result" > /dev/null; then
        return_value=1
    fi
    secretcli query compute tx "$tx_hash"

    return "$return_value"
}

# Extract the tx_hash from the output of the command
function tx_of() {
    "$@" | jq -r '.txhash'
}

function upload_code() {
    local tx_hash
    local code_id

    tx_hash="$(tx_of secretcli tx compute store code/contract.wasm.gz $CLI_FLAGS --gas 10000000)"
    code_id="$(
        wait_for_tx "$tx_hash" 'waiting for contract upload' |
            jq -r '.logs[0].events[0].attributes[] | select(.key == "code_id") | .value'
    )"

    log "uploaded contract #$code_id"

    echo "$code_id"
}

function instantiate() {
    local code_id="$1"

    local prng_seed
    prng_seed="$(xxd -ps <<< 'enigma-rocks')"
    local init_msg
    init_msg='{"name":"secret-secret","admin":"'"$ADDRESS_A"'","symbol":"SSCRT","decimals":6,"initial_balances":[],"prng_seed":"'"$prng_seed"'","config":{}}'
    log 'sending init message:'
    log "${init_msg@Q}"

    local tx_hash
    tx_hash="$(tx_of secretcli tx compute instantiate "$code_id" "$init_msg" --label "$(label_by_id "$code_id")" $CLI_FLAGS --gas 10000000)"
    wait_for_compute_tx "$tx_hash" 'waiting for init to complete'
}

function test_1() {
    local label="$1"
}

function test_2() {
    local label="$1"
}

function test_3() {
    local label="$1"
}

function main() {
    log '####-####-####-#### Starting integration tests ####-####-####-####'
    log "secretcli version in the docker image is: $(secretcli version)"

    local code_id
    code_id="$(upload_code)"

    instantiate "$code_id" >&2

    local label
    label="$(label_by_id "$code_id")"

    test_1 "$label"
    test_2 "$label"
    test_3 "$label"

    # If everything else worked, return successful status
    return 0
}

main "$@"
