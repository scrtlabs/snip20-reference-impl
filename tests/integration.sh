#!/bin/bash

set -eu
set -o pipefail # If anything in a pipeline fails, the pipe's exit status is a failure
#set -x # Print all commands for debugging

KEY_A='a'
KEY_B='b'
KEY_C='c'
KEY_D='d'

FROM_A="-y --from $KEY_A"
FROM_B="-y --from $KEY_B"
FROM_C="-y --from $KEY_C"
FROM_D="-y --from $KEY_D"

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
    tr --delete '\r\n' <<<"$input"
}

# Pad the string in the first argument to 256 bytes, using spaces
function pad_space() {
    printf '%-256s' "$1"
}

function assert_eq() {
    local left="$1"
    local right="$2"
    local message

    if [ -z ${3+x} ]; then
        message="assertion failed - both sides differ. left: ${left@Q}, right: ${right@Q}"
    else
        message="$3"
    fi

    if [[ "$left" != "$right" ]]; then
        log "$message"
        return 1
    fi

    return 0
}

function assert_ne() {
    local left="$1"
    local right="$2"
    local message

    if [ -z ${3+x} ]; then
        message="assertion failed - both sides are equal. left: ${left@Q}, right: ${right@Q}"
    else
        message="$3"
    fi

    if [[ "$left" == "$right" ]]; then
        log "$message"
        return 1
    fi

    return 0
}

# If the command described in the arguments fails, and prints to stdout,
# write the command output to stderr
function log_if_err() {
    local output

    # If the command succeeded
    if ! output="$("$@")"; then
        # if the output is not empty
        if [ -n "${output:+x}" ]; then
            log "$output"
        fi
        return 1
    fi
    echo "$output"
    return 0
}

ADDRESS_A="$(trim_newlines "$(secretcli keys show --address "$KEY_A")")"
ADDRESS_B="$(trim_newlines "$(secretcli keys show --address "$KEY_B")")"
ADDRESS_C="$(trim_newlines "$(secretcli keys show --address "$KEY_C")")"
ADDRESS_D="$(trim_newlines "$(secretcli keys show --address "$KEY_D")")"

VK_A=''
VK_B=''
VK_C=''
VK_D=''

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

    log "waiting on tx: $tx_hash"
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
    local decrypted

    result="$(wait_for_tx "$tx_hash" "$message")"
    # log "$result"
    if jq -e '.logs == null' <<<"$result" >/dev/null; then
        return_value=1
    fi
    decrypted="$(log_if_err secretcli query compute tx "$tx_hash")"
    log "$decrypted"
    echo "$decrypted"

    return "$return_value"
}

# If the tx failed, return a nonzero status code.
# The decrypted error or message will be echoed
function check_tx() {
    local tx_hash="$1"
    local result
    local return_value=0

    result="$(log_if_err secretcli query tx "$tx_hash")"
    if jq -e '.logs == null' <<<"$result" >/dev/null; then
        return_value=1
    fi
    secretcli query compute tx "$tx_hash"

    return "$return_value"
}

# Extract the tx_hash from the output of the command
function tx_of() {
    "$@" | jq -r '.txhash'
}

# Extract the output_data_as_string from the output of the command
function data_of() {
    "$@" | jq -r '.output_data_as_string'
}

function upload_code() {
    local tx_hash
    local code_id

    tx_hash="$(tx_of secretcli tx compute store code/contract.wasm.gz $FROM_A --gas 10000000)"
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
    prng_seed="$(xxd -ps <<<'enigma-rocks')"
    local init_msg
    init_msg='{"name":"secret-secret","admin":"'"$ADDRESS_A"'","symbol":"SSCRT","decimals":6,"initial_balances":[],"prng_seed":"'"$prng_seed"'","config":{}}'
    log 'sending init message:'
    log "${init_msg@Q}"

    local tx_hash
    tx_hash="$(tx_of secretcli tx compute instantiate "$code_id" "$init_msg" --label "$(label_by_id "$code_id")" $FROM_A --gas 10000000)"
    wait_for_tx "$tx_hash" 'waiting for init to complete'
}

function log_test_header() {
    log "# Starting ${FUNCNAME[1]}"
}

function test_viewing_key() {
    local contract_addr="$1"

    log_test_header

    local wrong_key
    wrong_key="$(xxd -ps <<<'wrong-key')"
    local balance_query_a='{"balance":{"address":"'"$ADDRESS_A"'","key":"'"$wrong_key"'"}}'
    local balance_query_b='{"balance":{"address":"'"$ADDRESS_B"'","key":"'"$wrong_key"'"}}'
    local balance_query_c='{"balance":{"address":"'"$ADDRESS_C"'","key":"'"$wrong_key"'"}}'
    local balance_query_d='{"balance":{"address":"'"$ADDRESS_D"'","key":"'"$wrong_key"'"}}'

    local result

    # query balance. Should fail.
    local expected_error=$'{"viewing_key_error":{"msg":"Wrong viewing key for this address or viewing key not set"}}\r'

    log 'querying balance for "a" with wrong viewing key'
    result="$(log_if_err secretcli query compute query "${contract_addr}" "$balance_query_a")"
    assert_eq "$result" "$expected_error"

    log 'querying balance for "b" with wrong viewing key'
    result="$(log_if_err secretcli query compute query "${contract_addr}" "$balance_query_b")"
    assert_eq "$result" "$expected_error"

    log 'querying balance for "c" with wrong viewing key'
    result="$(log_if_err secretcli query compute query "${contract_addr}" "$balance_query_c")"
    assert_eq "$result" "$expected_error"

    log 'querying balance for "d" with wrong viewing key'
    result="$(log_if_err secretcli query compute query "${contract_addr}" "$balance_query_d")"
    assert_eq "$result" "$expected_error"

    # Create viewing keys
    local create_viewing_key_message='{"create_viewing_key":{"entropy":"MyPassword123"}}'
    local vk_a
    local vk_b
    local vk_c
    local vk_d

    log 'creating viewing key for "a"'
    tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$create_viewing_key_message" $FROM_A --gas 1400000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for viewing key to be created')"
    vk_a="$(jq -er '.create_viewing_key.key' <<<"$deposit_response")"
    log $"viewing key for \"a\" set to $vk_a"

    log 'creating viewing key for "b"'
    tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$create_viewing_key_message" $FROM_B --gas 1400000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for viewing key to be created')"
    vk_b="$(jq -er '.create_viewing_key.key' <<<"$deposit_response")"
    log $"viewing key for \"b\" set to $vk_b"

    log 'creating viewing key for "c"'
    tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$create_viewing_key_message" $FROM_C --gas 1400000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for viewing key to be created')"
    vk_c="$(jq -er '.create_viewing_key.key' <<<"$deposit_response")"
    log $"viewing key for \"c\" set to $vk_c"

    log 'creating viewing key for "d"'
    tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$create_viewing_key_message" $FROM_D --gas 1400000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for viewing key to be created')"
    vk_d="$(jq -er '.create_viewing_key.key' <<<"$deposit_response")"
    log $"viewing key for \"d\" set to $vk_d"

    # Check that all viewing keys are different despite using the same entropy
    assert_ne "vk_a" "vk_b"
    assert_ne "vk_b" "vk_c"
    assert_ne "vk_c" "vk_d"

    # query balance. Should succeed.
    balance_query_a='{"balance":{"address":"'"$ADDRESS_A"'","key":"'"$vk_a"'"}}'
    balance_query_b='{"balance":{"address":"'"$ADDRESS_B"'","key":"'"$vk_b"'"}}'
    balance_query_c='{"balance":{"address":"'"$ADDRESS_C"'","key":"'"$vk_c"'"}}'
    balance_query_d='{"balance":{"address":"'"$ADDRESS_D"'","key":"'"$vk_d"'"}}'

    log 'querying balance for "a" with correct viewing key'
    result="$(log_if_err secretcli query compute query "${contract_addr}" "$balance_query_a")"
    if ! jq -e '.balance.amount | tonumber' <<<"$result" >/dev/null 2>&1; then
        log "Balance query returned unexpected response: ${result@Q}"
        return 1
    fi

    log 'querying balance for "b" with correct viewing key'
    result="$(log_if_err secretcli query compute query "${contract_addr}" "$balance_query_b")"
    if ! jq -e '.balance.amount | tonumber' <<<"$result" >/dev/null 2>&1; then
        log "Balance query returned unexpected response: ${result@Q}"
        return 1
    fi

    log 'querying balance for "c" with correct viewing key'
    result="$(log_if_err secretcli query compute query "${contract_addr}" "$balance_query_c")"
    if ! jq -e '.balance.amount | tonumber' <<<"$result" >/dev/null 2>&1; then
        log "Balance query returned unexpected response: ${result@Q}"
        return 1
    fi

    log 'querying balance for "d" with correct viewing key'
    result="$(log_if_err secretcli query compute query "${contract_addr}" "$balance_query_d")"
    if ! jq -e '.balance.amount | tonumber' <<<"$result" >/dev/null 2>&1; then
        log "Balance query returned unexpected response: ${result@Q}"
        return 1
    fi

    # Change viewing keys
    local vk2_a

    log 'creating new viewing key for "a"'
    tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$create_viewing_key_message" $FROM_A --gas 1400000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for viewing key to be created')"
    vk2_a="$(jq -er '.create_viewing_key.key' <<<"$deposit_response")"
    log $"viewing key for \"a\" set to $vk2_a"
    assert_ne "$vk_a" "$vk2_a"

    # query balance with old keys. Should fail.
    balance_query_a='{"balance":{"address":"'"$ADDRESS_A"'","key":"'"$vk_a"'"}}'

    log 'querying balance for "a" with old viewing key'
    result="$(log_if_err secretcli query compute query "${contract_addr}" "$balance_query_a")"
    assert_eq "$result" "$expected_error"

    # query balance with new keys. Should succeed.
    balance_query_a='{"balance":{"address":"'"$ADDRESS_A"'","key":"'"$vk2_a"'"}}'

    log 'querying balance for "a" with new viewing key'
    result="$(log_if_err secretcli query compute query "${contract_addr}" "$balance_query_a")"
    if ! jq -e '.balance.amount | tonumber' <<<"$result" >/dev/null 2>&1; then
        log "Balance query returned unexpected response: ${result@Q}"
        return 1
    fi

    # Set the vk for "a" to the original vk
    local set_viewing_key_message='{"set_viewing_key":{"key":"'"$vk_a"'"}}'

    log 'setting the viewing key for "a" back to the first one'
    tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$set_viewing_key_message" $FROM_A --gas 1400000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for viewing key to be set')"
    assert_eq "$deposit_response" "$(pad_space '{"set_viewing_key":{"status":"success"}}')"

    # try to use the new key - should fail
    balance_query_a='{"balance":{"address":"'"$ADDRESS_A"'","key":"'"$vk2_a"'"}}'

    log 'querying balance for "a" with new viewing key'
    result="$(log_if_err secretcli query compute query "${contract_addr}" "$balance_query_a")"
    assert_eq "$result" "$expected_error"

    # try to use the old key - should succeed
    balance_query_a='{"balance":{"address":"'"$ADDRESS_A"'","key":"'"$vk_a"'"}}'

    log 'querying balance for "a" with old viewing key'
    result="$(log_if_err secretcli query compute query "${contract_addr}" "$balance_query_a")"
    if ! jq -e '.balance.amount | tonumber' <<<"$result" >/dev/null 2>&1; then
        log "Balance query returned unexpected response: ${result@Q}"
        return 1
    fi

    # Save the VKs configured in this test to the global environment
    VK_A="$vk_a"
    VK_B="$vk_b"
    VK_C="$vk_c"
    VK_D="$vk_d"
}

function test_deposit() {
    local contract_addr="$1"

    log_test_header

    local deposit_response
    local message='{"deposit":{"padding":":::::::::::::::::"}}'

    # Deposit 1SCRT to A
    tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$message" --amount 1000000uscrt $FROM_A --gas 150000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for deposit to process')"
    log "${deposit_response@Q}"
    assert_eq "$deposit_response" "$(pad_space '{"deposit":{"status":"success"}}')" 'Unexpected Response'

    # Deposit 2SCRT to B
    tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$message" --amount 2000000uscrt $FROM_B --gas 150000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for deposit to process')"
    log "${deposit_response@Q}"
    assert_eq "$deposit_response" "$(pad_space '{"deposit":{"status":"success"}}')" 'Unexpected Response'

    # Deposit 3SCRT to C
    tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$message" --amount 3000000uscrt $FROM_C --gas 150000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for deposit to process')"
    log "${deposit_response@Q}"
    assert_eq "$deposit_response" "$(pad_space '{"deposit":{"status":"success"}}')" 'Unexpected Response'

    # Deposit 4SCRT to D
    tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$message" --amount 4000000uscrt $FROM_D --gas 150000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for deposit to process')"
    log "${deposit_response@Q}"
    assert_eq "$deposit_response" "$(pad_space '{"deposit":{"status":"success"}}')" 'Unexpected Response'

}

function test_2() {
    local contract_addr="$1"

    log_test_header
}

function test_3() {
    local contract_addr="$1"

    log_test_header
}

function main() {
    log '####-####-####-#### Starting integration tests ####-####-####-####'
    log "secretcli version in the docker image is: $(secretcli version)"

    local code_id
    code_id="$(upload_code)"

    local init_result
    init_result="$(instantiate "$code_id")"
    local contract_addr
    contract_addr="$(jq -r '.logs[0].events[0].attributes[] | select(.key == "contract_address") | .value' <<< "$init_result")"
    log "contract address: $contract_addr"

    # This first test also sets the `VK_*` global variables that are used in the other tests
    test_viewing_key "$contract_addr"
    test_deposit "$contract_addr"
    # test_2 "$contract_addr"
    # test_3 "$contract_addr"

    log 'Tests completed successfully'

    # If everything else worked, return successful status
    return 0
}

main "$@"
