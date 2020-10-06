#!/bin/bash

set -eu
set -o pipefail # If anything in a pipeline fails, the pipe's exit status is a failure
#set -x # Print all commands for debugging

declare -a KEY=(a b c d)

declare -A FROM=(
    [a]='-y --from a'
    [b]='-y --from b'
    [c]='-y --from c'
    [d]='-y --from d'
)

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

declare -A ADDRESS=(
    [a]="$(trim_newlines "$(secretcli keys show --address a)")"
    [b]="$(trim_newlines "$(secretcli keys show --address b)")"
    [c]="$(trim_newlines "$(secretcli keys show --address c)")"
    [d]="$(trim_newlines "$(secretcli keys show --address d)")"
)

declare -A VK=([a]='' [b]='' [c]='' [d]='')

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
    decrypted="$(log_if_err secretcli query compute tx "$tx_hash")"
    log "$decrypted"
    echo "$decrypted"

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

    tx_hash="$(tx_of secretcli tx compute store code/contract.wasm.gz ${FROM[a]} --gas 10000000)"
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
    init_msg='{"name":"secret-secret","admin":"'"${ADDRESS[a]}"'","symbol":"SSCRT","decimals":6,"initial_balances":[],"prng_seed":"'"$prng_seed"'","config":{}}'
    log 'sending init message:'
    log "${init_msg@Q}"

    local tx_hash
    tx_hash="$(tx_of secretcli tx compute instantiate "$code_id" "$init_msg" --label "$(label_by_id "$code_id")" ${FROM[a]} --gas 10000000)"
    wait_for_tx "$tx_hash" 'waiting for init to complete'
}

function log_test_header() {
    log " # Starting ${FUNCNAME[1]}"
}

function test_viewing_key() {
    local contract_addr="$1"

    log_test_header

    # common variables
    local result
    local tx_hash

    # query balance. Should fail.
    local wrong_key
    wrong_key="$(xxd -ps <<<'wrong-key')"
    local balance_query
    local expected_error=$'{"viewing_key_error":{"msg":"Wrong viewing key for this address or viewing key not set"}}\r'
    for key in "${KEY[@]}"; do
        log $"querying balance for \"$key\" with wrong viewing key"
        balance_query='{"balance":{"address":"'"${ADDRESS[$key]}"'","key":"'"$wrong_key"'"}}'
        result="$(log_if_err secretcli query compute query "$contract_addr" "$balance_query")"
        assert_eq "$result" "$expected_error"
    done

    # Create viewing keys
    local create_viewing_key_message='{"create_viewing_key":{"entropy":"MyPassword123"}}'
    local deposit_response
    for key in "${KEY[@]}"; do
        log $"creating viewing key for \"$key\""
        tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$create_viewing_key_message" ${FROM[$key]} --gas 1400000)"
        deposit_response="$(data_of wait_for_compute_tx "$tx_hash" $"waiting for viewing key for \"$key\" to be created")"
        VK[$key]="$(jq -er '.create_viewing_key.key' <<<"$deposit_response")"
        log $"viewing key for \"$key\" set to ${VK[$key]}"
        if [[ "${VK[$key]}" =~ ^api_key_ ]]; then
            log $"viewing key \"$key\" seems valid"
        else
            log 'viewing key is invalid'
            return 1
        fi
    done

    # Check that all viewing keys are different despite using the same entropy
    assert_ne "${VK[a]}" "${VK[b]}"
    assert_ne "${VK[b]}" "${VK[c]}"
    assert_ne "${VK[c]}" "${VK[d]}"

    # query balance. Should succeed.
    local balance_query
    for key in "${KEY[@]}"; do
        balance_query='{"balance":{"address":"'"${ADDRESS[$key]}"'","key":"'"${VK[$key]}"'"}}'
        log $"querying balance for \"$key\" with correct viewing key"
        result="$(log_if_err secretcli query compute query "$contract_addr" "$balance_query")"
        if ! jq -e '.balance.amount | tonumber' <<<"$result" >/dev/null 2>&1; then
            log "Balance query returned unexpected response: ${result@Q}"
            return 1
        fi
    done

    # Change viewing keys
    local vk2_a

    log 'creating new viewing key for "a"'
    tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$create_viewing_key_message" ${FROM[a]} --gas 1400000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for viewing key for "a" to be created')"
    vk2_a="$(jq -er '.create_viewing_key.key' <<<"$deposit_response")"
    log $"viewing key for \"a\" set to $vk2_a"
    assert_ne "${VK[a]}" "$vk2_a"

    # query balance with old keys. Should fail.
    log 'querying balance for "a" with old viewing key'
    local balance_query_a='{"balance":{"address":"'"${ADDRESS[a]}"'","key":"'"${VK[a]}"'"}}'
    result="$(log_if_err secretcli query compute query "$contract_addr" "$balance_query_a")"
    assert_eq "$result" "$expected_error"

    # query balance with new keys. Should succeed.
    log 'querying balance for "a" with new viewing key'
    balance_query_a='{"balance":{"address":"'"${ADDRESS[a]}"'","key":"'"$vk2_a"'"}}'
    result="$(log_if_err secretcli query compute query "$contract_addr" "$balance_query_a")"
    if ! jq -e '.balance.amount | tonumber' <<<"$result" >/dev/null 2>&1; then
        log "Balance query returned unexpected response: ${result@Q}"
        return 1
    fi

    # Set the vk for "a" to the original vk
    log 'setting the viewing key for "a" back to the first one'
    local set_viewing_key_message='{"set_viewing_key":{"key":"'"${VK[a]}"'"}}'
    tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$set_viewing_key_message" ${FROM[a]} --gas 1400000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for viewing key for "a" to be set')"
    assert_eq "$deposit_response" "$(pad_space '{"set_viewing_key":{"status":"success"}}')"

    # try to use the new key - should fail
    log 'querying balance for "a" with new viewing key'
    balance_query_a='{"balance":{"address":"'"${ADDRESS[a]}"'","key":"'"$vk2_a"'"}}'
    result="$(log_if_err secretcli query compute query "$contract_addr" "$balance_query_a")"
    assert_eq "$result" "$expected_error"

    # try to use the old key - should succeed
    log 'querying balance for "a" with old viewing key'
    balance_query_a='{"balance":{"address":"'"${ADDRESS[a]}"'","key":"'"${VK[a]}"'"}}'
    result="$(log_if_err secretcli query compute query "$contract_addr" "$balance_query_a")"
    if ! jq -e '.balance.amount | tonumber' <<<"$result" >/dev/null 2>&1; then
        log "Balance query returned unexpected response: ${result@Q}"
        return 1
    fi
}

function test_deposit() {
    local contract_addr="$1"

    log_test_header

    local tx_hash

    local deposit_message='{"deposit":{"padding":":::::::::::::::::"}}'
    local deposit_response
    local -A deposits=([a]='1000000' [b]='2000000' [c]='3000000' [d]='4000000')
    for key in "${KEY[@]}"; do
        tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$deposit_message" --amount "${deposits[$key]}uscrt" ${FROM[$key]} --gas 150000)"
        deposit_response="$(data_of wait_for_compute_tx "$tx_hash" "waiting for deposit to \"$key\" to process")"
        assert_eq "$deposit_response" "$(pad_space '{"deposit":{"status":"success"}}')"
        log "deposited ${deposits[$key]}uscrt to \"$key\" successfully"
    done

    # Query the balances of the accounts and make sure they have the right balances.
    local -A balance_query
    local balance_response
    for key in "${KEY[@]}"; do
        balance_query[$key]='{"balance":{"address":"'"${ADDRESS[$key]}"'","key":"'"${VK[$key]}"'"}}'
        log $"querying balance for \"$key\""
        balance_response="$(log_if_err secretcli query compute query "$contract_addr" "${balance_query[$key]}")"
        log "balance response was: $balance_response"
        assert_eq "$(jq -r '.balance.amount' <<<"$balance_response")" "${deposits[$key]}"
    done

    # Try to overdraft
    local redeem_message
    local overdraft
    local redeem_response
    for key in "${KEY[@]}"; do
        overdraft="$((deposits[$key] + 1))"
        redeem_message='{"redeem":{"amount":"'"$overdraft"'"}}'
        tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$redeem_message" ${FROM[$key]} --gas 150000)"
        # Notice the `!` before the command - it is EXPECTED to fail.
        ! redeem_response="$(wait_for_compute_tx "$tx_hash" $"waiting for overdraft from \"$key\" to process")"
        log "trying to overdraft from \"$key\" was rejected"
        assert_eq \
            "$(jq -r '.output_error.generic_err.msg' <<<"$redeem_response")" \
            "insufficient funds to redeem: balance=${deposits[$key]}, required=$overdraft"
    done

    # Withdraw Everything
    local redeem_message
    local redeem_tx
    local transfer_attributes
    local redeem_response
    for key in "${KEY[@]}"; do
        redeem_message='{"redeem":{"amount":"'"${deposits[$key]}"'"}}'
        tx_hash="$(tx_of secretcli tx compute execute "$contract_addr" "$redeem_message" ${FROM[$key]} --gas 150000)"
        redeem_tx="$(wait_for_tx "$tx_hash" $"waiting for redeem from \"$key\" to process")"
        transfer_attributes="$(jq -r '.logs[0].events[] | select(.type == "transfer") | .attributes' <<<"$redeem_tx")"
        assert_eq "$(jq -r '.[] | select(.key == "recipient") | .value' <<<"$transfer_attributes")" "${ADDRESS[$key]}"
        assert_eq "$(jq -r '.[] | select(.key == "amount") | .value' <<<"$transfer_attributes")" "${deposits[$key]}uscrt"
        log "redeem response for \"$key\" returned ${deposits[$key]}uscrt"
        redeem_response="$(data_of check_tx "$tx_hash")"
        assert_eq "$redeem_response" "$(pad_space '{"redeem":{"status":"success"}}')"
        log "redeemed ${deposits[$key]} from \"$key\" successfully"
    done

    # Check the balances again. They should all be empty
    for key in "${KEY[@]}"; do
        log $"querying balance for \"$key\""
        balance_response="$(log_if_err secretcli query compute query "$contract_addr" "${balance_query[$key]}")"
        log "balance response was: $balance_response"
        assert_eq "$(jq -r '.balance.amount' <<<"$balance_response")" '0'
    done
}

function test_send() {
    local contract_addr="$1"

    log_test_header

    # Deposit to "a"
    # Check "b" doesn't have any funds
    # Send from "a" to "b"
    # Check that "b" has the funds that "a" deposited
}

function test_transfer() {
    local contract_addr="$1"

    log_test_header

    # Deploy C2
    # Deposit to "a"
    # Check "b" doesn't have any funds
    # Transfer from "a" to "b" and sent to C2
    # Check that "b" has the funds that "a" deposited
    # Check that C2 received the message
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
    contract_addr="$(jq -r '.logs[0].events[0].attributes[] | select(.key == "contract_address") | .value' <<<"$init_result")"
    log "contract address: $contract_addr"

    # This first test also sets the `VK_*` global variables that are used in the other tests
    test_viewing_key "$contract_addr"
    test_deposit "$contract_addr"
    test_send "$contract_addr"
    test_transfer "$contract_addr"
    # test_2 "$contract_addr"
    # test_3 "$contract_addr"

    log 'Tests completed successfully'

    # If everything else worked, return successful status
    return 0
}

main "$@"
