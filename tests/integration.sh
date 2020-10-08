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
    docker exec secretdev /usr/bin/secretcli "$@"
}

# Just like `echo`, but prints to stderr
function log() {
    echo "$@" >&2
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

declare -A ADDRESS=(
    [a]="$(secretcli keys show --address a)"
    [b]="$(secretcli keys show --address b)"
    [c]="$(secretcli keys show --address c)"
    [d]="$(secretcli keys show --address d)"
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
    # secretcli will only print to stdout when it succeeds
    until result="$(secretcli query tx "$tx_hash" 2>/dev/null)"; do
        log "$message"
        sleep 1
    done

    # log out-of-gas events
    if jq -e '.raw_log | startswith("execute contract failed: Out of gas: ")' <<<"$result" >/dev/null; then
        log "$(jq -r '.raw_log' <<<"$result")"
    fi

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
    decrypted="$(secretcli query compute tx "$tx_hash")"
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

    result="$(secretcli query tx "$tx_hash")"
    if jq -e '.logs == null' <<<"$result" >/dev/null; then
        return_value=1
    fi
    decrypted="$(secretcli query compute tx "$tx_hash")"
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

# Send a compute transaction and return the tx hash.
# All arguments to this function are passed directly to `secretcli tx compute execute`.
function compute_execute() {
    tx_of secretcli tx compute execute "$@"
}

# Send a query to the contract.
# All arguments to this function are passed directly to `secretcli query compute query`.
function compute_query() {
    secretcli query compute query "$@"
}

function upload_code() {
    local directory="$1"
    local tx_hash
    local code_id

    tx_hash="$(tx_of secretcli tx compute store "code/$directory/contract.wasm.gz" ${FROM[a]} --gas 10000000)"
    code_id="$(
        wait_for_tx "$tx_hash" 'waiting for contract upload' |
            jq -r '.logs[0].events[0].attributes[] | select(.key == "code_id") | .value'
    )"

    log "uploaded contract #$code_id"

    echo "$code_id"
}

function instantiate() {
    local code_id="$1"
    local init_msg="$2"

    log 'sending init message:'
    log "${init_msg@Q}"

    local tx_hash
    tx_hash="$(tx_of secretcli tx compute instantiate "$code_id" "$init_msg" --label "$(label_by_id "$code_id")" ${FROM[a]} --gas 10000000)"
    wait_for_tx "$tx_hash" 'waiting for init to complete'
}

# This function uploads and instantiates a contract, and returns the new contract's address
function create_contract() {
    local dir="$1"
    local init_msg="$2"

    local code_id
    code_id="$(upload_code "$dir")"

    local init_result
    init_result="$(instantiate "$code_id" "$init_msg")"
    jq -r '.logs[0].events[0].attributes[] | select(.key == "contract_address") | .value' <<<"$init_result"
}

# Redeem some SCRT from an account
# As you can see, verifying this is happening correctly requires a lot of code
# so I separated it to its own function, because it's used several times.
function redeem() {
    local contract_addr="$1"
    local key="$2"
    local amount="$3"

    local redeem_message
    local tx_hash
    local redeem_tx
    local transfer_attributes
    local redeem_response

    log "redeeming \"$key\""
    redeem_message='{"redeem":{"amount":"'"$amount"'"}}'
    tx_hash="$(compute_execute "$contract_addr" "$redeem_message" ${FROM[$key]} --gas 150000)"
    redeem_tx="$(wait_for_tx "$tx_hash" "waiting for redeem from \"$key\" to process")"
    transfer_attributes="$(jq -r '.logs[0].events[] | select(.type == "transfer") | .attributes' <<<"$redeem_tx")"
    assert_eq "$(jq -r '.[] | select(.key == "recipient") | .value' <<<"$transfer_attributes")" "${ADDRESS[$key]}"
    assert_eq "$(jq -r '.[] | select(.key == "amount") | .value' <<<"$transfer_attributes")" "${amount}uscrt"
    log "redeem response for \"$key\" returned ${amount}uscrt"

    redeem_response="$(data_of check_tx "$tx_hash")"
    assert_eq "$redeem_response" "$(pad_space '{"redeem":{"status":"success"}}')"
    log "redeemed ${amount} from \"$key\" successfully"
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
    local expected_error='{"viewing_key_error":{"msg":"Wrong viewing key for this address or viewing key not set"}}'
    for key in "${KEY[@]}"; do
        log "querying balance for \"$key\" with wrong viewing key"
        balance_query='{"balance":{"address":"'"${ADDRESS[$key]}"'","key":"'"$wrong_key"'"}}'
        result="$(compute_query "$contract_addr" "$balance_query")"
        assert_eq "$result" "$expected_error"
    done

    # Create viewing keys
    local create_viewing_key_message='{"create_viewing_key":{"entropy":"MyPassword123"}}'
    local deposit_response
    for key in "${KEY[@]}"; do
        log "creating viewing key for \"$key\""
        tx_hash="$(compute_execute "$contract_addr" "$create_viewing_key_message" ${FROM[$key]} --gas 1400000)"
        deposit_response="$(data_of wait_for_compute_tx "$tx_hash" "waiting for viewing key for \"$key\" to be created")"
        VK[$key]="$(jq -er '.create_viewing_key.key' <<<"$deposit_response")"
        log "viewing key for \"$key\" set to ${VK[$key]}"
        if [[ "${VK[$key]}" =~ ^api_key_ ]]; then
            log "viewing key \"$key\" seems valid"
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
        log "querying balance for \"$key\" with correct viewing key"
        result="$(compute_query "$contract_addr" "$balance_query")"
        if ! jq -e '.balance.amount | tonumber' <<<"$result" >/dev/null 2>&1; then
            log "Balance query returned unexpected response: ${result@Q}"
            return 1
        fi
    done

    # Change viewing keys
    local vk2_a

    log 'creating new viewing key for "a"'
    tx_hash="$(compute_execute "$contract_addr" "$create_viewing_key_message" ${FROM[a]} --gas 1400000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for viewing key for "a" to be created')"
    vk2_a="$(jq -er '.create_viewing_key.key' <<<"$deposit_response")"
    log "viewing key for \"a\" set to $vk2_a"
    assert_ne "${VK[a]}" "$vk2_a"

    # query balance with old keys. Should fail.
    log 'querying balance for "a" with old viewing key'
    local balance_query_a='{"balance":{"address":"'"${ADDRESS[a]}"'","key":"'"${VK[a]}"'"}}'
    result="$(compute_query "$contract_addr" "$balance_query_a")"
    assert_eq "$result" "$expected_error"

    # query balance with new keys. Should succeed.
    log 'querying balance for "a" with new viewing key'
    balance_query_a='{"balance":{"address":"'"${ADDRESS[a]}"'","key":"'"$vk2_a"'"}}'
    result="$(compute_query "$contract_addr" "$balance_query_a")"
    if ! jq -e '.balance.amount | tonumber' <<<"$result" >/dev/null 2>&1; then
        log "Balance query returned unexpected response: ${result@Q}"
        return 1
    fi

    # Set the vk for "a" to the original vk
    log 'setting the viewing key for "a" back to the first one'
    local set_viewing_key_message='{"set_viewing_key":{"key":"'"${VK[a]}"'"}}'
    tx_hash="$(compute_execute "$contract_addr" "$set_viewing_key_message" ${FROM[a]} --gas 1400000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for viewing key for "a" to be set')"
    assert_eq "$deposit_response" "$(pad_space '{"set_viewing_key":{"status":"success"}}')"

    # try to use the new key - should fail
    log 'querying balance for "a" with new viewing key'
    balance_query_a='{"balance":{"address":"'"${ADDRESS[a]}"'","key":"'"$vk2_a"'"}}'
    result="$(compute_query "$contract_addr" "$balance_query_a")"
    assert_eq "$result" "$expected_error"

    # try to use the old key - should succeed
    log 'querying balance for "a" with old viewing key'
    balance_query_a='{"balance":{"address":"'"${ADDRESS[a]}"'","key":"'"${VK[a]}"'"}}'
    result="$(compute_query "$contract_addr" "$balance_query_a")"
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
        tx_hash="$(compute_execute "$contract_addr" "$deposit_message" --amount "${deposits[$key]}uscrt" ${FROM[$key]} --gas 150000)"
        deposit_response="$(data_of wait_for_compute_tx "$tx_hash" "waiting for deposit to \"$key\" to process")"
        assert_eq "$deposit_response" "$(pad_space '{"deposit":{"status":"success"}}')"
        log "deposited ${deposits[$key]}uscrt to \"$key\" successfully"
    done

    # Query the balances of the accounts and make sure they have the right balances.
    local -A balance_query
    local balance_response
    for key in "${KEY[@]}"; do
        balance_query[$key]='{"balance":{"address":"'"${ADDRESS[$key]}"'","key":"'"${VK[$key]}"'"}}'
        log "querying balance for \"$key\""
        balance_response="$(compute_query "$contract_addr" "${balance_query[$key]}")"
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
        tx_hash="$(compute_execute "$contract_addr" "$redeem_message" ${FROM[$key]} --gas 150000)"
        # Notice the `!` before the command - it is EXPECTED to fail.
        ! redeem_response="$(wait_for_compute_tx "$tx_hash" "waiting for overdraft from \"$key\" to process")"
        log "trying to overdraft from \"$key\" was rejected"
        assert_eq \
            "$(jq -r '.output_error.generic_err.msg' <<<"$redeem_response")" \
            "insufficient funds to redeem: balance=${deposits[$key]}, required=$overdraft"
    done

    # Withdraw Everything
    for key in "${KEY[@]}"; do
        redeem "$contract_addr" "$key" "${deposits[$key]}"
    done

    # Check the balances again. They should all be empty
    for key in "${KEY[@]}"; do
        log "querying balance for \"$key\""
        balance_response="$(compute_query "$contract_addr" "${balance_query[$key]}")"
        log "balance response was: $balance_response"
        assert_eq "$(jq -r '.balance.amount' <<<"$balance_response")" '0'
    done
}

function test_transfer() {
    local contract_addr="$1"

    log_test_header

    local tx_hash

    # Check "a" doesn't have any funds
    log 'querying balance for "a"'
    local balance_query_a='{"balance":{"address":"'"${ADDRESS[a]}"'","key":"'"${VK[a]}"'"}}'
    local balance_response
    balance_response="$(compute_query "$contract_addr" "$balance_query_a")"
    log "balance response was: $balance_response"
    assert_eq "$(jq -r '.balance.amount' <<<"$balance_response")" '0'

    # Check "b" doesn't have any funds
    log 'querying balance for "b"'
    local balance_query_b='{"balance":{"address":"'"${ADDRESS[b]}"'","key":"'"${VK[b]}"'"}}'
    local balance_response
    balance_response="$(compute_query "$contract_addr" "$balance_query_b")"
    log "balance response was: $balance_response"
    assert_eq "$(jq -r '.balance.amount' <<<"$balance_response")" '0'

    # Deposit to "a"
    local deposit_message='{"deposit":{"padding":":::::::::::::::::"}}'
    local deposit_response
    tx_hash="$(compute_execute "$contract_addr" "$deposit_message" --amount '1000000uscrt' ${FROM[a]} --gas 150000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for deposit to "a" to process')"
    assert_eq "$deposit_response" "$(pad_space '{"deposit":{"status":"success"}}')"
    log 'deposited 1000000uscrt to "a" successfully'

    # Try to transfer more than "a" has
    log 'transferring funds from "a" to "b", but more than "a" has'
    local transfer_message='{"transfer":{"recipient":"'"${ADDRESS[b]}"'","amount":"1000001"}}'
    local transfer_response
    tx_hash="$(compute_execute "$contract_addr" "$transfer_message" ${FROM[a]} --gas 150000)"
    # Notice the `!` before the command - it is EXPECTED to fail.
    ! transfer_response="$(wait_for_compute_tx "$tx_hash" 'waiting for transfer from "a" to "b" to process')"
    log "trying to overdraft from \"a\" to transfer to \"b\" was rejected"
    assert_eq \
        "$(jq -r '.output_error.generic_err.msg' <<<"$transfer_response")" \
        "insufficient funds: balance=1000000, required=1000001"

    # Transfer from "a" to "b"
    log 'transferring funds from "a" to "b"'
    local transfer_message='{"transfer":{"recipient":"'"${ADDRESS[b]}"'","amount":"400000"}}'
    local transfer_response
    tx_hash="$(compute_execute "$contract_addr" "$transfer_message" ${FROM[a]} --gas 150000)"
    transfer_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for transfer from "a" to "b" to process')"
    assert_eq "$transfer_response" "$(pad_space '{"transfer":{"status":"success"}}')"

    # Check that "a" has fewer funds
    log 'querying balance for "a"'
    balance_response="$(compute_query "$contract_addr" "$balance_query_a")"
    log "balance response was: $balance_response"
    assert_eq "$(jq -r '.balance.amount' <<<"$balance_response")" '600000'

    # Check that "b" has the funds that "a" deposited
    log 'querying balance for "b"'
    balance_response="$(compute_query "$contract_addr" "$balance_query_b")"
    log "balance response was: $balance_response"
    assert_eq "$(jq -r '.balance.amount' <<<"$balance_response")" '400000'

    # Redeem both accounts
    redeem "$contract_addr" a '600000'
    redeem "$contract_addr" b '400000'
    # Send the funds back
    secretcli tx send b "${ADDRESS[a]}" 400000uscrt -y -b block >/dev/null
}

function create_receiver_contract() {
    local init_msg
    local contract_addr

    init_msg='{"count":0}'
    contract_addr="$(create_contract 'tests/example-receiver' "$init_msg")"

    log "uploaded receiver contract to $contract_addr"
    echo "$contract_addr"
}

# This function exists so that we can reset the state as much as possible between different tests
function redeem_receiver() {
    local receiver_addr="$1"
    local snip20_addr="$2"
    local to_addr="$3"
    local amount="$4"

    local tx_hash
    local redeem_tx
    local transfer_attributes

    log 'fetching snip20 hash'
    local snip20_hash
    snip20_hash="$(secretcli query compute contract-hash "$snip20_addr")"

    local redeem_message='{"redeem":{"addr":"'"$snip20_addr"'","hash":"'"${snip20_hash:2}"'","to":"'"$to_addr"'","amount":"'"$amount"'"}}'
    tx_hash="$(compute_execute "$receiver_addr" "$redeem_message" ${FROM[a]} --gas 300000)"
    redeem_tx="$(wait_for_tx "$tx_hash" "waiting for redeem from receiver at \"$receiver_addr\" to process")"
    log "$redeem_tx"
    transfer_attributes="$(jq -r '.logs[0].events[] | select(.type == "transfer") | .attributes' <<<"$redeem_tx")"
    assert_eq "$(jq -r '.[] | select(.key == "recipient") | .value' <<<"$transfer_attributes")" "$receiver_addr"$'\n'"$to_addr"
    assert_eq "$(jq -r '.[] | select(.key == "amount") | .value' <<<"$transfer_attributes")" "${amount}uscrt"$'\n'"${amount}uscrt"
    log "redeem response for \"$receiver_addr\" returned ${amount}uscrt"
}

function register_receiver() {
    local receiver_addr="$1"
    local snip20_addr="$2"

    local tx_hash

    log 'fetching snip20 hash'
    local snip20_hash
    snip20_hash="$(secretcli query compute contract-hash "$snip20_addr")"

    log 'registering with snip20'
    local register_message='{"register":{"reg_addr":"'"$snip20_addr"'","reg_hash":"'"${snip20_hash:2}"'"}}'
    tx_hash="$(compute_execute "$receiver_addr" "$register_message" ${FROM[a]} --gas 200000)"
    # we throw away the output since we know it's empty
    local register_tx
    register_tx="$(wait_for_compute_tx "$tx_hash" 'Waiting for receiver registration')"
    assert_eq \
        "$(jq -r '.output_log[] | select(.type == "wasm") | .attributes[] | select(.key == "register_status") | .value' <<<"$register_tx")" \
        'success'
    log 'receiver registered successfully'
}

function test_send() {
    local contract_addr="$1"

    log_test_header

    local receiver_addr
    receiver_addr="$(create_receiver_contract)"
#    receiver_addr='secret17k8qt6aqd7eee3fawmtvy4vu6teqx8d7mdm49x'
    register_receiver "$receiver_addr" "$contract_addr"

    local tx_hash

    # Check "a" doesn't have any funds
    log 'querying balance for "a"'
    local balance_query_a='{"balance":{"address":"'"${ADDRESS[a]}"'","key":"'"${VK[a]}"'"}}'
    local balance_response
    balance_response="$(compute_query "$contract_addr" "$balance_query_a")"
    log "balance response was: $balance_response"
    assert_eq "$(jq -r '.balance.amount' <<<"$balance_response")" '0'

    # Check "b" doesn't have any funds
    log 'querying balance for "b"'
    local balance_query_b='{"balance":{"address":"'"${ADDRESS[b]}"'","key":"'"${VK[b]}"'"}}'
    local balance_response
    balance_response="$(compute_query "$contract_addr" "$balance_query_b")"
    log "balance response was: $balance_response"
    assert_eq "$(jq -r '.balance.amount' <<<"$balance_response")" '0'

    # Deposit to "a"
    local deposit_message='{"deposit":{"padding":":::::::::::::::::"}}'
    local deposit_response
    tx_hash="$(compute_execute "$contract_addr" "$deposit_message" --amount '1000000uscrt' ${FROM[a]} --gas 150000)"
    deposit_response="$(data_of wait_for_compute_tx "$tx_hash" 'waiting for deposit to "a" to process')"
    assert_eq "$deposit_response" "$(pad_space '{"deposit":{"status":"success"}}')"
    log 'deposited 1000000uscrt to "a" successfully'

    # Try to send more than "a" has
    log 'sending funds from "a" to "b", but more than "a" has'
    local send_message='{"send":{"recipient":"'"${ADDRESS[b]}"'","amount":"1000001"}}'
    local send_response
    tx_hash="$(compute_execute "$contract_addr" "$send_message" ${FROM[a]} --gas 150000)"
    # Notice the `!` before the command - it is EXPECTED to fail.
    ! send_response="$(wait_for_compute_tx "$tx_hash" 'waiting for send from "a" to "b" to process')"
    log "trying to overdraft from \"a\" to send to \"b\" was rejected"
    assert_eq \
        "$(jq -r '.output_error.generic_err.msg' <<<"$send_response")" \
        "insufficient funds: balance=1000000, required=1000001"

    # Query receiver state before Send
    local receiver_state
    local receiver_state_query='{"get_count":{}}'
    receiver_state="$(compute_query "$receiver_addr" "$receiver_state_query")"
    local original_count
    original_count="$(jq -r '.count' <<<"$receiver_state")"

    # Send from "a" to the receiver with message to the Receiver
    log 'sending funds from "a" to "b", with message to the Receiver'
    local receiver_msg='{"increment":{}}'
    receiver_msg="$(base64 <<<"$receiver_msg")"
    local send_message='{"send":{"recipient":"'"$receiver_addr"'","amount":"400000","msg":"'$receiver_msg'"}}'
    local send_response
    tx_hash="$(compute_execute "$contract_addr" "$send_message" ${FROM[a]} --gas 300000)"
    send_response="$(wait_for_compute_tx "$tx_hash" 'waiting for send from "a" to "b" to process')"
    assert_eq \
        "$(jq -r '.output_log[0].attributes[] | select(.key == "count") | .value' <<<"$send_response")" \
        "$((original_count + 1))"
    log 'received send response'

    # Check that the receiver got the message
    log 'checking whether state was updated in the receiver'
    receiver_state_query='{"get_count":{}}'
    receiver_state="$(compute_query "$receiver_addr" "$receiver_state_query")"
    local new_count
    new_count="$(jq -r '.count' <<<"$receiver_state")"
    assert_eq "$((original_count + 1))" "$new_count"
    log 'receiver contract received the message'

    # Check that "a" has fewer funds
    log 'querying balance for "a"'
    balance_query_a='{"balance":{"address":"'"${ADDRESS[a]}"'","key":"'"${VK[a]}"'"}}'
    balance_response="$(compute_query "$contract_addr" "$balance_query_a")"
    log "balance response was: $balance_response"
    assert_eq "$(jq -r '.balance.amount' <<<"$balance_response")" '600000'

    # redeem both accounts
    redeem "$contract_addr" 'a' '600000'
    redeem_receiver "$receiver_addr" "$contract_addr" "${ADDRESS[a]}" '400000'
}

function main() {
    log '              <####> Starting integration tests <####>'
    log "secretcli version in the docker image is: $(secretcli version)"

    local prng_seed
    prng_seed="$(xxd -ps <<<'enigma-rocks')"
    local init_msg
    init_msg='{"name":"secret-secret","admin":"'"${ADDRESS[a]}"'","symbol":"SSCRT","decimals":6,"initial_balances":[],"prng_seed":"'"$prng_seed"'","config":{}}'
    contract_addr="$(create_contract '.' "$init_msg")"

    # To make testing faster, check the logs and try to reuse the deployed contract and VKs from previous runs.
    # Remember to comment out the contract deployment and `test_viewing_key` if you do.
#    local contract_addr='secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg'
#    VK[a]='api_key_vcipODMLbckCJpjuPXEzId0u2dvN1DaXG/Qxzj+GG7c='
#    VK[b]='api_key_Yg0giN1v3mB+j/+7qssxPqZ1fCKDcbrwZILQvb6xyok='
#    VK[c]='api_key_BpGAyiNpB2xZQQQXD0K0ScYY6o12b1TzoF9dIRnIfgM='
#    VK[d]='api_key_Zs0LqlZ4AtYJ/kulyB6WDy2K3sW181/sLSMk1LmLJq8='

    log "contract address: $contract_addr"

    # This first test also sets the `VK[*]` global variables that are used in the other tests
    test_viewing_key "$contract_addr"
    test_deposit "$contract_addr"
    test_transfer "$contract_addr"
    test_send "$contract_addr"

    log 'Tests completed successfully'

    # If everything else worked, return successful status
    return 0
}

main "$@"
