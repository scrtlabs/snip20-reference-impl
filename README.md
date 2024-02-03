# SNIP-20 Reference Implementation

This is an implementation of a [SNIP-20](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md), [SNIP-21](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-21.md), [SNIP-22](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-22.md), [SNIP-23](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-23.md), [SNIP-24](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-24.md), [SNIP-25](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-25.md) and [SNIP-26](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-26.md) compliant token contract.

> **Note:**
> The master branch contains new features not covered by officially-released SNIPs and may be subject to change. When releasing a token on mainnet, we recommend you start with a [tagged release](https://github.com/scrtlabs/snip20-reference-impl/tags) to ensure compatibility with SNIP standards.

At the time of token creation you may configure:
* Public Total Supply:  If you enable this, the token's total supply will be displayed whenever a TokenInfo query is performed.  DEFAULT: false
* Enable Deposit: If you enable this, you will be able to convert from SCRT to the token.*  DEFAULT: false
* Enable Redeem: If you enable this, you will be able to redeem your token for SCRT.*  It should be noted that if you have redeem enabled, but deposit disabled, all redeem attempts will fail unless someone has sent SCRT to the token contract.  DEFAULT: false
* Enable Mint: If you enable this, any address in the list of minters will be able to mint new tokens.  The admin address is the default minter, but can use the set/add/remove_minters functions to change the list of approved minting addresses.  DEFAULT: false
* Enable Burn: If you enable this, addresses will be able to burn tokens.  DEFAULT: false


\*:The conversion rate will be 1 uscrt for 1 minimum denomination of the token.  This means that if your token has 6 decimal places, it will convert 1:1 with SCRT.  If your token has 10 decimal places, it will have an exchange rate of 10000 SCRT for 1 token.  If your token has 3 decimal places, it will have an exchange rate of 1000 tokens for 1 SCRT.  You can use the exchange_rate query to view the exchange rate for the token.  The query response will display either how many tokens are worth 1 SCRT, or how many SCRT are worth 1 token.  That is, the response lists the symbol of the coin that has less value (either SCRT or the token), and the number of those coins that are worth 1 of the other.

## Usage examples:

To create a new token:

```secretcli tx compute instantiate <code-id> '{"name":"<your_token_name>","symbol":"<your_token_symbol>","admin":"<optional_admin_address_defaults_to_the_from_address>","decimals":<number_of_decimals>,"initial_balances":[{"address":"<address1>","amount":"<amount_for_address1>"}],"prng_seed":"<base64_encoded_string>","config":{"public_total_supply":<true_or_false>,"enable_deposit":<true_or_false>,"enable_redeem":<true_or_false>,"enable_mint":<true_or_false>,"enable_burn":<true_or_false>}}' --label <token_label> --from <account>```

The `admin` field is optional and will default to the "--from" address if you do not specify it.  The `initial_balances` field is optional, and you can specify as many addresses/balances as you like.  The `config` field as well as every field in the `config` is optional.  Any `config` fields not specified will default to `false`.

To deposit: ***(This is public)***

```secretcli tx compute execute <contract-address> '{"deposit": {}}' --amount 1000000uscrt --from <account>``` 

To send SSCRT:

```secretcli tx compute execute <contract-address> '{"transfer": {"recipient": "<destination_address>", "amount": "<amount_to_send>"}}' --from <account>```

To set your viewing key: 

```secretcli tx compute execute <contract-address> '{"create_viewing_key": {"entropy": "<random_phrase>"}}' --from <account>```

To check your balance:

```secretcli q compute query <contract-address> '{"balance": {"address":"<your_address>", "key":"your_viewing_key"}}'```

To view your transfer history:

```secretcli q compute query <contract-address> '{"transfer_history": {"address": "<your_address>", "key": "<your_viewing_key>", "page": <optional_page_number>, "page_size": <number_of_transactions_to_return>, "should_filter_decoys":<should_filter_out_decoys_and_break_paging_or_not>}}'```

To view your transaction history:

```secretcli q compute query <contract-address> '{"transaction_history": {"address": "<your_address>", "key": "<your_viewing_key>", "page": <optional_page_number>, "page_size": <number_of_transactions_to_return>, "should_filter_decoys":<should_filter_out_decoys_and_break_paging_or_not>}}'```

To withdraw: ***(This is public)***

```secretcli tx compute execute <contract-address> '{"redeem": {"amount": "<amount_in_smallest_denom_of_token>"}}' --from <account>```

To view the token contract's configuration:

```secretcli q compute query <contract-address> '{"token_config": {}}'```

To view the deposit/redeem exchange rate:

```secretcli q compute query <contract-address> '{"exchange_rate": {}}'```


## Troubleshooting 

All transactions are encrypted, so if you want to see the error returned by a failed transaction, you need to use the command

`secretcli q compute tx <TX_HASH>`

# SNIP 25 Security Update

## Security Changes
1. Implemented the ability to have decoy addresses for every operation that access account's balance
2. Converted every add operation related to account's balance and total supply
3. Started using u128 instead of Uint128

## Decoys
### Transaction That Support Decoys
1. Redeem
2. Deposit
3. Transfer
4. TransferFrom
5. Send
6. SendFrom
7. Burn
8. BurnFrom
9. Mint
10. BatchTransfer - For every action (The strength of the decoys will be the minimal strength of all of the actions)
11. BatchSend - For every action (The strength of the decoys will be the minimal strength of all of the actions)
12. BatchTransferFrom - For every action (The strength of the decoys will be the minimal strength of all of the actions)
13. BatchSendFrom - For every action (The strength of the decoys will be the minimal strength of all of the actions)
14. BatchMint - For every action (The strength of the decoys will be the minimal strength of all of the actions)
15. BatchBurnFrom - For every action (The strength of the decoys will be the minimal strength of all of the actions)

### Example
```secretcli tx compute execute <contract-address> '{"transfer":{"recipient":"<address>","amount":"<amount>", "entropy":"<base64_encoded_entropy>", "decoys":<[addresses_list]>}}' --from <account>```

## Future Work
| Topic | Immediate-term solution | Medium-term solution | Long-term solution |
| --- | --- | --- | --- |
| Receiver privacy | Decoys - offer limited privacy, since it depends a lot on how you choose decoys. There’s probably no way to select decoys effectively enough, and thus it only makes it a bit harder but effectively doesn’t provide receiver privacy to a sophisticated long-term attacker | Some sort of bucketing? - still no clear path forward| ORAM? - still no clear path forward |
| Transfer amount privacy - subtractions (Transfer/Send/Burn) | None | None | Merkle proofs for storage reads - will make it very difficult to simulate transactions and play with storage. |

# SNIP 25 Other Updates

## All Allowances
Adds the ability for an owner to query for all allowances they have given out, as well as for a spender to query for all allowances they have received.

## Queries

### AllowancesGiven

This query MUST be authenticated.

Returns the list of allowances given out by the current account as an owner, as well as the total count of allowances given out.

Results SHOULD be paginated. Results MUST be sorted in reverse chronological order by the datetime at which the allowance was first created (i.e., order is not determined by expiration, nor by last modified).

#### Request

| Name | Type | Description | optional |
| ---- | ---- | ----------- | -------- |
| [with_permit].query.allowances_given.owner | string | Account from which tokens are allowed to be taken | no |
| [with_permit].query.allowances_given.page_size | number | Number of allowances to return, starting from the latest. i.e. n=1 will return only the latest allowance | no |
| [with_permit].query.allowances_given.page | number | Defaults to 0. Specifying a positive number will skip page * page_size txs from the start. | yes |

#### Response
```json
{
  "allowances_given": {
    "owner": "<address>",
    "allowances": [
      {
        "spender": "<address>",
        "allowance": "Uint128",
        "expiration": 1234,
      },
      { "...": "..." }
    ],
    "count": 200
  }
}
```

### AllowancesReceived

This query MUST be authenticated.

Returns the list of allowances given to the current account as a spender, as well as the total count of allowances received.

Results SHOULD be paginated. Results MUST be sorted in reverse chronological order by the datetime at which the allowance was first created (i.e., order is not determined by expiration).

#### Request

| Name | Type | Description | optional |
| ---- | ---- | ----------- | -------- |
| [with_permit.]query.allowances_received.spender | string | Account which is allowed to spend tokens on behalf of the owner | no |
| [with_permit.]query.allowances_received.page_size	| number | Number of allowances to return, starting from the latest. i.e. n=1 will return only the latest allowance | no |
| [with_permit.]query.allowances_received.page | number | Defaults to 0. Specifying a positive number will skip page * page_size txs from the start. | yes |

#### Response

```json
{
  "allowances_received": {
    "spender": "<address>",
    "allowances": [
      {
        "owner": "<address>",
        "allowance": "Uint128",
        "expiration": 1234,
      },
      { "...": "..." }
    ],
    "count": 200
  }
}
```
