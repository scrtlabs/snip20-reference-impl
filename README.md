# SNIP-20 Reference Implementation

This is an implementation of a [SNIP-20](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md), [SNIP-21](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-21.md), [SNIP-22](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-22.md), [SNIP-23](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-23.md), [SNIP-24](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-24.md), [~~SNIP-25~~](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-25.md), [SNIP-26](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-26.md), [~~SNIP-50~~](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-50.md) and [SNIP-52](https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-52.md) compliant token contract.

> **Note:**
> The master branch contains new features not covered by officially-released SNIPs and may be subject to change. When releasing a token on mainnet, we recommend you start with a [tagged release](https://github.com/scrtlabs/snip20-reference-impl/tags) to ensure compatibility with SNIP standards.

* [Building](#building)
* [Token instantiation](#instantiation)
* [Usage examples](#usage)
* [Troubleshooting](#troubleshooting)
* [Privacy Enchancements](#privacy)
* [Private Push Notifications](#push)
* [Security Features](#security)

## <a name="building"></a>Building

With the introduction of delayed write buffers (DWBs) and bitwise trie of bucketed entries (BTBEs) (see [Privacy Enchancements](#privacy) below) developers must configure the code prior to building the contract WASM. 

The crate `build.rs` file reads two environment variables `DWB_CAPACITY` and `BTBE_CAPACITY`, which correspond to the size of the DWB and bucket size for the BTBE, respectively. If the environemnt variables are not set, then they will both be set to `64`. The higher these values, the greater the anonymity set but also the higher the gas cost for transactions. See [here](https://hackmd.io/twnenQuoSp61hK_YWJo9oA) for a more technical description of how DWBs and BTBEs work.

A second consideration is how many bytes to use to store user balances in the DWB and BTBE. The default value used in the master branch code is 8 bytes (u64 size). Using only 8 bytes to store balance saves gas when writing the balances in the DWB and BTBE. 8 bytes translates to a maximum token balance in base denomination for a single account equal to approximately 18 quadrillion. For most tokens with 6 decimals, this is more than sufficient. However, some tokens such as secret wrapped ERC-20 tokens can have 18 decimals and this upper bound might not be enough. In that case, you will want to store balances with 16 bytes (u128 size).

> [!IMPORTANT] 
> The version in this branch has 64-bit balances and is recommended for tokens with 6 decimals only.
>
> See [here](https://github.com/SolarRepublic/snip20-reference-impl/tree/prod/ref-impl-balance128) for a branch that implements 128-bit balances.

## <a name="instantiation"></a>Token instantiation

At the time of token creation you may configure:

* Public Total Supply:  If you enable this, the token's total supply will be displayed whenever a TokenInfo query is performed.  DEFAULT: false
* Enable Deposit: If you enable this, you will be able to convert from SCRT to the token.*  DEFAULT: false
* Enable Redeem: If you enable this, you will be able to redeem your token for SCRT.*  It should be noted that if you have redeem enabled, but deposit disabled, all redeem attempts will fail unless someone has sent SCRT to the token contract.  DEFAULT: false
* Enable Mint: If you enable this, any address in the list of minters will be able to mint new tokens.  The admin address is the default minter, but can use the set/add/remove_minters functions to change the list of approved minting addresses.  DEFAULT: false
* Enable Burn: If you enable this, addresses will be able to burn tokens.  DEFAULT: false
* Can Modify Denoms: If you enable this, an admin can modify supported denoms. DEFAULT: false


\*:The conversion rate will be 1 uscrt for 1 minimum denomination of the token.  This means that if your token has 6 decimal places, it will convert 1:1 with SCRT.  If your token has 10 decimal places, it will have an exchange rate of 10000 SCRT for 1 token.  If your token has 3 decimal places, it will have an exchange rate of 1000 tokens for 1 SCRT.  You can use the exchange_rate query to view the exchange rate for the token.  The query response will display either how many tokens are worth 1 SCRT, or how many SCRT are worth 1 token.  That is, the response lists the symbol of the coin that has less value (either SCRT or the token), and the number of those coins that are worth 1 of the other.

## <a name="usage"></a>Usage examples:

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


## <a name="troubleshooting"></a>Troubleshooting 

All transactions are encrypted, so if you want to see the error returned by a failed transaction, you need to use the command

`secretcli q compute tx <TX_HASH>`

## <a name="privacy"></a>Privacy Enhancements

 - All transfers/sends (including batch and *_from) use the delayed write buffer (DWB) to address "spicy printf" storage access pattern attacks.
 - Additionally, a bitwise trie of bucketed entries (BTBE) creates dynamic anonymity sets for senders/owners, whose balance must be checked when transferring/sending. It also enhances privacy for recipients.
 - When querying for Transaction History, each event's `id` field returned in responses are deterministically obfuscated by `ChaChaRng(XorBytes(ChaChaRng(actual_event_id), internal_secret)) >> (64 - 53)` for better privacy. Without this, an attacker could deduce the number of events that took place between two transactions.

## <a name="push"></a>Private Push Notifications

This contract implements SNIP-52. It publishes encrypted messages to the event log which carry data intended to notify recipients of actions that affect them, such as token transfer and allowances.

Direct channels:
 - `recvd` -- emitted to a recipient when their account receives funds via one of `transfer`, `send`, `transfer_from`, or `send_from`. The notification data includes the amount, the sender, and the memo length.
 - `spent` -- emitted to an owner when their funds are spent, via one of `transfer`, `send`, `transfer_from` or `send_from`. The notification data includes the amount, the recipient, the owner's new balance, and a few other pieces of information such as memo length, number of actions, and whether the spender was the transaction's sender.
 - `allowance` -- emitted to a spender when some allower account has granted them or modified an existing allowance to spend their tokens, via `increase_allowance` or `decrease_allowance`. The notification data includes the amount, the allower, and the expiration of the allowance.

Group channels:
 - `multirecvd` -- emitted to a group of recipients (up to 16) when a `batch_transfer`, `batch_send`, `batch_transfer_from`, or `batch_send_from` has been executed. Each recipient will receive a packet of data containing the amount they received, the last 8 bytes of the owner's address, and some additional metadata.
 - `multispent` -- emitted to a group of spenders (up to 16) when a `batch_transfer_from`, or `batch_send_from` has been executed. Each spender will receive a packet of data containing the amount that was spent, the last 8 bytes of the recipient's address, and some additional metadata.


## <a name="push"></a>Security Features

 - Transfers to the contract itself will be rejected to prevent accidental loss of funds.


