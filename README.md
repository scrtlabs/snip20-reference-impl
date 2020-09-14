# Secret-SCRT - Privacy coin backed by SCRT

This is a PoC of how to create a privacy token on the Secret Network backed by a native coin.

Usage is pretty simple - you deposit SCRT into the contract, and you get SSCRT (or Secret-SCRT), which you can then use with the ERC-20-like functionality that the contract provides including: sending/receiving/allowance and withdrawing back to SCRT. 

In terms of privacy the deposit & withdrawals are public, as they are transactions on-chain. The rest of the functionality is private (so no one can see if you send SSCRT and to whom, and receiving SSCRT is also hidden). 

The code was updated with a new mechanism, which I call viewing keys. This allows a user to generate a key that enables off-chain queries. This way you can perform balance and transaction history queries without waiting for a transaction on-chain. The tranaction to create a viewing key is expensive, to the tune of about 3M gas. This is intended to make queries take a long time to execute to be resistant to brute-force attacks.

The usual disclaimer: Don't use this in production, I take no responsibility for anything anywhere anytime etc.

## Usage examples:

To deposit: ***(This is public)***

```./secretcli tx compute execute <contract-address> '{"deposit": {}}' --amount 1000000uscrt --from <account>``` 

To send SSCRT: ***(Only you will be able to see the parameters you send here)***

```./secretcli tx compute execute <contract-address> '{"transfer": {"recipient": "<destination_address>", "amount": "<amount_to_send>"}}' --from <account>```

To check your balance: ***(Only you will be able to see the parameters you send here)***

```./secretcli tx compute execute <contract-address> '{"balance": {}}' --from <account>```

```./secretcli q compute tx <returned tx-hash> --trust-node```

To withdraw: ***(This is public)***

```./secretcli tx compute execute <contract-address> '{"withdraw": {"amount": "<amount in uscrt>"}}' --from <account>```

To set your viewing key: 

```./secretcli tx compute execute <contract-address> '{"create_viewing_key": {"entropy": "<random_phrase>"}}' --from <account>```

This transaction will be expensive, so set your gas limit to about 3M with `--gas 3000000`

Make your random phrase as long as you want. At least 15 characters are recommended. You do not have to remember it - it will simply be used to randomize your generated viewing key. After this is done you can get your viewing key:

```./secretcli q compute tx <returned tx-hash>```

The key will start with the prefix `api_key_....`

To use your viewing key, you can query your balance or the transaction history:

```./secretcli q compute query <contract-address> '{"balance": {"address": "<your_address>", "viewing_key": "<your_viewing_key>"}}'```

```./secretcli q compute query <contract-address> '{"transfers": {"address": "<your_address>", "viewing_key": "<your_viewing_key>"}}'```

## Play with it on testnet

The deployed SSCRT contract address on the testnet is `secret1umwqjum7f4zmp9alr2kpmq4y5j4hyxlam896r3` and label `sscrt`

## Troubleshooting 

All transactions are encrypted, so if you want to see the error returned by a failed transaction, you need to use the command

`secretcli q compute tx <TX_HASH>`
