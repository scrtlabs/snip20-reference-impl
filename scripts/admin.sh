#!/bin/bash

################
#   ADMIN TXS   
################

#This command will register a token as an accepted deposit denom
secretcli tx compute execute $CONTRACT_ADDRESS @- << 'EOF'
{ 
    "register_token": {
        "address": "<token_address>", 
        "code_hash": "<token_code_hash",
        "ratio": "<exchange_ratio_token_for_1_sno",
        "max_deposit": "<total_maximum_deposit_amount>"  
    }
}
EOF

#This command will update the exhcange ratio of a specified token. Token must already be registered with the contract. 
secretcli tx compute execute $CONTRACT_ADDRESS @- << 'EOF' 
{ 
    "update_ratio": {
        "token": "<token_address>", 
        "ratio": "<exchange_ratio_token_for_1_sno>" 
    }
}
EOF

#This command will update the maximum amount of allowed deposits in the specified token denom. 
secretcli tx compute execute $CONTRACT_ADDRESS @- << 'EOF'
{ 
    "update_max_deposit": {
        "token": "<token_address>", 
        "max_deposit": "<new_total_maximum_deposit_amount" 
    }
}
EOF

#This command will update the approved admins.
secretcli tx compute execute $CONTRACT_ADDRESS @- << 'EOF'
{ 
    "update_admins": {
        "action": "<remove_or_add>"
        "admins": "[<admin1_address>, <admin2_address>]" 
    } 
}
EOF

#This command will update the current owner. Note: tx sender's adress must be equal to the current contract owner's address
secretcli tx compute execute $CONTRACT_ADDRESS @- << 'EOF'
{
    "update_owner": {
        "owner": "<new_owner_Address>"
    }
}
EOF

#This command will withdraw the specified amount in the specified token denomination to either the sender's address or an optional 'to' address
secretcli tx compute execute $CONTRACT_ADDRESS @- << 'EOF' 
{ 
    "withdraw": {
        "token": "<token_address", 
        "amount": "<amount_to_withdraw>", 
        "to": "<optional_to_address>" 
    }
}
EOF

#This command will pause minting on the contract
secretcli tx compute execute $CONTRACT_ADDRESS '{ "pause": {} }'

################
#   QUERIES     
################

#This query will return the available supply of SNO remaining as well as the global total supply
secretcli tx compute query $CONTRACT_ADDRESS '{ "max_supply": {}}'

#This query will return the current total amount of deposits as well global maximum deposit amount for the specified token
secretcli tx compute query $CONTRACT_ADDRESS '{ "max_deposits": { "token": "<token_address" } }'

#This query will return the token denominations currently accepted for minting 
secretcli tx compute query $CONTRACT_ADDRESS '{ "denoms": {} }'

#TODO ... 