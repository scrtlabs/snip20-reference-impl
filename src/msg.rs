use schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer};

use cosmwasm_std::{HumanAddr, Uint128};
use crate::viewing_key::ViewingKey;

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema)]
pub struct InitialBalance {
    pub address: HumanAddr,
    pub amount: Uint128,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InitMsg {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub initial_balances: Vec<InitialBalance>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {

    // Native coin interactions
    Withdraw {
        amount: Uint128,
    },
    Deposit { },

    // ERC-20 stuff
    Approve {
        spender: HumanAddr,
        amount: Uint128,
    },
    Transfer {
        recipient: HumanAddr,
        amount: Uint128,
    },
    TransferFrom {
        owner: HumanAddr,
        recipient: HumanAddr,
        amount: Uint128,
    },
    Burn {
        amount: Uint128,
    },
    Balance { },
    Allowance {
        spender: HumanAddr,
    },

    // Privacy stuff
    SetViewingKey { key: String },
    CreateViewingKey { entropy: String }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Balance { address: HumanAddr, key: String },
    Transfers { address: HumanAddr, key: String },
    Test {},
}

impl QueryMsg {
    pub fn get_validation_params(&self) -> (&HumanAddr, ViewingKey) {
        match self {
            Self::Balance { address, key} => (address, ViewingKey(key.clone())),
            Self::Transfers { address, key} => (address, ViewingKey(key.clone())),
            _ => (panic!("lol"))
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct BalanceResponse {
    pub balance: Uint128,
    pub token: String,
}

impl Serialize for BalanceResponse {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        unimplemented!()
    }
}


#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema)]
pub struct AllowanceResponse {
    pub allowance: Uint128,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema)]
pub struct CreateViewingKeyResponse {
    pub key: String,
}
