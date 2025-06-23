//! Types used in batch operations

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, Uint128};

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct TransferAction {
    pub recipient: String,
    pub amount: Uint128,
    pub memo: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct SendAction {
    pub recipient: String,
    pub recipient_code_hash: Option<String>,
    pub amount: Uint128,
    pub msg: Option<Binary>,
    pub memo: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct TransferFromAction {
    pub owner: String,
    pub recipient: String,
    pub amount: Uint128,
    pub memo: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct SendFromAction {
    pub owner: String,
    pub recipient: String,
    pub recipient_code_hash: Option<String>,
    pub amount: Uint128,
    pub msg: Option<Binary>,
    pub memo: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct MintAction {
    pub recipient: String,
    pub amount: Uint128,
    pub memo: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct BurnFromAction {
    pub owner: String,
    pub amount: Uint128,
    pub memo: Option<String>,
}
