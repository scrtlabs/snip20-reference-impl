#![allow(clippy::field_reassign_with_default)] // This is triggered in `#[derive(JsonSchema)]`

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, HumanAddr, Uint128};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PermitSignature {
    pub pub_key: PubKey,
    pub signature: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PubKey {
    /// ignored, but must be "tendermint/PubKeySecp256k1"
    pub r#type: String,
    /// Secp256k1 PubKey
    pub value: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
// Note: The order of fields in this struct is important for the permit signature verification!
pub struct Permit {
    /// ignored
    pub account_number: Uint128,
    /// ignored, no Env in query
    pub chain_id: String,
    /// ignored
    pub fee: Fee,
    /// ignored
    pub memo: String,
    /// the signed message
    pub msgs: Vec<PermitMsg>,
    /// ignored
    pub sequence: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
// Note: The order of fields in this struct is important for the permit signature verification!
pub struct Fee {
    pub amount: Vec<Coin>,
    pub gas: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
// Note: The order of fields in this struct is important for the permit signature verification!
pub struct Coin {
    pub amount: Uint128,
    pub denom: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
// Note: The order of fields in this struct is important for the permit signature verification!
pub struct PermitMsg {
    pub r#type: String,
    pub value: PermitContent,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
// Note: The order of fields in this struct is important for the permit signature verification!
pub struct PermitContent {
    pub allowed_tokens: Vec<HumanAddr>,
    pub permit_name: String,
}
