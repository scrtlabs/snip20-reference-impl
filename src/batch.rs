//! Types used in batch operations

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Binary, Uint128};

pub trait HasDecoy {
    fn decoys(&self) -> &Option<Vec<Addr>>;
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct TransferAction {
    pub recipient: String,
    pub amount: Uint128,
    pub memo: Option<String>,
    pub decoys: Option<Vec<Addr>>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct SendAction {
    pub recipient: String,
    pub recipient_code_hash: Option<String>,
    pub amount: Uint128,
    pub msg: Option<Binary>,
    pub memo: Option<String>,
    pub decoys: Option<Vec<Addr>>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct TransferFromAction {
    pub owner: String,
    pub recipient: String,
    pub amount: Uint128,
    pub memo: Option<String>,
    pub decoys: Option<Vec<Addr>>,
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
    pub decoys: Option<Vec<Addr>>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct MintAction {
    pub recipient: String,
    pub amount: Uint128,
    pub memo: Option<String>,
    pub decoys: Option<Vec<Addr>>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct BurnFromAction {
    pub owner: String,
    pub amount: Uint128,
    pub memo: Option<String>,
    pub decoys: Option<Vec<Addr>>,
}

macro_rules! impl_decoyable {
    ($struct:ty) => {
        impl HasDecoy for $struct {
            fn decoys(&self) -> &Option<Vec<Addr>> {
                &self.decoys
            }
        }
    };
}

impl_decoyable!(BurnFromAction);
impl_decoyable!(MintAction);
impl_decoyable!(SendFromAction);
impl_decoyable!(TransferFromAction);
impl_decoyable!(TransferAction);
impl_decoyable!(SendAction);
