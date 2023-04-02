#![allow(clippy::field_reassign_with_default)] // This is triggered in `#[derive(JsonSchema)]`

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::batch;
use crate::batch::HasDecoy;
use crate::transaction_history::{ExtendedTx, Tx};
use cosmwasm_std::{Addr, Api, Binary, StdError, StdResult, Uint128};
use secret_toolkit::permit::Permit;

#[cfg_attr(test, derive(Eq, PartialEq))]
#[derive(Serialize, Deserialize, Clone, JsonSchema)]
pub struct InitialBalance {
    pub address: String,
    pub amount: Uint128,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InstantiateMsg {
    pub name: String,
    pub admin: Option<String>,
    pub symbol: String,
    pub decimals: u8,
    pub initial_balances: Option<Vec<InitialBalance>>,
    pub prng_seed: Binary,
    pub config: Option<InitConfig>,
    pub supported_denoms: Option<Vec<String>>,
}

impl InstantiateMsg {
    pub fn config(&self) -> InitConfig {
        self.config.clone().unwrap_or_default()
    }
}

/// This type represents optional configuration values which can be overridden.
/// All values are optional and have defaults which are more private by default,
/// but can be overridden if necessary
#[derive(Serialize, Deserialize, JsonSchema, Clone, Default, Debug)]
#[serde(rename_all = "snake_case")]
pub struct InitConfig {
    /// Indicates whether the total supply is public or should be kept secret.
    /// default: False
    public_total_supply: Option<bool>,
    /// Indicates whether deposit functionality should be enabled
    /// default: False
    enable_deposit: Option<bool>,
    /// Indicates whether redeem functionality should be enabled
    /// default: False
    enable_redeem: Option<bool>,
    /// Indicates whether mint functionality should be enabled
    /// default: False
    enable_mint: Option<bool>,
    /// Indicates whether burn functionality should be enabled
    /// default: False
    enable_burn: Option<bool>,
    /// Indicated whether an admin can modify supported denoms
    /// default: False
    can_modify_denoms: Option<bool>,
}

impl InitConfig {
    pub fn public_total_supply(&self) -> bool {
        self.public_total_supply.unwrap_or(false)
    }

    pub fn deposit_enabled(&self) -> bool {
        self.enable_deposit.unwrap_or(false)
    }

    pub fn redeem_enabled(&self) -> bool {
        self.enable_redeem.unwrap_or(false)
    }

    pub fn mint_enabled(&self) -> bool {
        self.enable_mint.unwrap_or(false)
    }

    pub fn burn_enabled(&self) -> bool {
        self.enable_burn.unwrap_or(false)
    }

    pub fn can_modify_denoms(&self) -> bool {
        self.can_modify_denoms.unwrap_or(false)
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    // Native coin interactions
    Redeem {
        amount: Uint128,
        denom: Option<String>,
        decoys: Option<Vec<Addr>>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },
    Deposit {
        decoys: Option<Vec<Addr>>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },

    // Base ERC-20 stuff
    Transfer {
        recipient: String,
        amount: Uint128,
        memo: Option<String>,
        decoys: Option<Vec<Addr>>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },
    Send {
        recipient: String,
        recipient_code_hash: Option<String>,
        amount: Uint128,
        msg: Option<Binary>,
        memo: Option<String>,
        decoys: Option<Vec<Addr>>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },
    BatchTransfer {
        actions: Vec<batch::TransferAction>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },
    BatchSend {
        actions: Vec<batch::SendAction>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },
    Burn {
        amount: Uint128,
        memo: Option<String>,
        decoys: Option<Vec<Addr>>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },
    RegisterReceive {
        code_hash: String,
        padding: Option<String>,
    },
    CreateViewingKey {
        entropy: String,
        padding: Option<String>,
    },
    SetViewingKey {
        key: String,
        padding: Option<String>,
    },

    // Allowance
    IncreaseAllowance {
        spender: String,
        amount: Uint128,
        expiration: Option<u64>,
        padding: Option<String>,
    },
    DecreaseAllowance {
        spender: String,
        amount: Uint128,
        expiration: Option<u64>,
        padding: Option<String>,
    },
    TransferFrom {
        owner: String,
        recipient: String,
        amount: Uint128,
        memo: Option<String>,
        decoys: Option<Vec<Addr>>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },
    SendFrom {
        owner: String,
        recipient: String,
        recipient_code_hash: Option<String>,
        amount: Uint128,
        msg: Option<Binary>,
        memo: Option<String>,
        decoys: Option<Vec<Addr>>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },
    BatchTransferFrom {
        actions: Vec<batch::TransferFromAction>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },
    BatchSendFrom {
        actions: Vec<batch::SendFromAction>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },
    BurnFrom {
        owner: String,
        amount: Uint128,
        memo: Option<String>,
        decoys: Option<Vec<Addr>>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },
    BatchBurnFrom {
        actions: Vec<batch::BurnFromAction>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },

    // Mint
    Mint {
        recipient: String,
        amount: Uint128,
        memo: Option<String>,
        decoys: Option<Vec<Addr>>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },
    BatchMint {
        actions: Vec<batch::MintAction>,
        entropy: Option<Binary>,
        padding: Option<String>,
    },
    AddMinters {
        minters: Vec<String>,
        padding: Option<String>,
    },
    RemoveMinters {
        minters: Vec<String>,
        padding: Option<String>,
    },
    SetMinters {
        minters: Vec<String>,
        padding: Option<String>,
    },

    // Admin
    ChangeAdmin {
        address: String,
        padding: Option<String>,
    },
    SetContractStatus {
        level: ContractStatusLevel,
        padding: Option<String>,
    },
    /// Add deposit/redeem support for these coin denoms
    AddSupportedDenoms { denoms: Vec<String> },
    /// Remove deposit/redeem support for these coin denoms
    RemoveSupportedDenoms { denoms: Vec<String> },

    // Permit
    RevokePermit {
        permit_name: String,
        padding: Option<String>,
    },
}

pub trait Decoyable {
    fn get_minimal_decoys_size(&self) -> usize;
    fn get_entropy(self) -> Option<Binary>;
}

impl Decoyable for ExecuteMsg {
    fn get_minimal_decoys_size(&self) -> usize {
        match self {
            ExecuteMsg::Deposit { decoys, .. }
            | ExecuteMsg::Redeem { decoys, .. }
            | ExecuteMsg::Transfer { decoys, .. }
            | ExecuteMsg::Send { decoys, .. }
            | ExecuteMsg::Burn { decoys, .. }
            | ExecuteMsg::Mint { decoys, .. }
            | ExecuteMsg::TransferFrom { decoys, .. }
            | ExecuteMsg::SendFrom { decoys, .. }
            | ExecuteMsg::BurnFrom { decoys, .. } => {
                if let Some(user_decoys) = decoys {
                    return user_decoys.len();
                }

                0
            }
            ExecuteMsg::BatchSendFrom { actions, .. } => get_min_decoys_count(actions),
            ExecuteMsg::BatchTransferFrom { actions, .. } => get_min_decoys_count(actions),
            ExecuteMsg::BatchTransfer { actions, .. } => get_min_decoys_count(actions),
            ExecuteMsg::BatchSend { actions, .. } => get_min_decoys_count(actions),
            ExecuteMsg::BatchBurnFrom { actions, .. } => get_min_decoys_count(actions),
            ExecuteMsg::BatchMint { actions, .. } => get_min_decoys_count(actions),
            _ => 0,
        }
    }

    fn get_entropy(self) -> Option<Binary> {
        match self {
            ExecuteMsg::Deposit { entropy, .. }
            | ExecuteMsg::Redeem { entropy, .. }
            | ExecuteMsg::Transfer { entropy, .. }
            | ExecuteMsg::Send { entropy, .. }
            | ExecuteMsg::Burn { entropy, .. }
            | ExecuteMsg::Mint { entropy, .. }
            | ExecuteMsg::TransferFrom { entropy, .. }
            | ExecuteMsg::SendFrom { entropy, .. }
            | ExecuteMsg::BurnFrom { entropy, .. }
            | ExecuteMsg::BatchTransferFrom { entropy, .. }
            | ExecuteMsg::BatchSendFrom { entropy, .. }
            | ExecuteMsg::BatchTransfer { entropy, .. }
            | ExecuteMsg::BatchSend { entropy, .. }
            | ExecuteMsg::BatchBurnFrom { entropy, .. }
            | ExecuteMsg::BatchMint { entropy, .. } => entropy,
            _ => None,
        }
    }
}

fn get_min_decoys_count<T: HasDecoy>(actions: &[T]) -> usize {
    let mut min_decoys_count = usize::MAX;
    for action in actions {
        if let Some(user_decoys) = &action.decoys() {
            if user_decoys.len() < min_decoys_count {
                min_decoys_count = user_decoys.len();
            }
        }
    }

    if min_decoys_count == usize::MAX {
        0
    } else {
        min_decoys_count
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteAnswer {
    // Native
    Deposit {
        status: ResponseStatus,
    },
    Redeem {
        status: ResponseStatus,
    },

    // Base
    Transfer {
        status: ResponseStatus,
    },
    Send {
        status: ResponseStatus,
    },
    BatchTransfer {
        status: ResponseStatus,
    },
    BatchSend {
        status: ResponseStatus,
    },
    Burn {
        status: ResponseStatus,
    },
    RegisterReceive {
        status: ResponseStatus,
    },
    CreateViewingKey {
        key: String,
    },
    SetViewingKey {
        status: ResponseStatus,
    },

    // Allowance
    IncreaseAllowance {
        spender: Addr,
        owner: Addr,
        allowance: Uint128,
    },
    DecreaseAllowance {
        spender: Addr,
        owner: Addr,
        allowance: Uint128,
    },
    TransferFrom {
        status: ResponseStatus,
    },
    SendFrom {
        status: ResponseStatus,
    },
    BatchTransferFrom {
        status: ResponseStatus,
    },
    BatchSendFrom {
        status: ResponseStatus,
    },
    BurnFrom {
        status: ResponseStatus,
    },
    BatchBurnFrom {
        status: ResponseStatus,
    },

    // Mint
    Mint {
        status: ResponseStatus,
    },
    BatchMint {
        status: ResponseStatus,
    },
    AddMinters {
        status: ResponseStatus,
    },
    RemoveMinters {
        status: ResponseStatus,
    },
    SetMinters {
        status: ResponseStatus,
    },

    // Other
    ChangeAdmin {
        status: ResponseStatus,
    },
    SetContractStatus {
        status: ResponseStatus,
    },
    AddSupportedDenoms {
        status: ResponseStatus,
    },
    RemoveSupportedDenoms {
        status: ResponseStatus,
    },

    // Permit
    RevokePermit {
        status: ResponseStatus,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    TokenInfo {},
    TokenConfig {},
    ContractStatus {},
    ExchangeRate {},
    Allowance {
        owner: String,
        spender: String,
        key: String,
    },
    AllowancesGiven {
        owner: String,
        key: String,
        page: Option<u32>,
        page_size: u32,
    },
    AllowancesReceived {
        spender: String,
        key: String,
        page: Option<u32>,
        page_size: u32,
    },
    Balance {
        address: String,
        key: String,
    },
    TransferHistory {
        address: String,
        key: String,
        page: Option<u32>,
        page_size: u32,
        should_filter_decoys: bool,
    },
    TransactionHistory {
        address: String,
        key: String,
        page: Option<u32>,
        page_size: u32,
        should_filter_decoys: bool,
    },
    Minters {},
    WithPermit {
        permit: Permit,
        query: QueryWithPermit,
    },
}

impl QueryMsg {
    pub fn get_validation_params(&self, api: &dyn Api) -> StdResult<(Vec<Addr>, String)> {
        match self {
            Self::Balance { address, key } => {
                let address = api.addr_validate(address.as_str())?;
                Ok((vec![address], key.clone()))
            }
            Self::TransferHistory { address, key, .. } => {
                let address = api.addr_validate(address.as_str())?;
                Ok((vec![address], key.clone()))
            }
            Self::TransactionHistory { address, key, .. } => {
                let address = api.addr_validate(address.as_str())?;
                Ok((vec![address], key.clone()))
            }
            Self::Allowance {
                owner,
                spender,
                key,
                ..
            } => {
                let owner = api.addr_validate(owner.as_str())?;
                let spender = api.addr_validate(spender.as_str())?;

                Ok((vec![owner, spender], key.clone()))
            }
            Self::AllowancesGiven { owner, key, .. } => {
                let owner = api.addr_validate(owner.as_str())?;
                Ok((vec![owner], key.clone()))
            }
            Self::AllowancesReceived { spender, key, .. } => {
                let spender = api.addr_validate(spender.as_str())?;
                Ok((vec![spender], key.clone()))
            }
            _ => panic!("This query type does not require authentication"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[serde(rename_all = "snake_case")]
pub enum QueryWithPermit {
    Allowance {
        owner: String,
        spender: String,
    },
    AllowancesGiven {
        owner: String,
        page: Option<u32>,
        page_size: u32,
    },
    AllowancesReceived {
        spender: String,
        page: Option<u32>,
        page_size: u32,
    },
    Balance {},
    TransferHistory {
        page: Option<u32>,
        page_size: u32,
        should_filter_decoys: bool,
    },
    TransactionHistory {
        page: Option<u32>,
        page_size: u32,
        should_filter_decoys: bool,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    TokenInfo {
        name: String,
        symbol: String,
        decimals: u8,
        total_supply: Option<Uint128>,
    },
    TokenConfig {
        public_total_supply: bool,
        deposit_enabled: bool,
        redeem_enabled: bool,
        mint_enabled: bool,
        burn_enabled: bool,
        supported_denoms: Vec<String>,
    },
    ContractStatus {
        status: ContractStatusLevel,
    },
    ExchangeRate {
        rate: Uint128,
        denom: String,
    },
    Allowance {
        spender: Addr,
        owner: Addr,
        allowance: Uint128,
        expiration: Option<u64>,
    },
    AllowancesGiven {
        owner: Addr,
        allowances: Vec<AllowanceGivenResult>,
        count: u32,
    },
    AllowancesReceived {
        spender: Addr,
        allowances: Vec<AllowanceReceivedResult>,
        count: u32,
    },
    Balance {
        amount: Uint128,
    },
    TransferHistory {
        txs: Vec<Tx>,
        total: Option<u64>,
    },
    TransactionHistory {
        txs: Vec<ExtendedTx>,
        total: Option<u64>,
    },
    ViewingKeyError {
        msg: String,
    },
    Minters {
        minters: Vec<Addr>,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct AllowanceGivenResult {
    pub spender: Addr,
    pub allowance: Uint128,
    pub expiration: Option<u64>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct AllowanceReceivedResult {
    pub owner: Addr,
    pub allowance: Uint128,
    pub expiration: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Success,
    Failure,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatusLevel {
    NormalRun,
    StopAllButRedeems,
    StopAll,
}

pub fn status_level_to_u8(status_level: ContractStatusLevel) -> u8 {
    match status_level {
        ContractStatusLevel::NormalRun => 0,
        ContractStatusLevel::StopAllButRedeems => 1,
        ContractStatusLevel::StopAll => 2,
    }
}

pub fn u8_to_status_level(status_level: u8) -> StdResult<ContractStatusLevel> {
    match status_level {
        0 => Ok(ContractStatusLevel::NormalRun),
        1 => Ok(ContractStatusLevel::StopAllButRedeems),
        2 => Ok(ContractStatusLevel::StopAll),
        _ => Err(StdError::generic_err("Invalid state level")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{from_slice, StdResult};

    #[derive(Serialize, Deserialize, JsonSchema, Debug, PartialEq)]
    #[serde(rename_all = "snake_case")]
    pub enum Something {
        Var { padding: Option<String> },
    }

    #[test]
    fn test_deserialization_of_missing_option_fields() -> StdResult<()> {
        let input = b"{ \"var\": {} }";
        let obj: Something = from_slice(input)?;
        assert_eq!(
            obj,
            Something::Var { padding: None },
            "unexpected value: {:?}",
            obj
        );
        Ok(())
    }
}
