use std::any::type_name;
use std::convert::TryFrom;

use cosmwasm_std::{Addr, CanonicalAddr, StdError, StdResult, Storage};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use schemars::JsonSchema;
use secret_toolkit::storage::{Item, Keymap};
use serde::{Deserialize, Serialize};

use crate::msg::{status_level_to_u8, u8_to_status_level, ContractStatusLevel};
use crate::viewing_key::ViewingKey;
use serde::de::DeserializeOwned;

pub static CONFIG_KEY: &[u8] = b"config";
pub const PREFIX_TXS: &[u8] = b"transfers";

pub const KEY_CONSTANTS: &[u8] = b"constants";
pub const KEY_TOTAL_SUPPLY: &[u8] = b"total_supply";
pub const KEY_CONTRACT_STATUS: &[u8] = b"contract_status";
pub const KEY_MINTERS: &[u8] = b"minters";
pub const KEY_TX_COUNT: &[u8] = b"tx-count";

pub const PREFIX_CONFIG: &[u8] = b"config";
pub const PREFIX_BALANCES: &[u8] = b"balances";
pub const PREFIX_ALLOWANCES: &[u8] = b"allowances";
pub const PREFIX_VIEW_KEY: &[u8] = b"viewingkey";
pub const PREFIX_RECEIVERS: &[u8] = b"receivers";

// Config

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, JsonSchema)]
pub struct Constants {
    pub name: String,
    pub admin: Addr,
    pub symbol: String,
    pub decimals: u8,
    pub prng_seed: Vec<u8>,
    // privacy configuration
    pub total_supply_is_public: bool,
    // is deposit enabled
    pub deposit_is_enabled: bool,
    // is redeem enabled
    pub redeem_is_enabled: bool,
    // is mint enabled
    pub mint_is_enabled: bool,
    // is burn enabled
    pub burn_is_enabled: bool,
    // the address of this contract, used to validate query permits
    pub contract_address: Addr,
}

pub static CONSTANTS: Item<Constants> = Item::new(KEY_CONSTANTS);
pub struct ConstantsStore {}
impl ConstantsStore {
    pub fn may_load(store: &dyn Storage) -> StdResult<Constants> {
        CONSTANTS
            .may_load(store)?
            .ok_or_else(|| StdError::generic_err("no constants stored"))
    }

    pub fn save(store: &mut dyn Storage, constants: &Constants) -> StdResult<()> {
        CONSTANTS.save(store, constants)
    }
}

pub static TOTAL_SUPPLY: Item<u128> = Item::new(KEY_TOTAL_SUPPLY);
pub struct TotalSupplyStore {}
impl TotalSupplyStore {
    pub fn may_load(store: &dyn Storage) -> StdResult<u128> {
        TOTAL_SUPPLY
            .may_load(store)?
            .ok_or_else(|| StdError::generic_err("no total supply stored"))
    }

    pub fn save(store: &mut dyn Storage, supply: u128) -> StdResult<()> {
        TOTAL_SUPPLY.save(store, &supply)
    }
}

pub static CONTRACT_STATUS: Item<ContractStatusLevel> = Item::new(KEY_CONTRACT_STATUS);
pub struct ContractStatusStore {}
impl ContractStatusStore {
    pub fn may_load(store: &dyn Storage) -> StdResult<ContractStatusLevel> {
        CONTRACT_STATUS
            .may_load(store)?
            .ok_or_else(|| StdError::generic_err("no contract status stored"))
    }

    pub fn save(store: &mut dyn Storage, status: ContractStatusLevel) -> StdResult<()> {
        // Elad check supply because it's a primitive (serializable? should send as: &supply.to_be_bytes() maybe?)
        CONTRACT_STATUS.save(store, &status)
    }
}

pub static MINTERS: Item<Vec<String>> = Item::new(KEY_MINTERS);
pub struct MintersStore {}
impl MintersStore {
    pub fn may_load(store: &dyn Storage) -> StdResult<Vec<String>> {
        MINTERS
            .may_load(store)?
            .ok_or_else(|| StdError::generic_err(""))
    }

    pub fn save(store: &mut dyn Storage, minters_to_set: Vec<String>) -> StdResult<()> {
        // Elad check serialization for minters_to_set
        MINTERS.save(store, &minters_to_set)
    }

    pub fn add_minters(store: &mut dyn Storage, minters_to_add: Vec<String>) -> StdResult<()> {
        let mut loaded_minters = MINTERS.may_load(store)?;

        loaded_minters.extend(minters_to_add);

        MINTERS.save(&mut store, &loaded_minters)
    }

    pub fn remove_minters(
        store: &mut dyn Storage,
        minters_to_remove: Vec<String>,
    ) -> StdResult<()> {
        let mut loaded_minters = MINTERS.may_load(store)?;

        for minter in minters_to_remove {
            loaded_minters.retain(|x| x != &minter);
        }

        MINTERS.save(&mut store, &loaded_minters)
    }
}

pub static TX_COUNT: Item<u64> = Item::new(KEY_TX_COUNT);
pub struct TxCountStore {}
impl TxCountStore {
    pub fn may_load(store: &dyn Storage) -> StdResult<u64> {
        TX_COUNT
            .may_load(store)?
            .ok_or_else(|| StdError::generic_err(""))
    }

    pub fn save(store: &mut dyn Storage, count: u64) -> StdResult<()> {
        TX_COUNT.save(store, &count)
    }
}

// elad: maybe use Uint128,
pub static BALANCES: Keymap<Addr, u128> = Keymap::new(PREFIX_BALANCES);
pub struct BalancesStore {}
impl BalancesStore {
    pub fn load(store: &dyn Storage, account: &Addr) -> u128 {
        BALANCES.get(store, account)?.ok_or_else(|| 0)
    }

    pub fn save(store: &mut dyn Storage, account: &Addr, amount: u128) -> StdResult<()> {
        BALANCES.insert(store, account, &amount)
    }
}

// Allowances

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, Default, JsonSchema)]
pub struct Allowance {
    pub amount: u128,
    pub expiration: Option<u64>,
}

impl Allowance {
    pub fn is_expired_at(&self, block: &cosmwasm_std::BlockInfo) -> bool {
        match self.expiration {
            Some(time) => block.time >= time,
            None => false, // allowance has no expiration
        }
    }
}

pub static ALLOWANCES: Keymap<(Addr, Addr), Allowance> = Keymap::new(PREFIX_ALLOWANCES);
pub struct AllowancesStore {}
impl AllowancesStore {
    pub fn may_load(store: &dyn Storage, owner: &Addr, spender: &Addr) -> StdResult<Allowance> {
        ALLOWANCES
            .get(store, (owner, spender))?
            .ok_or_else(|| Option::unwrap_or_default)
        // let loaded_allowance = ALLOWANCES.may_load(&store, (owner, spender))?;
        // loaded_allowance.map(Option::unwrap_or_default)
    }

    pub fn save(
        store: &mut dyn Storage,
        owner: &Addr,
        spender: &Addr,
        allowance: &Allowance,
    ) -> StdResult<()> {
        ALLOWANCES.insert(store, (owner, spender), allowance)
    }
}

// Viewing Keys

pub fn write_viewing_key(store: &mut dyn Storage, owner: &CanonicalAddr, key: &ViewingKey) {
    let mut balance_store = PrefixedStorage::new(PREFIX_VIEW_KEY, store);
    balance_store.set(owner.as_slice(), &key.to_hashed());
}

pub fn read_viewing_key(store: &dyn Storage, owner: &CanonicalAddr) -> Option<Vec<u8>> {
    let balance_store = ReadonlyPrefixedStorage::new(PREFIX_VIEW_KEY, store);
    balance_store.get(owner.as_slice())
}

// Receiver Interface

pub fn get_receiver_hash(store: &dyn Storage, account: &Addr) -> Option<StdResult<String>> {
    let store = ReadonlyPrefixedStorage::new(PREFIX_RECEIVERS, store);
    store.get(account.as_str().as_bytes()).map(|data| {
        String::from_utf8(data)
            .map_err(|_err| StdError::invalid_utf8("stored code hash was not a valid String"))
    })
}

pub fn set_receiver_hash(store: &mut dyn Storage, account: &Addr, code_hash: String) {
    let mut store = PrefixedStorage::new(PREFIX_RECEIVERS, store);
    store.set(account.as_str().as_bytes(), code_hash.as_bytes());
}

// Helpers

/// Converts 16 bytes value into u128
/// Errors if data found that is not 16 bytes
fn slice_to_u128(data: &[u8]) -> StdResult<u128> {
    match <[u8; 16]>::try_from(data) {
        Ok(bytes) => Ok(u128::from_be_bytes(bytes)),
        Err(_) => Err(StdError::generic_err(
            "Corrupted data found. 16 byte expected.",
        )),
    }
}

/// Converts 1 byte value into u8
/// Errors if data found that is not 1 byte
fn slice_to_u8(data: &[u8]) -> StdResult<u8> {
    if data.len() == 1 {
        Ok(data[0])
    } else {
        Err(StdError::generic_err(
            "Corrupted data found. 1 byte expected.",
        ))
    }
}
