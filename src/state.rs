use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, StdError, StdResult, Storage};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use secret_toolkit::serialization::Json;
use secret_toolkit::storage::{Item, Keymap};

use crate::msg::ContractStatusLevel;

pub static CONFIG_KEY: &[u8] = b"config";

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

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
pub struct Constants {
    pub name: String,
    pub admin: Addr,
    pub symbol: String,
    pub decimals: u8,
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
impl Constants {
    pub fn load(store: &dyn Storage) -> StdResult<Constants> {
        CONSTANTS
            .load(store)
            .map_err(|_err| StdError::generic_err("no constants stored"))
    }

    pub fn save(store: &mut dyn Storage, constants: &Constants) -> StdResult<()> {
        CONSTANTS.save(store, constants)
    }
}

pub static TOTAL_SUPPLY: Item<u128> = Item::new(KEY_TOTAL_SUPPLY);
pub struct TotalSupplyStore {}
impl TotalSupplyStore {
    pub fn load(store: &dyn Storage) -> StdResult<u128> {
        TOTAL_SUPPLY
            .load(store)
            .map_err(|_err| StdError::generic_err("no total supply stored"))
    }

    pub fn save(store: &mut dyn Storage, supply: u128) -> StdResult<()> {
        TOTAL_SUPPLY.save(store, &supply)
    }
}

pub static CONTRACT_STATUS: Item<ContractStatusLevel, Json> = Item::new(KEY_CONTRACT_STATUS);
pub struct ContractStatusStore {}
impl ContractStatusStore {
    pub fn load(store: &dyn Storage) -> StdResult<ContractStatusLevel> {
        CONTRACT_STATUS
            .load(store)
            .map_err(|_err| StdError::generic_err("no contract status stored"))
    }

    pub fn save(store: &mut dyn Storage, status: ContractStatusLevel) -> StdResult<()> {
        CONTRACT_STATUS.save(store, &status)
    }
}

pub static MINTERS: Item<Vec<Addr>> = Item::new(KEY_MINTERS);
pub struct MintersStore {}
impl MintersStore {
    pub fn load(store: &dyn Storage) -> StdResult<Vec<Addr>> {
        MINTERS
            .load(store)
            .map_err(|_err| StdError::generic_err(""))
    }

    pub fn save(store: &mut dyn Storage, minters_to_set: Vec<Addr>) -> StdResult<()> {
        MINTERS.save(store, &minters_to_set)
    }

    pub fn add_minters(store: &mut dyn Storage, minters_to_add: Vec<Addr>) -> StdResult<()> {
        let mut loaded_minters = MINTERS
            .load(store)
            .map_err(|_err| StdError::not_found("Key not found in storage"))?;

        loaded_minters.extend(minters_to_add);

        MINTERS.save(store, &loaded_minters)
    }

    pub fn remove_minters(store: &mut dyn Storage, minters_to_remove: Vec<Addr>) -> StdResult<()> {
        let mut loaded_minters = MINTERS
            .load(store)
            .map_err(|_err| StdError::generic_err(""))?;

        for minter in minters_to_remove {
            loaded_minters.retain(|x| x != &minter);
        }

        MINTERS.save(store, &loaded_minters)
    }
}

pub static TX_COUNT: Item<u64> = Item::new(KEY_TX_COUNT);
pub struct TxCountStore {}
impl TxCountStore {
    pub fn load(store: &dyn Storage) -> u64 {
        TX_COUNT.load(store).unwrap_or_default()
    }

    pub fn save(store: &mut dyn Storage, count: u64) -> StdResult<()> {
        TX_COUNT.save(store, &count)
    }
}

pub static BALANCES: Keymap<Addr, u128> = Keymap::new(PREFIX_BALANCES);
pub struct BalancesStore {}
impl BalancesStore {
    pub fn load(store: &dyn Storage, account: &Addr) -> u128 {
        BALANCES.get(store, account).unwrap_or_default()
    }

    pub fn save(store: &mut dyn Storage, account: &Addr, amount: u128) -> StdResult<()> {
        BALANCES.insert(store, account, &amount)
    }
}

// Allowances

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, Eq, Default, JsonSchema)]
pub struct Allowance {
    pub amount: u128,
    pub expiration: Option<u64>,
}

impl Allowance {
    pub fn is_expired_at(&self, block: &cosmwasm_std::BlockInfo) -> bool {
        match self.expiration {
            Some(time) => block.time.seconds() >= time,
            None => false, // allowance has no expiration
        }
    }
}

pub static ALLOWANCES: Keymap<(Addr, Addr), Allowance> = Keymap::new(PREFIX_ALLOWANCES);
pub struct AllowancesStore {}
impl AllowancesStore {
    pub fn load(store: &dyn Storage, owner: &Addr, spender: &Addr) -> Allowance {
        ALLOWANCES
            .get(store, &(owner.clone(), spender.clone()))
            .unwrap_or_default()
    }

    pub fn save(
        store: &mut dyn Storage,
        owner: &Addr,
        spender: &Addr,
        allowance: &Allowance,
    ) -> StdResult<()> {
        ALLOWANCES.insert(store, &(owner.clone(), spender.clone()), allowance)
    }
}

// Receiver Interface

pub fn get_receiver_hash(store: &dyn Storage, account: &Addr) -> Option<StdResult<String>> {
    let store = ReadonlyPrefixedStorage::new(store, PREFIX_RECEIVERS);
    store.get(account.as_str().as_bytes()).map(|data| {
        String::from_utf8(data)
            .map_err(|_err| StdError::invalid_utf8("stored code hash was not a valid String"))
    })
}

pub fn set_receiver_hash(store: &mut dyn Storage, account: &Addr, code_hash: String) {
    let mut store = PrefixedStorage::new(store, PREFIX_RECEIVERS);
    store.set(account.as_str().as_bytes(), code_hash.as_bytes());
}
