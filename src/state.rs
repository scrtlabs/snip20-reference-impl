use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, StdError, StdResult, Storage};
use secret_toolkit::serialization::Json;
use secret_toolkit::storage::{Item, Keymap};

use crate::msg::ContractStatusLevel;

pub const KEY_CONFIG: &[u8] = b"config";
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

#[derive(Serialize, Debug, Deserialize, Clone, JsonSchema)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Config {
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
    // coin denoms that are supported for deposit/redeem
    pub supported_denoms: Vec<String>,
    // can admin add or remove supported denoms
    pub can_modify_denoms: bool,
}

pub static CONFIG: Item<Config> = Item::new(KEY_CONFIG);

pub static TOTAL_SUPPLY: Item<u128> = Item::new(KEY_TOTAL_SUPPLY);

pub static CONTRACT_STATUS: Item<ContractStatusLevel, Json> = Item::new(KEY_CONTRACT_STATUS);

pub static MINTERS: Item<Vec<Addr>> = Item::new(KEY_MINTERS);

pub static TX_COUNT: Item<u64> = Item::new(KEY_TX_COUNT);

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

pub static BALANCES: Item<u128> = Item::new(PREFIX_BALANCES);
pub struct BalancesStore {}
impl BalancesStore {
    pub fn load(store: &dyn Storage, account: &Addr) -> u128 {
        let balances = BALANCES.add_suffix(account.as_str().as_bytes());
        balances.load(store).unwrap_or_default()
    }

    pub fn save(store: &mut dyn Storage, account: &Addr, amount: u128) -> StdResult<()> {
        let balances = BALANCES.add_suffix(account.as_str().as_bytes());
        balances.save(store, &amount)
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
pub static RECEIVER_HASH: Item<String> = Item::new(PREFIX_RECEIVERS);
pub struct ReceiverHashStore {}
impl ReceiverHashStore {
    pub fn may_load(store: &dyn Storage, account: &Addr) -> StdResult<Option<String>> {
        let receiver_hash = RECEIVER_HASH.add_suffix(account.as_str().as_bytes());
        receiver_hash.may_load(store)
    }

    pub fn save(store: &mut dyn Storage, account: &Addr, code_hash: String) -> StdResult<()> {
        let receiver_hash = RECEIVER_HASH.add_suffix(account.as_str().as_bytes());
        receiver_hash.save(store, &code_hash)
    }
}
