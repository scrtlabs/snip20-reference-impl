use std::any::type_name;
use std::convert::TryFrom;

use cosmwasm_std::{
    Api, CanonicalAddr, Coin, HumanAddr, ReadonlyStorage, StdError, StdResult, Storage, Uint128,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::viewing_key::ViewingKey;

pub static CONFIG_KEY: &[u8] = b"config";
pub const PREFIX_TXS: &[u8] = b"transfers";

pub const PREFIX_CONFIG: &[u8] = b"config";
pub const PREFIX_BALANCES: &[u8] = b"balances";
pub const PREFIX_ALLOWANCES: &[u8] = b"allowances";
pub const PREFIX_VIEW_KEY: &[u8] = b"viewingkey";
pub const KEY_CONSTANTS: &[u8] = b"constants";
pub const KEY_TOTAL_SUPPLY: &[u8] = b"total_supply";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Tx {
    pub sender: HumanAddr,
    pub receiver: HumanAddr,
    pub coins: Coin,
}

/// This is here so we can create constant length transactions if we want to return this on-chain instead of a query
impl Default for Tx {
    fn default() -> Self {
        Self {
            sender: Default::default(),
            receiver: Default::default(),
            coins: Coin {
                denom: "EMPT".to_string(),
                amount: Uint128::zero(),
            },
        }
    }
}

// impl fmt::Debug for Coin {
//     fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
//         format!("{} {}", ConstLenStr(self.denom.clone()), ConstLenStr(self.amount.to_string())).fmt(f)
//     }
// }

pub fn store_transfer<A: Api, S: Storage>(
    api: &A,
    storage: &mut S,
    from_address: &CanonicalAddr,
    to_address: &CanonicalAddr,
    amount: Uint128,
    denom: String,
) {
    let sender = api.human_address(from_address).unwrap();
    let receiver = api.human_address(to_address).unwrap();
    let coins = Coin { denom, amount };

    let tx = Tx {
        sender,
        receiver,
        coins,
    };

    let mut store = PrefixedStorage::new(PREFIX_TXS, storage);

    append_tx(&mut store, &tx, from_address);
    append_tx(&mut store, &tx, to_address);
}

fn append_tx<S: Storage>(store: &mut PrefixedStorage<S>, tx: &Tx, for_address: &CanonicalAddr) {
    let mut new_txs: Vec<Tx> = vec![];

    let txs = store.get(for_address.as_slice());

    if let Some(txs_bytes) = txs {
        new_txs = bincode2::deserialize(txs_bytes.as_slice()).unwrap();
    }

    new_txs.push(tx.clone());

    let tx_bytes: Vec<u8> = bincode2::serialize(&new_txs).unwrap();

    store.set(for_address.as_slice(), &tx_bytes);
}

pub fn get_transfers<S: Storage>(storage: &S, for_address: &CanonicalAddr) -> StdResult<Vec<Tx>> {
    let store = ReadonlyPrefixedStorage::new(PREFIX_TXS, storage);

    if let Some(tx_bytes) = store.get(for_address.as_slice()) {
        let txs: Vec<Tx> = bincode2::deserialize(&tx_bytes).unwrap();
        Ok(txs)
    } else {
        Ok(vec![])
    }
}

// Config

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, JsonSchema)]
pub struct Constants {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

pub struct ReadonlyConfig<'a, S: ReadonlyStorage> {
    storage: ReadonlyPrefixedStorage<'a, S>,
}

impl<'a, S: ReadonlyStorage> ReadonlyConfig<'a, S> {
    pub fn from_storage(storage: &'a S) -> Self {
        Self {
            storage: ReadonlyPrefixedStorage::new(PREFIX_CONFIG, storage),
        }
    }

    fn as_readonly(&self) -> ReadonlyConfigImpl<ReadonlyPrefixedStorage<S>> {
        ReadonlyConfigImpl(&self.storage)
    }

    pub fn constants(&self) -> StdResult<Constants> {
        self.as_readonly().constants()
    }

    pub fn total_supply(&self) -> u128 {
        self.as_readonly().total_supply()
    }
}

pub struct Config<'a, S: Storage> {
    storage: PrefixedStorage<'a, S>,
}

impl<'a, S: Storage> Config<'a, S> {
    pub fn from_storage(storage: &'a mut S) -> Self {
        Self {
            storage: PrefixedStorage::new(PREFIX_CONFIG, storage),
        }
    }

    fn as_readonly(&self) -> ReadonlyConfigImpl<PrefixedStorage<S>> {
        ReadonlyConfigImpl(&self.storage)
    }

    pub fn constants(&self) -> StdResult<Constants> {
        self.as_readonly().constants()
    }

    pub fn set_constants(&mut self, constants: &Constants) -> StdResult<()> {
        let constants = bincode2::serialize(&constants)
            .map_err(|e| StdError::serialize_err(type_name::<Constants>(), e))?;

        self.storage.set(KEY_CONSTANTS, &constants);
        Ok(())
    }

    pub fn total_supply(&self) -> u128 {
        self.as_readonly().total_supply()
    }

    pub fn set_total_supply(&mut self, supply: u128) {
        self.storage.set(KEY_TOTAL_SUPPLY, &supply.to_be_bytes());
    }
}

/// This struct refactors out the readonly methods that we need for `Config` and `ReadonlyConfig`
/// in a way that is generic over their mutability.
///
/// This was the only way to prevent code duplication of these methods because of the way
/// that `ReadonlyPrefixedStorage` and `PrefixedStorage` are implemented in `cosmwasm-std`
struct ReadonlyConfigImpl<'a, S: ReadonlyStorage>(&'a S);

impl<'a, S: ReadonlyStorage> ReadonlyConfigImpl<'a, S> {
    fn constants(&self) -> StdResult<Constants> {
        let consts_bytes = self
            .0
            .get(KEY_CONSTANTS)
            .ok_or_else(|| StdError::generic_err("no constants stored in configuration"))?;
        bincode2::deserialize::<Constants>(&consts_bytes)
            .map_err(|e| StdError::serialize_err(type_name::<Constants>(), e))
    }

    fn total_supply(&self) -> u128 {
        let supply_bytes = self
            .0
            .get(KEY_TOTAL_SUPPLY)
            .expect("no total supply stored in config");
        // This unwrap is ok because we know we stored things correctly
        slice_to_u128(&supply_bytes).unwrap()
    }
}

// Balances

pub struct ReadonlyBalances<'a, S: ReadonlyStorage> {
    storage: ReadonlyPrefixedStorage<'a, S>,
}

impl<'a, S: ReadonlyStorage> ReadonlyBalances<'a, S> {
    pub fn from_storage(storage: &'a S) -> Self {
        Self {
            storage: ReadonlyPrefixedStorage::new(PREFIX_BALANCES, storage),
        }
    }

    fn as_readonly(&self) -> ReadonlyBalancesImpl<ReadonlyPrefixedStorage<S>> {
        ReadonlyBalancesImpl(&self.storage)
    }

    pub fn account_amount(&self, account: &CanonicalAddr) -> u128 {
        self.as_readonly().account_amount(account)
    }
}

pub struct Balances<'a, S: Storage> {
    storage: PrefixedStorage<'a, S>,
}

impl<'a, S: Storage> Balances<'a, S> {
    pub fn from_storage(storage: &'a mut S) -> Self {
        Self {
            storage: PrefixedStorage::new(PREFIX_BALANCES, storage),
        }
    }

    fn as_readonly(&self) -> ReadonlyBalancesImpl<PrefixedStorage<S>> {
        ReadonlyBalancesImpl(&self.storage)
    }

    pub fn account_amount(&self, account: &CanonicalAddr) -> u128 {
        self.as_readonly().account_amount(account)
    }

    pub fn set_account_balance(&mut self, account: &CanonicalAddr, amount: u128) {
        self.storage.set(account.as_slice(), &amount.to_be_bytes())
    }
}

/// This struct refactors out the readonly methods that we need for `Balances` and `ReadonlyBalances`
/// in a way that is generic over their mutability.
///
/// This was the only way to prevent code duplication of these methods because of the way
/// that `ReadonlyPrefixedStorage` and `PrefixedStorage` are implemented in `cosmwasm-std`
struct ReadonlyBalancesImpl<'a, S: ReadonlyStorage>(&'a S);

impl<'a, S: ReadonlyStorage> ReadonlyBalancesImpl<'a, S> {
    pub fn account_amount(&self, account: &CanonicalAddr) -> u128 {
        let account_bytes = account.as_slice();
        let result = self.0.get(account_bytes);
        match result {
            // This unwrap is ok because we know we stored things correctly
            Some(balance_bytes) => slice_to_u128(&balance_bytes).unwrap(),
            None => 0,
        }
    }
}

// Allowances

pub fn read_allowance<S: Storage>(
    store: &S,
    owner: &CanonicalAddr,
    spender: &CanonicalAddr,
) -> StdResult<u128> {
    let allowances_store = ReadonlyPrefixedStorage::new(PREFIX_ALLOWANCES, store);
    let owner_store = ReadonlyPrefixedStorage::new(owner.as_slice(), &allowances_store);
    let result = owner_store.get(spender.as_slice());
    match result {
        Some(data) => slice_to_u128(&data),
        None => Ok(0u128),
    }
}

pub fn write_allowance<S: Storage>(
    store: &mut S,
    owner: &CanonicalAddr,
    spender: &CanonicalAddr,
    amount: u128,
) -> StdResult<()> {
    let mut allowances_store = PrefixedStorage::new(PREFIX_ALLOWANCES, store);
    let mut owner_store = PrefixedStorage::new(owner.as_slice(), &mut allowances_store);
    owner_store.set(spender.as_slice(), &amount.to_be_bytes());
    Ok(())
}

// Viewing Keys

pub fn write_viewing_key<S: Storage>(
    store: &mut S,
    owner: &CanonicalAddr,
    key: &ViewingKey,
) -> StdResult<()> {
    let mut balance_store = PrefixedStorage::new(PREFIX_VIEW_KEY, store);
    balance_store.set(owner.as_slice(), key.to_hashed().as_ref());
    Ok(())
}

pub fn read_viewing_key<S: Storage>(store: &S, owner: &CanonicalAddr) -> Option<Vec<u8>> {
    let balance_store = ReadonlyPrefixedStorage::new(PREFIX_VIEW_KEY, store);
    balance_store.get(owner.as_slice())
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
