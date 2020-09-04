use crate::utils::ConstLenStr;
use bincode2;
use core::fmt;
use cosmwasm_std::{
    Api, CanonicalAddr, Coin, HumanAddr, ReadonlyStorage, StdError, StdResult, Storage, Uint128,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use serde::export::Formatter;
use serde::{Deserialize, Serialize};
use std::path::Display;

pub static CONFIG_KEY: &[u8] = b"config";
pub const PREFIX_TXS: &[u8] = b"transfers";

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
    amount: &Uint128,
    symbol: String,
) {
    let sender = api.human_address(from_address).unwrap();
    let receiver = api.human_address(to_address).unwrap();
    let coins = Coin {
        denom: symbol,
        amount: amount.clone(),
    };

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
