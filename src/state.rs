use bincode2;

use cosmwasm_std::{CanonicalAddr, Storage, StdResult, StdError};

pub static CONFIG_KEY: &[u8] = b"config";

pub const CONTRACT_ADDRESS: &[u8] = "contract_address".as_bytes();

pub fn store_address<S: Storage>(storage: &mut S, address: &CanonicalAddr) {
    let address_bytes: Vec<u8> = bincode2::serialize(&address).unwrap();

    storage.set(&CONTRACT_ADDRESS, &address_bytes);
}

pub fn get_address<S: Storage>(storage: &mut S) -> StdResult<CanonicalAddr> {

    if let Some(address_bytes) = storage.get(&CONTRACT_ADDRESS) {
        let record: CanonicalAddr = bincode2::deserialize(&address_bytes).unwrap();
        Ok(record)
    } else {
        Err(StdError::GenericErr {
            msg: "Privacy token not available for this token".to_string(),
            backtrace: None,
        })
    }

}