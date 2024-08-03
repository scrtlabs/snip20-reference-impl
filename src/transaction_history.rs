use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{
    Addr, Api, BlockInfo, CanonicalAddr, Coin, StdError, StdResult, Storage, Uint128,
};

use secret_toolkit::storage::Item;

use crate::state::TX_COUNT;

const PREFIX_TXS: &[u8] = b"transactions";

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TxAction {
    Transfer {
        from: Addr,
        sender: Addr,
        recipient: Addr,
    },
    Mint {
        minter: Addr,
        recipient: Addr,
    },
    Burn {
        burner: Addr,
        owner: Addr,
    },
    Deposit {},
    Redeem {},
}

// Note that id is a globally incrementing counter.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Tx {
    pub id: u64,
    pub action: TxAction,
    pub coins: Coin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    // The block time and block height are optional so that the JSON schema
    // reflects that some SNIP-20 contracts may not include this info.
    pub block_time: u64,
    pub block_height: u64,
}

// Stored types:

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
pub struct StoredCoin {
    pub denom: String,
    pub amount: u128,
}

impl From<Coin> for StoredCoin {
    fn from(value: Coin) -> Self {
        Self {
            denom: value.denom,
            amount: value.amount.u128(),
        }
    }
}

impl From<StoredCoin> for Coin {
    fn from(value: StoredCoin) -> Self {
        Self {
            denom: value.denom,
            amount: Uint128::new(value.amount),
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum TxCode {
    Transfer = 0,
    Mint = 1,
    Burn = 2,
    Deposit = 3,
    Redeem = 4,
}

impl TxCode {
    fn to_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(n: u8) -> StdResult<Self> {
        use TxCode::*;
        match n {
            0 => Ok(Transfer),
            1 => Ok(Mint),
            2 => Ok(Burn),
            3 => Ok(Deposit),
            4 => Ok(Redeem),
            other => Err(StdError::generic_err(format!(
                "Unexpected Tx code in transaction history: {} Storage is corrupted.",
                other
            ))),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct StoredTxAction {
    tx_type: u8,
    address1: Option<CanonicalAddr>,
    address2: Option<CanonicalAddr>,
    address3: Option<CanonicalAddr>,
}

impl StoredTxAction {
    pub fn transfer(from: CanonicalAddr, sender: CanonicalAddr, recipient: CanonicalAddr) -> Self {
        Self {
            tx_type: TxCode::Transfer.to_u8(),
            address1: Some(from),
            address2: Some(sender),
            address3: Some(recipient),
        }
    }
    pub fn mint(minter: CanonicalAddr, recipient: CanonicalAddr) -> Self {
        Self {
            tx_type: TxCode::Mint.to_u8(),
            address1: Some(minter),
            address2: Some(recipient),
            address3: None,
        }
    }
    pub fn burn(owner: CanonicalAddr, burner: CanonicalAddr) -> Self {
        Self {
            tx_type: TxCode::Burn.to_u8(),
            address1: Some(burner),
            address2: Some(owner),
            address3: None,
        }
    }
    pub fn deposit() -> Self {
        Self {
            tx_type: TxCode::Deposit.to_u8(),
            address1: None,
            address2: None,
            address3: None,
        }
    }
    pub fn redeem() -> Self {
        Self {
            tx_type: TxCode::Redeem.to_u8(),
            address1: None,
            address2: None,
            address3: None,
        }
    }

    pub fn into_tx_action(self, api: &dyn Api) -> StdResult<TxAction> {
        let transfer_addr_err = || {
            StdError::generic_err(
                "Missing address in stored Transfer transaction. Storage is corrupt",
            )
        };
        let mint_addr_err = || {
            StdError::generic_err("Missing address in stored Mint transaction. Storage is corrupt")
        };
        let burn_addr_err = || {
            StdError::generic_err("Missing address in stored Burn transaction. Storage is corrupt")
        };

        // In all of these, we ignore fields that we don't expect to find populated
        let action = match TxCode::from_u8(self.tx_type)? {
            TxCode::Transfer => {
                let from = self.address1.ok_or_else(transfer_addr_err)?;
                let sender = self.address2.ok_or_else(transfer_addr_err)?;
                let recipient = self.address3.ok_or_else(transfer_addr_err)?;
                TxAction::Transfer {
                    from: api.addr_humanize(&from)?,
                    sender: api.addr_humanize(&sender)?,
                    recipient: api.addr_humanize(&recipient)?,
                }
            }
            TxCode::Mint => {
                let minter = self.address1.ok_or_else(mint_addr_err)?;
                let recipient = self.address2.ok_or_else(mint_addr_err)?;
                TxAction::Mint {
                    minter: api.addr_humanize(&minter)?,
                    recipient: api.addr_humanize(&recipient)?,
                }
            }
            TxCode::Burn => {
                let burner = self.address1.ok_or_else(burn_addr_err)?;
                let owner = self.address2.ok_or_else(burn_addr_err)?;
                TxAction::Burn {
                    burner: api.addr_humanize(&burner)?,
                    owner: api.addr_humanize(&owner)?,
                }
            }
            TxCode::Deposit => TxAction::Deposit {},
            TxCode::Redeem => TxAction::Redeem {},
        };

        Ok(action)
    }
}

// use with add_suffix tx id (u64 to_be_bytes)
// does not need to be an AppendStore because we never need to iterate over global list of txs
pub static TRANSACTIONS: Item<StoredTx> = Item::new(PREFIX_TXS);

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct StoredTx {
    action: StoredTxAction,
    coins: StoredCoin,
    memo: Option<String>,
    block_time: u64,
    block_height: u64,
}

impl StoredTx {
    pub fn into_humanized(self, api: &dyn Api, id: u64) -> StdResult<Tx> {
        Ok(Tx {
            id,
            action: self.action.into_tx_action(api)?,
            coins: self.coins.into(),
            memo: self.memo,
            block_time: self.block_time,
            block_height: self.block_height,
        })
    }
}

// Storage functions:

pub fn append_new_stored_tx(
    store: &mut dyn Storage,
    action: &StoredTxAction,
    amount: u128,
    denom: String,
    memo: Option<String>,
    block: &BlockInfo,
) -> StdResult<u64> {
    // tx ids are serialized starting at 1
    let serial_id = TX_COUNT.load(store).unwrap_or_default() + 1;
    let coins = StoredCoin { denom, amount };
    let stored_tx = StoredTx {
        action: action.clone(),
        coins,
        memo,
        block_time: block.time.seconds(),
        block_height: block.height,
    };

    TRANSACTIONS
        .add_suffix(&serial_id.to_be_bytes())
        .save(store, &stored_tx)?;
    TX_COUNT.save(store, &(serial_id))?;
    Ok(serial_id)
}

#[allow(clippy::too_many_arguments)] // We just need them
pub fn store_transfer_action(
    store: &mut dyn Storage,
    owner: &CanonicalAddr,
    sender: &CanonicalAddr,
    receiver: &CanonicalAddr,
    amount: u128,
    denom: String,
    memo: Option<String>,
    block: &BlockInfo,
) -> StdResult<u64> {
    let action = StoredTxAction::transfer(owner.clone(), sender.clone(), receiver.clone());
    append_new_stored_tx(store, &action, amount, denom, memo, block)
}

pub fn store_mint_action(
    store: &mut dyn Storage,
    minter: &CanonicalAddr,
    recipient: &CanonicalAddr,
    amount: u128,
    denom: String,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<u64> {
    let action = StoredTxAction::mint(minter.clone(), recipient.clone());
    append_new_stored_tx(store, &action, amount, denom, memo, block)
}

#[allow(clippy::too_many_arguments)]
pub fn store_burn_action(
    store: &mut dyn Storage,
    owner: CanonicalAddr,
    burner: CanonicalAddr,
    amount: u128,
    denom: String,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<u64> {
    let action = StoredTxAction::burn(owner, burner);
    append_new_stored_tx(store, &action, amount, denom, memo, block)
}

pub fn store_deposit_action(
    store: &mut dyn Storage,
    amount: u128,
    denom: String,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<u64> {
    let action = StoredTxAction::deposit();
    append_new_stored_tx(store, &action, amount, denom, None, block)
}

pub fn store_redeem_action(
    store: &mut dyn Storage,
    amount: u128,
    denom: String,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<u64> {
    let action = StoredTxAction::redeem();
    append_new_stored_tx(store, &action, amount, denom, None, block)
}
