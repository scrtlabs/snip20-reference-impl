use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Api, BlockInfo, CanonicalAddr, Coin, StdError, StdResult, Storage, Uint128};

use secret_toolkit::storage::{AppendStore, Item};

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
// Since it's 64 bits long, even at 50 tx/s it would take
// over 11 billion years for it to rollback. I'm pretty sure
// we'll have bigger issues by then.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Tx {
    pub id: u64,
    pub action: TxAction,
    pub amount: Uint128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
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
                    recipient: api.addr_humanize(&recipient)?
                }
            }
            TxCode::Burn => {
                let burner = self.address1.ok_or_else(burn_addr_err)?;
                let owner = self.address2.ok_or_else(burn_addr_err)?;
                TxAction::Burn { 
                    burner: api.addr_humanize(&burner)?,
                    owner: api.addr_humanize(&owner)? 
                }
            }
            TxCode::Deposit => TxAction::Deposit {},
            TxCode::Redeem => TxAction::Redeem {},
        };

        Ok(action)
    }
}

// use with add_suffix tx id (u64)
// does not need to be an AppendStore because we never need to iterate over global list of txs
static TRANSACTIONS: Item<StoredTx> = Item::new(PREFIX_TXS);

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct StoredTx {
    action: StoredTxAction,
    amount: u128,
    memo: Option<String>,
    block_time: u64,
    block_height: u64,
}

impl StoredTx {
    fn new(
        id: u64,
        action: StoredTxAction,
        amount: Uint128,
        memo: Option<String>,
        block: &cosmwasm_std::BlockInfo,
    ) -> Self {
        Self {
            action,
            amount: amount.u128(),
            memo,
            block_time: block.time.seconds(),
            block_height: block.height,
        }
    }

    fn into_humanized(self, api: &dyn Api, id: u64) -> StdResult<Tx> {
        Ok(Tx {
            id,
            action: self.action.into_tx_action(api)?,
            amount: Uint128::from(self.amount),
            memo: self.memo,
            block_time: self.block_time,
            block_height: self.block_height,
        })
    }

/*
    fn append_tx(
        store: &mut dyn Storage,
        tx: &StoredTx,
        for_address: &Addr,
    ) -> StdResult<()> {
        let current_addr_store = TRANSACTIONS.add_suffix(for_address.as_bytes());
        current_addr_store.push(store, tx)
    }

    pub fn get_txs(
        storage: &dyn Storage,
        api: &dyn Api,
        for_address: Addr,
        page: u32,
        page_size: u32,
    ) -> StdResult<(Vec<Tx>, u64)> {
        let current_addr_store = TRANSACTIONS.add_suffix(for_address.as_bytes());
        let len = current_addr_store.get_len(storage)? as u64;

        // Take `page_size` txs starting from the latest tx, potentially skipping `page * page_size`
        // txs from the start.
        let tx_iter = current_addr_store
            .iter(storage)?
            .rev()
            .skip((page * page_size) as _)
            .take(page_size as _);

        // The `and_then` here flattens the `StdResult<StdResult<Tx>>` to an `StdResult<Tx>`
        let txs: StdResult<Vec<Tx>> = tx_iter
            .map(|tx| tx.map(|tx| tx.into_humanized(api)).and_then(|x| x))
            .collect();
        txs.map(|txs| (txs, len))
    }
*/
}

// Storage functions:

fn increment_tx_count(store: &mut dyn Storage) -> StdResult<u64> {
    let id = TX_COUNT.load(store).unwrap_or_default() + 1;
    TX_COUNT.save(store, &id)?;
    Ok(id)
}

pub fn append_new_stored_tx(
    store: &mut dyn Storage,
    action: &StoredTxAction,
    amount: u128,
    memo: Option<String>,
    block: &BlockInfo,
) -> StdResult<u64> {
    let id = TX_COUNT.load(store).unwrap_or_default();
    let stored_tx = StoredTx {
        action: action.clone(),
        amount,
        memo,
        block_time: block.time.seconds(),
        block_height: block.height,
    };

    TRANSACTIONS.add_suffix(&id.to_be_bytes()).save(store, &stored_tx)?;
    TX_COUNT.save(store, &(id+1))?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)] // We just need them
pub fn store_transfer(
    store: &mut dyn Storage,
    owner: &CanonicalAddr,
    sender: &CanonicalAddr,
    receiver: &CanonicalAddr,
    amount: u128,
    memo: Option<String>,
    block: &BlockInfo,
) -> StdResult<u64> {
    let action = StoredTxAction::transfer(
        owner.clone(), 
        sender.clone(), 
        receiver.clone()
    );
    append_new_stored_tx(store, &action, amount, memo, block)
/*
    // Write to the owners history if it's different from the other two addresses
    // TODO: check if we want to always write this. 
    if owner != sender && owner != receiver {
        // cosmwasm_std::debug_print("saving transaction history for owner");
        StoredTx::append_tx(store, &tx, owner)?;
    }
    // Write to the sender's history if it's different from the receiver
    if sender != receiver {
        // cosmwasm_std::debug_print("saving transaction history for sender");
        StoredTx::append_tx(store, &tx, sender)?;
    }
    // Always write to the recipient's history
    // cosmwasm_std::debug_print("saving transaction history for receiver");
    StoredTx::append_tx(store, &tx, receiver)?;
*/
}

pub fn store_mint(
    store: &mut dyn Storage,
    api: &dyn Api,
    minter: CanonicalAddr,
    recipient: CanonicalAddr,
    amount: u128,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let action = StoredTxAction::mint(
        minter, 
        recipient
    );
    let id = append_new_stored_tx(store, &action, amount, memo, block)?;

/*
    if minter != recipient {
        StoredTx::append_tx(store, &tx, &recipient)?;
    }

    StoredTx::append_tx(store, &tx, &minter)?;
*/

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn store_burn(
    store: &mut dyn Storage,
    api: &dyn Api,
    owner: CanonicalAddr,
    burner: CanonicalAddr,
    amount: u128,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let action = StoredTxAction::burn(
        owner, 
        burner
    );
    let id = append_new_stored_tx(store, &action, amount, memo, block)?;

/*
    if burner != owner {
        StoredTx::append_tx(store, &tx, &owner)?;
    }

    StoredTx::append_tx(store, &tx, &burner)?;
*/

    Ok(())
}

pub fn store_deposit(
    store: &mut dyn Storage,
    recipient: &CanonicalAddr,
    amount: u128,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let action = StoredTxAction::deposit();
    let id = append_new_stored_tx(store, &action, amount, None, block)?;

/*
    StoredTx::append_tx(store, &tx, recipient)?;
*/

    Ok(())
}

pub fn store_redeem(
    store: &mut dyn Storage,
    redeemer: &CanonicalAddr,
    amount: u128,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let action = StoredTxAction::redeem();
    let id = append_new_stored_tx(store, &action, amount, None, block)?;

/*
    StoredTx::append_tx(store, &tx, redeemer)?;
*/

    Ok(())
}