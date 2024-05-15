use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Api, CanonicalAddr, Coin, StdError, StdResult, Storage, Uint128};

use secret_toolkit::storage::AppendStore;

use crate::state::TX_COUNT;

const PREFIX_TXS: &[u8] = b"transactions";
const PREFIX_TRANSFERS: &[u8] = b"transfers";

// Note that id is a globally incrementing counter.
// Since it's 64 bits long, even at 50 tx/s it would take
// over 11 billion years for it to rollback. I'm pretty sure
// we'll have bigger issues by then.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct Tx {
    pub id: u64,
    pub from: Addr,
    pub sender: Addr,
    pub receiver: Addr,
    pub coins: Coin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    // The block time and block height are optional so that the JSON schema
    // reflects that some SNIP-20 contracts may not include this info.
    pub block_time: Option<u64>,
    pub block_height: Option<u64>,
}

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
pub struct ExtendedTx {
    pub id: u64,
    pub action: TxAction,
    pub coins: Coin,
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

/// This type is the stored version of the legacy transfers
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct StoredLegacyTransfer {
    id: u64,
    from: CanonicalAddr,
    sender: CanonicalAddr,
    receiver: CanonicalAddr,
    coins: StoredCoin,
    memo: Option<String>,
    block_time: u64,
    block_height: u64,
}
static TRANSFERS: AppendStore<StoredLegacyTransfer> = AppendStore::new(PREFIX_TRANSFERS);

impl StoredLegacyTransfer {
    pub fn into_humanized(self, api: &dyn Api) -> StdResult<Tx> {
        let tx = Tx {
            id: self.id,
            from: api.addr_humanize(&self.from)?,
            sender: api.addr_humanize(&self.sender)?,
            receiver: api.addr_humanize(&self.receiver)?,
            coins: self.coins.into(),
            memo: self.memo,
            block_time: Some(self.block_time),
            block_height: Some(self.block_height),
        };
        Ok(tx)
    }

    fn append_transfer(
        store: &mut dyn Storage,
        tx: &StoredLegacyTransfer,
        for_address: &Addr,
    ) -> StdResult<()> {
        let current_addr_store = TRANSFERS.add_suffix(for_address.as_bytes());
        current_addr_store.push(store, tx)
    }

    pub fn get_transfers(
        storage: &dyn Storage,
        api: &dyn Api,
        for_address: Addr,
        page: u32,
        page_size: u32,
    ) -> StdResult<(Vec<Tx>, u64)> {
        let current_addr_store = TRANSFERS.add_suffix(for_address.as_bytes());
        let len = current_addr_store.get_len(storage)? as u64;
        // Take `page_size` txs starting from the latest tx, potentially skipping `page * page_size`
        // txs from the start.
        let transfer_iter = current_addr_store
            .iter(storage)?
            .rev()
            .skip((page * page_size) as _)
            .take(page_size as _);

        // The `and_then` here flattens the `StdResult<StdResult<ExtendedTx>>` to an `StdResult<ExtendedTx>`
        let transfers: StdResult<Vec<Tx>> = transfer_iter
            .map(|tx| tx.map(|tx| tx.into_humanized(api)).and_then(|x| x))
            .collect();
        transfers.map(|txs| (txs, len))
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
struct StoredTxAction {
    tx_type: u8,
    address1: Option<CanonicalAddr>,
    address2: Option<CanonicalAddr>,
    address3: Option<CanonicalAddr>,
}

impl StoredTxAction {
    fn transfer(from: CanonicalAddr, sender: CanonicalAddr, recipient: CanonicalAddr) -> Self {
        Self {
            tx_type: TxCode::Transfer.to_u8(),
            address1: Some(from),
            address2: Some(sender),
            address3: Some(recipient),
        }
    }
    fn mint(minter: CanonicalAddr, recipient: CanonicalAddr) -> Self {
        Self {
            tx_type: TxCode::Mint.to_u8(),
            address1: Some(minter),
            address2: Some(recipient),
            address3: None,
        }
    }
    fn burn(owner: CanonicalAddr, burner: CanonicalAddr) -> Self {
        Self {
            tx_type: TxCode::Burn.to_u8(),
            address1: Some(burner),
            address2: Some(owner),
            address3: None,
        }
    }
    fn deposit() -> Self {
        Self {
            tx_type: TxCode::Deposit.to_u8(),
            address1: None,
            address2: None,
            address3: None,
        }
    }
    fn redeem() -> Self {
        Self {
            tx_type: TxCode::Redeem.to_u8(),
            address1: None,
            address2: None,
            address3: None,
        }
    }

    fn into_tx_action(self, api: &dyn Api) -> StdResult<TxAction> {
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

static TRANSACTIONS: AppendStore<StoredExtendedTx> = AppendStore::new(PREFIX_TXS);

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct StoredExtendedTx {
    id: u64,
    action: StoredTxAction,
    coins: StoredCoin,
    memo: Option<String>,
    block_time: u64,
    block_height: u64,
}

impl StoredExtendedTx {
    fn new(
        id: u64,
        action: StoredTxAction,
        coins: Coin,
        memo: Option<String>,
        block: &cosmwasm_std::BlockInfo,
    ) -> Self {
        Self {
            id,
            action,
            coins: coins.into(),
            memo,
            block_time: block.time.seconds(),
            block_height: block.height,
        }
    }

    fn into_humanized(self, api: &dyn Api) -> StdResult<ExtendedTx> {
        Ok(ExtendedTx {
            id: self.id,
            action: self.action.into_tx_action(api)?,
            coins: self.coins.into(),
            memo: self.memo,
            block_time: self.block_time,
            block_height: self.block_height,
        })
    }

    fn from_stored_legacy_transfer(transfer: StoredLegacyTransfer) -> Self {
        let action = StoredTxAction::transfer(transfer.from, transfer.sender, transfer.receiver);
        Self {
            id: transfer.id,
            action,
            coins: transfer.coins,
            memo: transfer.memo,
            block_time: transfer.block_time,
            block_height: transfer.block_height,
        }
    }

    fn append_tx(
        store: &mut dyn Storage,
        tx: &StoredExtendedTx,
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
    ) -> StdResult<(Vec<ExtendedTx>, u64)> {
        let current_addr_store = TRANSACTIONS.add_suffix(for_address.as_bytes());
        let len = current_addr_store.get_len(storage)? as u64;

        // Take `page_size` txs starting from the latest tx, potentially skipping `page * page_size`
        // txs from the start.
        let tx_iter = current_addr_store
            .iter(storage)?
            .rev()
            .skip((page * page_size) as _)
            .take(page_size as _);

        // The `and_then` here flattens the `StdResult<StdResult<ExtendedTx>>` to an `StdResult<ExtendedTx>`
        let txs: StdResult<Vec<ExtendedTx>> = tx_iter
            .map(|tx| tx.map(|tx| tx.into_humanized(api)).and_then(|x| x))
            .collect();
        txs.map(|txs| (txs, len))
    }
}

// Storage functions:

fn increment_tx_count(store: &mut dyn Storage) -> StdResult<u64> {
    let id = TX_COUNT.load(store).unwrap_or_default() + 1;
    TX_COUNT.save(store, &id)?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)] // We just need them
pub fn store_transfer(
    store: &mut dyn Storage,
    api: &dyn Api,
    owner: &Addr,
    sender: &Addr,
    receiver: &Addr,
    amount: Uint128,
    denom: String,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let id = increment_tx_count(store)?;
    let coins = Coin { denom, amount };
    let transfer = StoredLegacyTransfer {
        id,
        from: api.addr_canonicalize(owner.as_str())?,
        sender: api.addr_canonicalize(sender.as_str())?,
        receiver: api.addr_canonicalize(receiver.as_str())?,
        coins: coins.into(),
        memo,
        block_time: block.time.seconds(),
        block_height: block.height,
    };
    let tx = StoredExtendedTx::from_stored_legacy_transfer(transfer.clone());

    // Write to the owners history if it's different from the other two addresses
    if owner != sender && owner != receiver {
        // cosmwasm_std::debug_print("saving transaction history for owner");
        StoredExtendedTx::append_tx(store, &tx, owner)?;
        StoredLegacyTransfer::append_transfer(store, &transfer, owner)?;
    }
    // Write to the sender's history if it's different from the receiver
    if sender != receiver {
        // cosmwasm_std::debug_print("saving transaction history for sender");
        StoredExtendedTx::append_tx(store, &tx, sender)?;
        StoredLegacyTransfer::append_transfer(store, &transfer, sender)?;
    }
    // Always write to the recipient's history
    // cosmwasm_std::debug_print("saving transaction history for receiver");
    StoredExtendedTx::append_tx(store, &tx, receiver)?;
    StoredLegacyTransfer::append_transfer(store, &transfer, receiver)?;

    Ok(())
}

pub fn store_mint(
    store: &mut dyn Storage,
    api: &dyn Api,
    minter: Addr,
    recipient: Addr,
    amount: Uint128,
    denom: String,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let id = increment_tx_count(store)?;
    let coins = Coin { denom, amount };
    let action = StoredTxAction::mint(
        api.addr_canonicalize(minter.as_str())?, 
        api.addr_canonicalize(recipient.as_str())?
    );
    let tx = StoredExtendedTx::new(id, action, coins, memo, block);

    if minter != recipient {
        StoredExtendedTx::append_tx(store, &tx, &recipient)?;
    }

    StoredExtendedTx::append_tx(store, &tx, &minter)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn store_burn(
    store: &mut dyn Storage,
    api: &dyn Api,
    owner: Addr,
    burner: Addr,
    amount: Uint128,
    denom: String,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let id = increment_tx_count(store)?;
    let coins = Coin { denom, amount };
    let action = StoredTxAction::burn(
        api.addr_canonicalize(owner.as_str())?, 
        api.addr_canonicalize(burner.as_str())?
    );
    let tx = StoredExtendedTx::new(id, action, coins, memo, block);

    if burner != owner {
        StoredExtendedTx::append_tx(store, &tx, &owner)?;
    }

    StoredExtendedTx::append_tx(store, &tx, &burner)?;

    Ok(())
}

pub fn store_deposit(
    store: &mut dyn Storage,
    recipient: &Addr,
    amount: Uint128,
    denom: String,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let id = increment_tx_count(store)?;
    let coins = Coin { denom, amount };
    let action = StoredTxAction::deposit();
    let tx = StoredExtendedTx::new(id, action, coins, None, block);

    StoredExtendedTx::append_tx(store, &tx, recipient)?;

    Ok(())
}

pub fn store_redeem(
    store: &mut dyn Storage,
    redeemer: &Addr,
    amount: Uint128,
    denom: String,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let id = increment_tx_count(store)?;
    let coins = Coin { denom, amount };
    let action = StoredTxAction::redeem();
    let tx = StoredExtendedTx::new(id, action, coins, None, block);

    StoredExtendedTx::append_tx(store, &tx, redeemer)?;

    Ok(())
}