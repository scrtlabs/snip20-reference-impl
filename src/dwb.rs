use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use cosmwasm_std::{CanonicalAddr, StdError, StdResult, Storage};
use secret_toolkit::storage::{AppendStore, Item};

use crate::transaction_history::Tx;

pub const DWB_LEN: u16 = 64;
pub const KEY_DWB: &[u8] = b"dwb";
pub const KEY_TX_NODES: &[u8] = b"dwb-tx-nodes";
pub const KEY_ACCOUNT_TXS: &[u8] = b"dwb-acc-txs";
pub const KEY_ACCOUNT_TX_COUNT: &[u8] = b"dwb-acc-tx-cnt";

pub static DWB: Item<DelayedWriteBuffer> = Item::new(KEY_DWB);
// tx nodes used in linked lists
pub static TX_NODES: AppendStore<TxNode> = AppendStore::new(KEY_TX_NODES);

#[derive(Serialize, Deserialize, Debug)]
pub struct DelayedWriteBuffer {
    pub empty_space_counter: u16,
    pub elements: Vec<DelayedWriteBufferElement>,
}

impl DelayedWriteBuffer {
    #[inline]
    pub fn saturated(&self) -> bool {
        self.empty_space_counter == 0
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DelayedWriteBufferElement {
    pub recipient: CanonicalAddr,
    /// aggregate amount for the tx nodes 
    pub amount: u128,
    /// length of the tx node linked list for this element
    pub list_len: u32,
    /// TX_NODES idx - pointer to the head node in the linked list
    ///   None if the list_len == 0
    pub head_node: Option<u32>,
}

impl DelayedWriteBufferElement {
    pub fn new(recipient: CanonicalAddr) -> Self {
        Self {
            recipient,
            amount: 0,
            list_len: 0,
            head_node: None,
        }
    }

    pub fn add_tx_node(&mut self, store: &mut dyn Storage, tx_id: u64, add_tx_amount: Option<u128>) -> StdResult<()> {
        if let Some(head_node) = self.head_node {
            let tx_node = TxNode {
                tx_id,
                next: Some(head_node),
            };
            TX_NODES.push(store, &tx_node)?;
            let new_head_node = TX_NODES.get_len(store)? - 1;
            self.head_node = Some(new_head_node);
            self.list_len = self.list_len + 1;
        } else {
            let tx_node = TxNode {
                tx_id,
                next: None,
            };
            TX_NODES.push(store, &tx_node)?;
            let head_node = TX_NODES.get_len(store)? - 1;
            self.head_node = Some(head_node);
            self.list_len = 1;
        }
        if let Some(add_tx_amount) = add_tx_amount {
            self.amount = self.amount.saturating_add(add_tx_amount);
        }

        Ok(())
    } 
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxNode {
    /// transaction id in the TRANSACTIONS list
    pub tx_id: u64,
    /// TX_NODES idx - pointer to the next node in the linked list
    pub next: Option<u32>,
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxBundle {
    /// TX_NODES idx - pointer to the head tx node in the linked list
    pub head_node: u32,
    /// length of the tx node linked list for this element
    pub list_len: u32,
    /// offset of the first tx of this bundle in the history of txs for the account (for pagination)
    pub offset: u32,
}

/// A tx bundle is 1 or more tx nodes added to an account's history.
/// The bundle points to a linked list of transaction nodes, which each reference
/// a transaction record by its global id.
/// used with add_suffix(canonical addr of account)
pub static ACCOUNT_TXS: AppendStore<TxBundle> = AppendStore::new(KEY_ACCOUNT_TXS);

/// Keeps track of the total count of txs for an account (not tx bundles)
/// used with add_suffix(canonical addr of account)
pub static ACCOUNT_TX_COUNT: Item<u32> = Item::new(KEY_ACCOUNT_TX_COUNT);

pub struct AccountTxsStore {}
impl AccountTxsStore {
    /// appends a new tx bundle for an account when tx occurs or is settled.
    pub fn append_bundle(store: &mut dyn Storage, account: &CanonicalAddr, head_node: u32, list_len: u32) -> StdResult<()> {
        let account_txs_store = ACCOUNT_TXS.add_suffix(account.as_slice());
        let account_txs_len = account_txs_store.get_len(store)?;
        let tx_bundle;
        if account_txs_len > 0 {
            // peek at the last tx bundle added
            let last_tx_bundle = account_txs_store.get_at(store, account_txs_len - 1)?;
            tx_bundle = TxBundle {
                head_node,
                list_len,
                offset: last_tx_bundle.offset + last_tx_bundle.list_len,
            };
        } else { // this is the first bundle for the account
            tx_bundle = TxBundle {
                head_node,
                list_len,
                offset: 0,
            };
        }

        // update the total count of txs for account
        let account_tx_count_store = ACCOUNT_TX_COUNT.add_suffix(account.as_slice());
        let account_tx_count = account_tx_count_store.may_load(store)?.unwrap_or_default();
        account_tx_count_store.save(store, &(account_tx_count.saturating_add(list_len)))?;

        account_txs_store.push(store, &tx_bundle)
    }

    /// Does a binary search on the append store to find the bundle where the `start_idx` tx can be found.
    /// For a paginated search `start_idx` = `page` * `page_size`.
    pub fn find_start_bundle(store: &dyn Storage, account: CanonicalAddr, start_idx: u32) -> StdResult<Option<(u32, TxBundle)>> {
        let account_txs_store = ACCOUNT_TXS.add_suffix(account.as_slice());

        let mut left = 0u32;
        let mut right = account_txs_store.get_len(store)?;

        while left <= right {
            let mid = (left + right) / 2;
            let mid_bundle = account_txs_store.get_at(store, mid)?;
            if start_idx >= mid_bundle.offset && start_idx < mid_bundle.offset + mid_bundle.list_len {
                // we have the correct bundle
                return Ok(Some((mid, mid_bundle)));
            } else if start_idx < mid_bundle.offset {
                right = mid - 1;
            } else {
                left = mid + 1;
            }
        }

        Ok(None)
    }
}