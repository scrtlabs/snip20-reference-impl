use std::collections::{HashMap, HashSet};

use crypto::util::fixed_time_eq;
use schemars::JsonSchema;
use secret_toolkit_crypto::{sha_256, ContractPrng};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use cosmwasm_std::{CanonicalAddr, StdError, StdResult, Storage};
use secret_toolkit::storage::{AppendStore, Item};

use crate::{state::{safe_add, safe_add_u64, BalancesStore, BALANCES}, transaction_history::Tx};

pub const KEY_DWB: &[u8] = b"dwb";
pub const KEY_TX_NODES_COUNT: &[u8] = b"dwb-node-cnt";
pub const KEY_TX_NODES: &[u8] = b"dwb-tx-nodes";
pub const KEY_ACCOUNT_TXS: &[u8] = b"dwb-acc-txs";
pub const KEY_ACCOUNT_TX_COUNT: &[u8] = b"dwb-acc-tx-cnt";

pub static DWB: Item<DelayedWriteBuffer> = Item::new(KEY_DWB);
// use with add_suffix tx id (u64)
// does not need to be an AppendStore because we never need to iterate over global list of txs
pub static TX_NODES: Item<TxNode> = Item::new(KEY_TX_NODES);
pub static TX_NODES_COUNT: Item<u64> = Item::new(KEY_TX_NODES_COUNT);

fn store_new_tx_node(store: &mut dyn Storage, tx_node: TxNode) -> StdResult<u64> {
    // tx nodes ids serialized start at 1
    let tx_nodes_serial_id = TX_NODES_COUNT.load(store).unwrap_or_default() + 1;
    TX_NODES.add_suffix(&tx_nodes_serial_id.to_be_bytes()).save(store, &tx_node)?;
    TX_NODES_COUNT.save(store,&(tx_nodes_serial_id))?;
    Ok(tx_nodes_serial_id)
}

pub const ZERO_ADDR: [u8; 20] = [0u8; 20];
// 64 entries + 1 "dummy" entry prepended (idx: 0 in DelayedWriteBufferEntry array)
pub const DWB_LEN: u16 = 65;

#[derive(Serialize, Deserialize, Debug)]
pub struct DelayedWriteBuffer {
    pub empty_space_counter: u16,
    #[serde(with = "BigArray")]
    pub entries: [DelayedWriteBufferEntry; DWB_LEN as usize],
}

#[inline]
fn random_addr(rng: &mut ContractPrng) -> CanonicalAddr {
    CanonicalAddr::from(&rng.rand_bytes()[0..20])
}

impl DelayedWriteBuffer {
    pub fn new() -> StdResult<Self> {
        Ok(Self {
            empty_space_counter: DWB_LEN - 1,
            // first entry is a dummy entry for constant-time writing
            entries: [
                DelayedWriteBufferEntry::new(CanonicalAddr::from(&ZERO_ADDR))?; DWB_LEN as usize
            ]
        })
    }

    #[inline]
    pub fn saturated(&self) -> bool {
        self.empty_space_counter == 0
    }

    /// settles a participant's account who may or may not have an entry in the buffer
    pub fn settle_account(
        &mut self,
        store: &mut dyn Storage,
        rng: &mut ContractPrng,
        address: &CanonicalAddr,
        tx_id: u64,
        amount_spent: u128,
    ) -> StdResult<()> {
        // release the address from the buffer
        let (balance, entry_opt) = self.constant_time_release(
            store, 
            rng, 
            address
        )?;
    
        if let Some(mut entry) = entry_opt {
            // add tx at the head before adding new tx bundle for account history
            entry.add_tx_node(store, tx_id, None)?;
            AccountTxsStore::append_bundle(
                store,
                address,
                entry.head_node()?,
                entry.list_len()
            )?;
        } else { 
            // no entry in dwb, so we just create a single node and 
            // push it as a bundle in the account tx history 
            let tx_node = TxNode {
                tx_id,
                next: None,
            };

            let head_node = store_new_tx_node(store, tx_node)?;
            AccountTxsStore::append_bundle(
                store, 
                address, 
                head_node,
                1
            )?;
        }
    
        let new_balance = if let Some(balance_after_sub) = balance.checked_sub(amount_spent) {
            balance_after_sub
        } else {
            return Err(StdError::generic_err(format!(
                "insufficient funds to transfer: balance={balance}, required={amount_spent}",
            )));
        };
        BalancesStore::save(store, address, new_balance)?;
    
        Ok(())
    }

    /// "releases" a given recipient from the buffer, removing their entry if one exists, in constant-time
    /// returns the new balance and the buffer entry
    pub fn constant_time_release(
        &mut self, 
        store: &mut dyn Storage, 
        rng: &mut ContractPrng, 
        address: &CanonicalAddr
    ) -> StdResult<(u128, Option<DelayedWriteBufferEntry>)> {
        // get the address' stored balance
        let mut balance = BalancesStore::load(store, address);

        // locate the position of the entry in the buffer
        let matched_entry_idx = self.recipient_match(address);

        // produce a new random address
        let mut replacement_address = random_addr(rng);
        // ensure random addr is not already in dwb (extremely unlikely!!)
        while self.recipient_match(&replacement_address) > 0 {
            replacement_address = random_addr(rng);
        }
        let replacement_entry = DelayedWriteBufferEntry::new(replacement_address)?;

        // get the current entry at the matched index (0 if dummy)
        let entry = self.entries[matched_entry_idx];
        // add entry amount to the stored balance for the address (will be 0 if dummy)
        safe_add(&mut balance, entry.amount()? as u128);
        // overwrite the entry idx with random addr replacement
        self.entries[matched_entry_idx] = replacement_entry;

        match matched_entry_idx {
            // no match
            0 => Ok((balance, None)),
            // otherwise return the updated balance and entry
            x => Ok((balance, Some(entry)))
        }
    }

    // returns matched index for a given address
    // trailing zeros will be 128 if not found, so return 0 (dummy entry)
    pub fn recipient_match(&self, address: &CanonicalAddr) -> usize {
        // for a dwb > 128 entries in size use a u256
        let mut matched_index: u128 = 0;
        let address = address.as_slice();
        for (idx, entry) in self.entries.iter().enumerate().skip(1) {
            let equals = fixed_time_eq(address, entry.recipient_slice()) as u128;
            matched_index |= equals << idx;
        }
        match matched_index.trailing_zeros() {
            128 => 0,
            x => x as usize
        }
    }

}

const U64_BYTES: usize = 8;

const DWB_RECIPIENT_BYTES: usize = 20;
const DWB_AMOUNT_BYTES: usize = 8;     // Max 16 (u128)
const DWB_HEAD_NODE_BYTES: usize = 5;  // Max 8  (u64)
const DWB_LIST_LEN_BYTES: usize = 1;

const DWB_ENTRY_BYTES: usize = DWB_RECIPIENT_BYTES + DWB_AMOUNT_BYTES + DWB_HEAD_NODE_BYTES + DWB_LIST_LEN_BYTES;

/// A delayed write buffer entry consists of the following bytes in this order:
/// 
/// // recipient canonical address
/// recipient - 20 bytes
/// // for sscrt w/ 6 decimals u64 is good for > 18 trillion tokens, far exceeding supply
/// // change to 16 bytes (u128) or other size for tokens with more decimals/higher supply
/// amount    - 8 bytes (u64)
/// // global id for head of linked list of transaction nodes
/// // 40 bits allows for over 1 trillion transactions
/// head_node - 5 bytes
/// // length of list (limited to 255)
/// list_len  - 1 byte
/// 
/// total: 34 bytes
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DelayedWriteBufferEntry(
    #[serde(with = "BigArray")]
    [u8; DWB_ENTRY_BYTES]
);

impl DelayedWriteBufferEntry {
    pub fn new(recipient: CanonicalAddr) -> StdResult<Self> {
        let recipient = recipient.as_slice();
        if recipient.len() != DWB_RECIPIENT_BYTES {
            return Err(StdError::generic_err("dwb: invalid recipient length"));
        }
        let mut result = [0u8; DWB_ENTRY_BYTES];
        result[..DWB_RECIPIENT_BYTES].copy_from_slice(recipient);
        Ok(Self {
            0: result
        })
    }

    fn recipient_slice(&self) -> &[u8] {
        &self.0[..DWB_RECIPIENT_BYTES]
    }

    fn recipient(&self) -> StdResult<CanonicalAddr> {
        let result = CanonicalAddr::try_from(self.recipient_slice())
            .or(Err(StdError::generic_err("Get dwb recipient error")))?;
        Ok(result)
    }

    fn set_recipient(&mut self, val: &CanonicalAddr) -> StdResult<()> {
        let val_slice = val.as_slice();
        if val_slice.len() != DWB_RECIPIENT_BYTES {
            return Err(StdError::generic_err("Set dwb recipient error"));
        }
        self.0[..DWB_RECIPIENT_BYTES].copy_from_slice(val_slice);
        Ok(())
    }

    fn amount(&self) -> StdResult<u64> {
        let start = DWB_RECIPIENT_BYTES;
        let end = start + DWB_AMOUNT_BYTES;
        let amount_slice = &self.0[start..end];
        let result = amount_slice
            .try_into()
            .or(Err(StdError::generic_err("Get dwb amount error")))?;
        Ok(u64::from_be_bytes(result))
    }

    fn set_amount(&mut self, val: u64) -> StdResult<()> {
        let start = DWB_RECIPIENT_BYTES;
        let end = start + DWB_AMOUNT_BYTES;
        if DWB_AMOUNT_BYTES != U64_BYTES {
            return Err(StdError::generic_err("Set dwb amount error"));
        }
        self.0[start..end].copy_from_slice(&val.to_be_bytes());
        Ok(())
    }

    fn head_node(&self) -> StdResult<u64> {
        let start = DWB_RECIPIENT_BYTES + DWB_AMOUNT_BYTES;
        let end = start + DWB_HEAD_NODE_BYTES;
        let head_node_slice = &self.0[start..end];
        let mut result = [0u8; U64_BYTES];
        if DWB_HEAD_NODE_BYTES > U64_BYTES {
            return Err(StdError::generic_err("Get dwb head node error"));
        }
        result[U64_BYTES - DWB_HEAD_NODE_BYTES..].copy_from_slice(head_node_slice);
        Ok(u64::from_be_bytes(result))
    }

    fn set_head_node(&mut self, val: u64) -> StdResult<()> {
        let start = DWB_RECIPIENT_BYTES + DWB_AMOUNT_BYTES;
        let end = start + DWB_HEAD_NODE_BYTES;
        let val_bytes = &val.to_be_bytes()[U64_BYTES - DWB_HEAD_NODE_BYTES..];
        if val_bytes.len() != DWB_HEAD_NODE_BYTES {
            return Err(StdError::generic_err("Set dwb head node error"));
        }
        self.0[start..end].copy_from_slice(val_bytes);
        Ok(())
    }

    fn list_len(&self) -> u8 {
        let pos = DWB_RECIPIENT_BYTES + DWB_AMOUNT_BYTES + DWB_HEAD_NODE_BYTES;
        self.0[pos]
    }

    fn set_list_len(&mut self, val: u8) {
        let pos = DWB_RECIPIENT_BYTES + DWB_AMOUNT_BYTES + DWB_HEAD_NODE_BYTES;
        self.0[pos] = val;
    }

    pub fn add_tx_node(&mut self, store: &mut dyn Storage, tx_id: u64, add_tx_amount: Option<u128>) -> StdResult<()> {
        let tx_node;
        let head_node = self.head_node()?;
        if head_node > 0 {
            tx_node = TxNode {
                tx_id,
                next: Some(head_node),
            };
        } else {
            tx_node = TxNode {
                tx_id,
                next: None,
            };
        }

        // store the new node on chain
        let new_node = store_new_tx_node(store, tx_node)?;
        // set the head node to the new node id
        self.set_head_node(new_node)?;
        // increment the node list length
        self.set_list_len(self.list_len() + 1);
        if let Some(add_tx_amount) = add_tx_amount {
            // change this to safe_add if your coin needs to store amount in buffer as u128 (e.g. 18 decimals)
            let mut amount = self.amount()?;
            let add_tx_amount_u64 = add_tx_amount
                .try_into()
                .or_else(|_| return Err(StdError::generic_err("dwb: deposit overflow")))?;
            safe_add_u64(&mut amount, add_tx_amount_u64);
            self.set_amount(amount)?;
        }

        Ok(())
    } 
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxNode {
    /// transaction id in the TRANSACTIONS list
    pub tx_id: u64,
    /// TX_NODES idx - pointer to the next node in the linked list
    pub next: Option<u64>,
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxBundle {
    /// TX_NODES idx - pointer to the head tx node in the linked list
    pub head_node: u64,
    /// length of the tx node linked list for this element
    pub list_len: u8,
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
    /// appends a new tx bundle for an account, called when non-transfer tx occurs or is settled.
    pub fn append_bundle(store: &mut dyn Storage, account: &CanonicalAddr, head_node: u64, list_len: u8) -> StdResult<()> {
        let account_txs_store = ACCOUNT_TXS.add_suffix(account.as_slice());
        let account_txs_len = account_txs_store.get_len(store)?;
        let tx_bundle;
        if account_txs_len > 0 {
            // peek at the last tx bundle added
            let last_tx_bundle = account_txs_store.get_at(store, account_txs_len - 1)?;
            tx_bundle = TxBundle {
                head_node,
                list_len,
                offset: last_tx_bundle.offset + u32::from(last_tx_bundle.list_len),
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
        account_tx_count_store.save(store, &(account_tx_count.saturating_add(u32::from(list_len))))?;

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
            if start_idx >= mid_bundle.offset && start_idx < mid_bundle.offset + u32::from(mid_bundle.list_len) {
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


#[cfg(test)]
mod tests {
    use std::any::Any;

    use cosmwasm_std::{testing::*, Api};
    use cosmwasm_std::{
        from_binary, BlockInfo, ContractInfo, MessageInfo, OwnedDeps, QueryResponse, ReplyOn,
        SubMsg, Timestamp, TransactionInfo, WasmMsg,
    };
    use secret_toolkit::permit::{PermitParams, PermitSignature, PubKey};

    use crate::msg::ResponseStatus;
    use crate::msg::{InitConfig, InitialBalance};

    use super::*;

    #[test]
    fn test_dwb_entry_setters_getters() {
        let recipient = CanonicalAddr::from(ZERO_ADDR);
        let dwb_entry = DelayedWriteBufferEntry::new(recipient).unwrap();
        assert_eq!(dwb_entry, DelayedWriteBufferEntry([0u8; DWB_ENTRY_BYTES]));
    }
}