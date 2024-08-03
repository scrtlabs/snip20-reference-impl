use constant_time_eq::constant_time_eq;
use cosmwasm_std::{Api, CanonicalAddr, StdError, StdResult, Storage};
use rand::RngCore;
use secret_toolkit::storage::Item;
use secret_toolkit_crypto::ContractPrng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::btbe::{merge_dwb_entry, stored_balance};
use crate::state::{safe_add, safe_add_u64};
use crate::transaction_history::{Tx, TRANSACTIONS};
#[cfg(feature = "gas_tracking")]
use crate::gas_tracker::GasTracker;
#[cfg(feature = "gas_tracking")]
use cosmwasm_std::{Binary, to_binary};
#[cfg(feature = "gas_tracking")]
use crate::msg::QueryAnswer;

include!(concat!(env!("OUT_DIR"), "/config.rs"));

pub const KEY_DWB: &[u8] = b"dwb";
pub const KEY_TX_NODES_COUNT: &[u8] = b"dwb-node-cnt";
pub const KEY_TX_NODES: &[u8] = b"dwb-tx-nodes";

pub static DWB: Item<DelayedWriteBuffer> = Item::new(KEY_DWB);
// use with add_suffix tx id (u64)
// does not need to be an AppendStore because we never need to iterate over global list of txs
pub static TX_NODES: Item<TxNode> = Item::new(KEY_TX_NODES);
pub static TX_NODES_COUNT: Item<u64> = Item::new(KEY_TX_NODES_COUNT);

fn store_new_tx_node(store: &mut dyn Storage, tx_node: TxNode) -> StdResult<u64> {
    // tx nodes ids serialized start at 1
    let tx_nodes_serial_id = TX_NODES_COUNT.load(store).unwrap_or_default() + 1;
    TX_NODES
        .add_suffix(&tx_nodes_serial_id.to_be_bytes())
        .save(store, &tx_node)?;
    TX_NODES_COUNT.save(store, &(tx_nodes_serial_id))?;
    Ok(tx_nodes_serial_id)
}

// n entries + 1 "dummy" entry prepended (idx: 0 in DelayedWriteBufferEntry array)
// minimum allowable size: 3
pub const DWB_LEN: u16 = DWB_CAPACITY + 1;

// maximum number of tx events allowed in an entry's linked list
pub const DWB_MAX_TX_EVENTS: u16 = u16::MAX;

#[derive(Serialize, Deserialize, Debug)]
pub struct DelayedWriteBuffer {
    pub empty_space_counter: u16,
    #[serde(with = "BigArray")]
    pub entries: [DelayedWriteBufferEntry; DWB_LEN as usize],
}

pub fn random_in_range(rng: &mut ContractPrng, a: u32, b: u32) -> StdResult<u32> {
    if b <= a {
        return Err(StdError::generic_err("invalid range"));
    }
    let range_size = (b - a) as u64;
    // need to make sure random is below threshold to prevent modulo bias
    let threshold = u64::MAX - range_size;
    loop {
        // this loop will almost always run only once since range_size << u64::MAX
        let random_u64 = rng.next_u64();
        if random_u64 < threshold {
            return Ok((random_u64 % range_size) as u32 + a);
        }
    }
}

impl DelayedWriteBuffer {
    pub fn new() -> StdResult<Self> {
        Ok(Self {
            empty_space_counter: DWB_LEN - 1,
            // first entry is a dummy entry for constant-time writing
            entries: [DelayedWriteBufferEntry::new(&CanonicalAddr::from(&ZERO_ADDR))?;
                DWB_LEN as usize],
        })
    }

    /// settles a participant's account who may or may not have an entry in the buffer
    /// gets balance including any amount in the buffer, and then subtracts amount spent in this tx
    pub fn settle_sender_or_owner_account(
        &mut self,
        store: &mut dyn Storage,
        address: &CanonicalAddr,
        tx_id: u64,
        amount_spent: u128,
        op_name: &str,
        #[cfg(feature = "gas_tracking")] tracker: &mut GasTracker,
    ) -> StdResult<()> {
        #[cfg(feature = "gas_tracking")]
        let mut group1 = tracker.group("settle_sender_or_owner_account.1");

        // release the address from the buffer
        let (balance, mut dwb_entry) = self.release_dwb_recipient(store, address)?;

        #[cfg(feature = "gas_tracking")]
        group1.log("release_dwb_recipient");

        if balance.checked_sub(amount_spent).is_none() {
            return Err(StdError::generic_err(format!(
                "insufficient funds to {op_name}: balance={balance}, required={amount_spent}",
            )));
        };

        dwb_entry.add_tx_node(store, tx_id)?;

        #[cfg(feature = "gas_tracking")]
        group1.log("add_tx_node");

        let mut entry = dwb_entry.clone();
        entry.set_recipient(address)?;

        #[cfg(feature = "gas_tracking")]
        group1.logf(format!(
            "@entry=address:{}, amount:{}",
            entry.recipient()?,
            entry.amount()?
        ));

        let result = merge_dwb_entry(
            store,
            &entry,
            Some(amount_spent),
            #[cfg(feature = "gas_tracking")]
            tracker,
        );

        result
    }

    /// "releases" a given recipient from the buffer, removing their entry if one exists
    /// returns the new balance and the buffer entry
    fn release_dwb_recipient(
        &mut self,
        store: &mut dyn Storage,
        address: &CanonicalAddr,
    ) -> StdResult<(u128, DelayedWriteBufferEntry)> {
        // get the address' stored balance
        let mut balance = stored_balance(store, address)?;

        // locate the position of the entry in the buffer
        let matched_entry_idx = self.recipient_match(address);

        // get the current entry at the matched index (0 if dummy)
        let entry = self.entries[matched_entry_idx];

        // create a new entry to replace the released one, giving it the same address to avoid introducing random addresses
        let replacement_entry = DelayedWriteBufferEntry::new(&entry.recipient()?)?;

        // add entry amount to the stored balance for the address (will be 0 if dummy)
        safe_add(&mut balance, entry.amount()? as u128);

        // overwrite the entry idx with replacement
        self.entries[matched_entry_idx] = replacement_entry;

        Ok((balance, entry))
    }

    // returns matched index for a given address
    pub fn recipient_match(&self, address: &CanonicalAddr) -> usize {
        let mut matched_index: usize = 0;
        let address = address.as_slice();
        for (idx, entry) in self.entries.iter().enumerate().skip(1) {
            let equals = constant_time_eq(address, entry.recipient_slice()) as usize;
            // an address can only occur once in the buffer
            matched_index |= idx * equals;
        }
        matched_index
    }

    pub fn add_recipient<'a>(
        &mut self,
        store: &mut dyn Storage,
        rng: &mut ContractPrng,
        recipient: &CanonicalAddr,
        tx_id: u64,
        amount: u128,
        #[cfg(feature = "gas_tracking")] tracker: &mut GasTracker<'a>,
    ) -> StdResult<()> {
        #[cfg(feature = "gas_tracking")]
        let mut group1 = tracker.group("add_recipient.1");

        // check if `recipient` is already a recipient in the delayed write buffer
        let recipient_index = self.recipient_match(recipient);
        #[cfg(feature = "gas_tracking")]
        group1.log("recipient_match");

        // the new entry will either derive from a prior entry for the recipient or the dummy entry
        let mut new_entry = self.entries[recipient_index].clone();

        new_entry.set_recipient(recipient)?;
        #[cfg(feature = "gas_tracking")]
        group1.log("set_recipient");

        new_entry.add_tx_node(store, tx_id)?;
        #[cfg(feature = "gas_tracking")]
        group1.log("add_tx_node");

        new_entry.add_amount(amount)?;
        #[cfg(feature = "gas_tracking")]
        group1.log("add_amount");

        // whether or not recipient is in the buffer (non-zero index)
        // casting to i32 will never overflow, so long as dwb length is limited to a u16 value
        let if_recipient_in_buffer = constant_time_is_not_zero(recipient_index as i32);
        #[cfg(feature = "gas_tracking")]
        group1.logf(format!(
            "@if_recipient_in_buffer: {}",
            if_recipient_in_buffer
        ));

        // whether or not the buffer is fully saturated yet
        let if_undersaturated = constant_time_is_not_zero(self.empty_space_counter as i32);
        #[cfg(feature = "gas_tracking")]
        group1.logf(format!("@if_undersaturated: {}", if_undersaturated));

        // find the next empty entry in the buffer
        let next_empty_index = (DWB_LEN - self.empty_space_counter) as usize;
        #[cfg(feature = "gas_tracking")]
        group1.logf(format!("@next_empty_index: {}", next_empty_index));

        // which entry to settle (not yet considering if recipient's entry has capacity in history list)
        //   if recipient is in buffer or buffer is undersaturated then settle the dummy entry
        //   otherwise, settle a random entry
        let presumptive_settle_index = constant_time_if_else(
            if_recipient_in_buffer,
            0,
            constant_time_if_else(
                if_undersaturated,
                0,
                random_in_range(rng, 1, DWB_LEN as u32)? as usize,
            ),
        );
        #[cfg(feature = "gas_tracking")]
        group1.logf(format!(
            "@presumptive_settle_index: {}",
            presumptive_settle_index
        ));

        // check if we have any open slots in the linked list
        let if_list_can_grow = constant_time_is_not_zero(
            (DWB_MAX_TX_EVENTS - self.entries[recipient_index].list_len()?) as i32,
        );
        #[cfg(feature = "gas_tracking")]
        group1.logf(format!("@if_list_can_grow: {}", if_list_can_grow));

        // if we would overflow the list by updating the existing entry, then just settle that recipient
        let actual_settle_index =
            constant_time_if_else(if_list_can_grow, presumptive_settle_index, recipient_index);
        #[cfg(feature = "gas_tracking")]
        group1.logf(format!("@actual_settle_index: {}", actual_settle_index));

        // where to write the new/replacement entry
        //   if recipient is in buffer then update it
        //   otherwise, if buffer is undersaturated then put new entry at next open slot
        //   otherwise, the buffer is saturated so replace the entry that is getting settled
        let write_index = constant_time_if_else(
            if_recipient_in_buffer,
            recipient_index,
            constant_time_if_else(if_undersaturated, next_empty_index, actual_settle_index),
        );
        #[cfg(feature = "gas_tracking")]
        group1.logf(format!("@write_index: {}", write_index));

        // settle the entry
        let dwb_entry = self.entries[actual_settle_index];
        merge_dwb_entry(
            store,
            &dwb_entry,
            None,
            #[cfg(feature = "gas_tracking")]
            tracker,
        )?;

        #[cfg(feature = "gas_tracking")]
        let mut group2 = tracker.group("add_recipient.2");

        #[cfg(feature = "gas_tracking")]
        group2.log("merge_dwb_entry");

        // write the new entry, which either overwrites the existing one for the same recipient,
        // replaces a randomly settled one, or inserts into an "empty" slot in the buffer
        self.entries[write_index] = new_entry;

        // decrement empty space counter if it is undersaturated and the recipient was not already in the buffer
        self.empty_space_counter -= constant_time_if_else(
            if_undersaturated,
            constant_time_if_else(if_recipient_in_buffer, 0, 1),
            0,
        ) as u16;
        #[cfg(feature = "gas_tracking")]
        group2.logf(format!(
            "@empty_space_counter: {}",
            self.empty_space_counter
        ));

        Ok(())
    }
}

const U16_BYTES: usize = 2;
const U64_BYTES: usize = 8;
const U128_BYTES: usize = 16;

#[cfg(test)]
const DWB_RECIPIENT_BYTES: usize = 54; // because mock_api creates rando canonical addr that is 54 bytes long
#[cfg(not(test))]
const DWB_RECIPIENT_BYTES: usize = 20;
const DWB_AMOUNT_BYTES: usize = 8; // Max 16 (u128)
const DWB_HEAD_NODE_BYTES: usize = 5; // Max 8  (u64)
const DWB_LIST_LEN_BYTES: usize = 2; // u16

const_assert!(DWB_AMOUNT_BYTES <= U128_BYTES);
const_assert!(DWB_HEAD_NODE_BYTES <= U64_BYTES);
const_assert!(DWB_LIST_LEN_BYTES <= U16_BYTES);

const DWB_ENTRY_BYTES: usize =
    DWB_RECIPIENT_BYTES + DWB_AMOUNT_BYTES + DWB_HEAD_NODE_BYTES + DWB_LIST_LEN_BYTES;

pub const ZERO_ADDR: [u8; DWB_RECIPIENT_BYTES] = [0u8; DWB_RECIPIENT_BYTES];

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
/// // length of list (limited to 65535)
/// list_len  - 2 byte
///
/// total: 35 bytes
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DelayedWriteBufferEntry(#[serde(with = "BigArray")] [u8; DWB_ENTRY_BYTES]);

impl DelayedWriteBufferEntry {
    pub fn new(recipient: &CanonicalAddr) -> StdResult<Self> {
        let recipient = recipient.as_slice();
        if recipient.len() != DWB_RECIPIENT_BYTES {
            return Err(StdError::generic_err("dwb: invalid recipient length"));
        }
        let mut result = [0u8; DWB_ENTRY_BYTES];
        result[..DWB_RECIPIENT_BYTES].copy_from_slice(recipient);
        Ok(Self { 0: result })
    }

    pub fn recipient_slice(&self) -> &[u8] {
        &self.0[..DWB_RECIPIENT_BYTES]
    }

    pub fn recipient(&self) -> StdResult<CanonicalAddr> {
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

    pub fn amount(&self) -> StdResult<u64> {
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
        self.0[start..end].copy_from_slice(&val.to_be_bytes());
        Ok(())
    }

    pub fn head_node(&self) -> StdResult<u64> {
        let start = DWB_RECIPIENT_BYTES + DWB_AMOUNT_BYTES;
        let end = start + DWB_HEAD_NODE_BYTES;
        let head_node_slice = &self.0[start..end];
        let mut result = [0u8; U64_BYTES];
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

    pub fn list_len(&self) -> StdResult<u16> {
        let start = DWB_RECIPIENT_BYTES + DWB_AMOUNT_BYTES + DWB_HEAD_NODE_BYTES;
        let end = start + DWB_LIST_LEN_BYTES;
        let list_len_slice = &self.0[start..end];
        let result = list_len_slice
            .try_into()
            .or(Err(StdError::generic_err("Get dwb list len error")))?;
        Ok(u16::from_be_bytes(result))
    }

    fn set_list_len(&mut self, val: u16) -> StdResult<()> {
        let start = DWB_RECIPIENT_BYTES + DWB_AMOUNT_BYTES + DWB_HEAD_NODE_BYTES;
        let end = start + DWB_LIST_LEN_BYTES;
        self.0[start..end].copy_from_slice(&val.to_be_bytes());
        Ok(())
    }

    /// adds a tx node to the linked list
    /// returns: the new head node
    fn add_tx_node(&mut self, store: &mut dyn Storage, tx_id: u64) -> StdResult<u64> {
        let tx_node = TxNode {
            tx_id,
            next: self.head_node()?,
        };

        // store the new node on chain
        let new_node = store_new_tx_node(store, tx_node)?;
        // set the head node to the new node id
        self.set_head_node(new_node)?;
        // increment the node list length
        self.set_list_len(self.list_len()? + 1)?;

        Ok(new_node)
    }

    // adds some amount to the total amount for all txs in the entry linked list
    // returns: the new amount
    fn add_amount(&mut self, add_tx_amount: u128) -> StdResult<u64> {
        // change this to safe_add if your coin needs to store amount in buffer as u128 (e.g. 18 decimals)
        let mut amount = self.amount()?;
        let add_tx_amount_u64 = amount_u64(Some(add_tx_amount))?;
        safe_add_u64(&mut amount, add_tx_amount_u64);
        self.set_amount(amount)?;

        Ok(amount)
    }
}

pub fn amount_u64(amount_spent: Option<u128>) -> StdResult<u64> {
    let amount_spent = amount_spent.unwrap_or_default();
    let amount_spent_u64 = amount_spent
        .try_into()
        .or_else(|_| return Err(StdError::generic_err("se: spent overflow")))?;
    Ok(amount_spent_u64)
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct TxNode {
    /// transaction id in the TRANSACTIONS list
    pub tx_id: u64,
    /// TX_NODES idx - pointer to the next node in the linked list
    /// 0 if next is null
    pub next: u64,
}

impl TxNode {
    // converts this and following elements in list to a vec of Tx
    pub fn to_vec(&self, store: &dyn Storage, api: &dyn Api) -> StdResult<Vec<Tx>> {
        let mut result = vec![];
        let mut cur_node = Some(self.to_owned());
        while cur_node.is_some() {
            let node = cur_node.unwrap();
            let stored_tx = TRANSACTIONS
                .add_suffix(&node.tx_id.to_be_bytes())
                .load(store)?;
            let tx = stored_tx.into_humanized(api, node.tx_id)?;
            result.push(tx);
            if node.next > 0 {
                let next_node = TX_NODES.add_suffix(&node.next.to_be_bytes()).load(store)?;
                cur_node = Some(next_node);
            } else {
                cur_node = None;
            }
        }

        Ok(result)
    }
}

/// A tx bundle is 1 or more tx nodes added to an account's history.
/// The bundle points to a linked list of transaction nodes, which each reference
/// a transaction record by its global id.
/// used with add_suffix(canonical addr of account)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxBundle {
    /// TX_NODES idx - pointer to the head tx node in the linked list
    pub head_node: u64,
    /// length of the tx node linked list for this element
    pub list_len: u16,
    /// offset of the first tx of this bundle in the history of txs for the account (for pagination)
    pub offset: u32,
}

#[inline]
fn constant_time_is_not_zero(value: i32) -> u32 {
    (((value | -value) >> 31) & 1) as u32
}

#[inline]
fn constant_time_if_else(condition: u32, then: usize, els: usize) -> usize {
    (then * condition as usize) | (els * (1 - condition as usize))
}

#[cfg(feature = "gas_tracking")]
pub fn log_dwb(storage: &dyn Storage) -> StdResult<Binary> {
    let dwb = DWB.load(storage)?;
    to_binary(&QueryAnswer::Dwb {
        dwb: format!("{:?}", dwb),
    })
}

#[cfg(test)]
mod tests {
    use crate::contract::instantiate;
    use crate::msg::{InitialBalance, InstantiateMsg};
    use crate::transaction_history::{append_new_stored_tx, StoredTxAction};
    use cosmwasm_std::{testing::*, Binary, OwnedDeps, Response, Uint128};

    use super::*;

    fn init_helper(
        initial_balances: Vec<InitialBalance>,
    ) -> (
        StdResult<Response>,
        OwnedDeps<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies_with_balance(&[]);
        let env = mock_env();
        let info = mock_info("instantiator", &[]);

        let init_msg = InstantiateMsg {
            name: "sec-sec".to_string(),
            admin: Some("admin".to_string()),
            symbol: "SECSEC".to_string(),
            decimals: 8,
            initial_balances: Some(initial_balances),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: None,
            supported_denoms: None,
        };

        (instantiate(deps.as_mut(), env, info, init_msg), deps)
    }

    #[test]
    fn test_dwb_entry() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let env = mock_env();
        let _info = mock_info("bob", &[]);

        let recipient = CanonicalAddr::from(ZERO_ADDR);
        let mut dwb_entry = DelayedWriteBufferEntry::new(&recipient).unwrap();
        assert_eq!(dwb_entry, DelayedWriteBufferEntry([0u8; DWB_ENTRY_BYTES]));

        assert_eq!(
            dwb_entry.recipient().unwrap(),
            CanonicalAddr::from(ZERO_ADDR)
        );
        assert_eq!(dwb_entry.amount().unwrap(), 0u64);
        assert_eq!(dwb_entry.head_node().unwrap(), 0u64);
        assert_eq!(dwb_entry.list_len().unwrap(), 0u16);

        let canonical_addr = CanonicalAddr::from(&[1u8; DWB_RECIPIENT_BYTES]);
        dwb_entry.set_recipient(&canonical_addr).unwrap();
        dwb_entry.set_amount(1).unwrap();
        dwb_entry.set_head_node(1).unwrap();
        dwb_entry.set_list_len(1).unwrap();

        assert_eq!(
            dwb_entry.recipient().unwrap(),
            CanonicalAddr::from(&[1u8; DWB_RECIPIENT_BYTES])
        );
        assert_eq!(dwb_entry.amount().unwrap(), 1u64);
        assert_eq!(dwb_entry.head_node().unwrap(), 1u64);
        assert_eq!(dwb_entry.list_len().unwrap(), 1u16);

        // first store the tx information in the global append list of txs and get the new tx id
        let storage = deps.as_mut().storage;
        let from = CanonicalAddr::from(&[2u8; 20]);
        let sender = CanonicalAddr::from(&[2u8; 20]);
        let to = CanonicalAddr::from(&[1u8; 20]);
        let action = StoredTxAction::transfer(from.clone(), sender.clone(), to.clone());
        let tx_id = append_new_stored_tx(
            storage,
            &action,
            1000u128,
            "uscrt".to_string(),
            Some("memo".to_string()),
            &env.block,
        )
        .unwrap();

        let result = dwb_entry.add_tx_node(storage, tx_id).unwrap();
        assert_eq!(dwb_entry.head_node().unwrap(), result);
    }
}
