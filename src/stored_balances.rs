use constant_time_eq::constant_time_eq;
use secret_toolkit::storage::Item;
use serde::{Serialize, Deserialize,};
use serde_big_array::BigArray;
use cosmwasm_std::{CanonicalAddr, StdError, StdResult, Storage};

use crate::{
    dwb::DelayedWriteBufferEntry, state::safe_add_u64
};

// btsb = bitwise-trie of stored balances

pub const KEY_BTSB_ENTRY_HISTORY: &[u8] = b"btsb-entry-hist";
pub const KEY_BTSB_BUCKETS_COUNT: &[u8] = b"btsb-buckets-cnt";
pub const KEY_BTSB_BUCKETS: &[u8] = b"btsb-buckets";
pub const KEY_BTSB_TRIE_NODES: &[u8] = b"btsb-trie-nodes";
pub const KEY_BTSB_TRIE_NODES_COUNT: &[u8] = b"btsb-trie-nodes-cnt";


const U16_BYTES: usize = 2;
const U32_BYTES: usize = 4;
const U64_BYTES: usize = 8;
const U128_BYTES: usize = 16;

#[cfg(test)]
const BTSB_BUCKET_ADDRESS_BYTES: usize = 54;
#[cfg(not(test))]
const BTSB_BUCKET_ADDRESS_BYTES: usize = 20;
const BTSB_BUCKET_BALANCE_BYTES: usize = 8;  // Max 16 (u128)
const BTSB_BUCKET_HISTORY_BYTES: usize = 5;  // Max 8  (u64)

const_assert!(BTSB_BUCKET_BALANCE_BYTES <= U128_BYTES);
const_assert!(BTSB_BUCKET_HISTORY_BYTES <= U64_BYTES);

const BTSB_BUCKET_ENTRY_BYTES: usize = BTSB_BUCKET_ADDRESS_BYTES + BTSB_BUCKET_BALANCE_BYTES + BTSB_BUCKET_HISTORY_BYTES;

const ZERO_ADDR: [u8; BTSB_BUCKET_ADDRESS_BYTES] = [0u8; BTSB_BUCKET_ADDRESS_BYTES];

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct StoredBalanceEntry(
    #[serde(with = "BigArray")]
    [u8; BTSB_BUCKET_ENTRY_BYTES]
);

impl StoredBalanceEntry {
    pub fn new(address: CanonicalAddr) -> StdResult<Self> {
        let address = address.as_slice();

        if address.len() != BTSB_BUCKET_ADDRESS_BYTES {
            return Err(StdError::generic_err("bucket: invalid address length"));
        }

        let mut result = [0u8; BTSB_BUCKET_ENTRY_BYTES];
        result[..BTSB_BUCKET_ENTRY_BYTES].copy_from_slice(address);
        Ok(Self {
            0: result
        })
    }

    pub fn from(dwb_entry: DelayedWriteBufferEntry) -> StdResult<Self> {
        let mut entry = StoredBalanceEntry::new(dwb_entry.recipient()?)?;

        entry.set_balace(dwb_entry.amount()?);
        entry.set_history_len(1);

        Ok(entry)
    }

    fn address_slice(&self) -> &[u8] {
        &self.0[..BTSB_BUCKET_ADDRESS_BYTES]
    }

    fn address(&self) -> StdResult<CanonicalAddr> {
        let result = CanonicalAddr::try_from(self.address_slice())
            .or(Err(StdError::generic_err("Get bucket address error")))?;
        Ok(result)
    }

    pub fn balance(&self) -> StdResult<u64> {
        let start = BTSB_BUCKET_ADDRESS_BYTES;
        let end = start + BTSB_BUCKET_BALANCE_BYTES;
        let amount_slice = &self.0[start..end];
        let result = amount_slice
            .try_into()
            .or(Err(StdError::generic_err("Get bucket balance error")))?;
        Ok(u64::from_be_bytes(result))
    }

    fn set_balace(&mut self, val: u64) -> StdResult<()> {
        let start = BTSB_BUCKET_ADDRESS_BYTES;
        let end = start + BTSB_BUCKET_BALANCE_BYTES;
        self.0[start..end].copy_from_slice(&val.to_be_bytes());
        Ok(())
    }

    pub fn history_len(&self) -> StdResult<u64> {
        let start = BTSB_BUCKET_ADDRESS_BYTES + BTSB_BUCKET_BALANCE_BYTES;
        let end = start + BTSB_BUCKET_HISTORY_BYTES;
        let history_len_slice = &self.0[start..end];
        let mut result = [0u8; U64_BYTES];
        result[U64_BYTES - BTSB_BUCKET_HISTORY_BYTES..].copy_from_slice(history_len_slice);
        Ok(u64::from_be_bytes(result))
    }

    fn set_history_len(&mut self, val: u64) -> StdResult<()> {
        let start = BTSB_BUCKET_ADDRESS_BYTES + BTSB_BUCKET_BALANCE_BYTES;
        let end = start + BTSB_BUCKET_HISTORY_BYTES;
        let val_bytes = &val.to_be_bytes()[U64_BYTES - BTSB_BUCKET_HISTORY_BYTES..];
        if val_bytes.len() != BTSB_BUCKET_HISTORY_BYTES {
            return Err(StdError::generic_err("Set bucket history len error"));
        }
        self.0[start..end].copy_from_slice(val_bytes);
        Ok(())
    }

    pub fn merge_dwb_entry(&mut self, entry: &DelayedWriteBufferEntry) -> StdResult<()> {
        let mut balance = self.balance()?;
        safe_add_u64(&mut balance, entry.amount()?);
        self.set_balace(balance)?;

        // TOOD: update history len

        Ok(())
    }

}



const BTSB_BUCKET_LEN: u16 = 128;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
struct BtsbBucket {
    pub capacity: u16,
    #[serde(with = "BigArray")]
    pub entries: [StoredBalanceEntry; BTSB_BUCKET_LEN as usize],
}

static BTSB_ENTRY_HISTORY: Item<u64> = Item::new(KEY_BTSB_ENTRY_HISTORY);
static BTSB_BUCKETS_COUNT: Item<u64> = Item::new(KEY_BTSB_BUCKETS_COUNT);
static BTSB_BUCKETS: Item<BtsbBucket> = Item::new(KEY_BTSB_BUCKETS);

// create type alias to refer to position of a bucket entry, which is its index in the array plus 1
type BucketEntryPosition = usize;

impl BtsbBucket {
    pub fn new() -> StdResult<Self> {
        Ok(Self {
            capacity: BTSB_BUCKET_LEN,
            entries: [
                StoredBalanceEntry::new(CanonicalAddr::from(&ZERO_ADDR))?; BTSB_BUCKET_LEN as usize
            ]
        })
    }

    pub fn add_entry(&mut self, storage: &mut dyn Storage, entry: &StoredBalanceEntry, bit_pos: u8) -> StdResult<u16> {
        match self.capacity {
            // buffer is at capacity
            0 => Err(StdError::generic_err("")),

            // has capacity for a new entry
            _ => {
                // save entry to bucket
                self.entries[self.entries.len() - self.capacity as usize] = entry.clone();

                // update capacity
                self.capacity -= 1;

                // done
                Ok(self.capacity)
            }
        }
    }

    pub fn constant_time_find_address(&self, address: &CanonicalAddr) -> Option<StoredBalanceEntry> {
        let address = address.as_slice();

        let mut matched_index_p1: BucketEntryPosition = 0;
        for (idx, entry) in self.entries.iter().enumerate() {
            let equals = constant_time_eq(address, entry.address_slice()) as usize;
            matched_index_p1 |= (idx + 1) * equals;
        }

        match matched_index_p1 {
            0 => None,
            idx => Some(self.entries[idx - 1]),
        }
    }

    pub fn quick_find_entry(&self, address: &CanonicalAddr) -> Option<StoredBalanceEntry> {
        let address = address.as_slice();

        let mut matched_index_p1: BucketEntryPosition = 0;
        /* TODO:
            binary search on bucket
         */

         match matched_index_p1 {
            0 => None,
            idx => Some(self.entries[idx - 1]),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct BitwiseTrieNode {
    pub left: u64,
    pub right: u64,
    pub bucket: u64,
}


pub static BTSB_TRIE_NODES: Item<BitwiseTrieNode> = Item::new(KEY_BTSB_TRIE_NODES);
pub static BTSB_TRIE_NODES_COUNT: Item<u64> = Item::new(KEY_BTSB_TRIE_NODES_COUNT);

impl BitwiseTrieNode {
    // creates a new leaf node
    pub fn new_leaf(storage: &mut dyn Storage, bucket: BtsbBucket) -> StdResult<Self> {
        let buckets_count = BTSB_BUCKETS_COUNT.load(storage).unwrap_or_default() + 1;

        // ID for new bucket
        let bucket_id = buckets_count;

        // save updated count
        BTSB_BUCKETS_COUNT.save(storage, &buckets_count)?;

        // save bucket to storage
        BTSB_BUCKETS.add_suffix(&bucket_id.to_be_bytes()).save(storage, &bucket)?;

        // create new node
        Ok(Self {
            left: 0,
            right: 0,
            bucket: bucket_id,
        })
    }

    // loads the node's bucket from storage
    pub fn bucket(self, storage: &mut dyn Storage) -> StdResult<BtsbBucket> {
        if self.bucket == 0 {
            return Err(StdError::generic_err("btsb: attempted to load bucket of branch node"));
        }

        // load bucket from storage
        BTSB_BUCKETS.add_suffix(&self.bucket.to_be_bytes()).load(storage)
    }

    // stores the bucket associated with this node
    fn set_and_save_bucket(self, storage: &mut dyn Storage, bucket: BtsbBucket) -> StdResult<()> {
        if self.bucket == 0 {
            return Err(StdError::generic_err("btsb: attempted to store a bucket to a branch node"));
        }

        BTSB_BUCKETS.add_suffix(&self.bucket.to_be_bytes()).save(storage, &bucket)
    }
}


// locates a btsb node given an address; returns tuple of (node, bit position)
pub fn locate_btsb_node(storage: &mut dyn Storage, address: &CanonicalAddr) -> StdResult<(BitwiseTrieNode, u64, u8)> {
    let hash: [u8; 32] = [0u8; 32];
    /* TODO:
        let hash := hkdf(ikm=contractInternalSecret, info=addrress, length=256bits)
    */

    // start at root of trie
    let mut node_id: u64 = 1;
    let mut node = BTSB_TRIE_NODES.add_suffix(&node_id.to_be_bytes()).load(storage)?;
    let mut bit_pos: u8 = 0;

    // while the node has children
    while node.bucket == 0 {
        // calculate bit value at current bit position
        let bit_value = (hash[(bit_pos / 8) as usize] >> (7 - (bit_pos % 8))) & 1;

        // increment bit position
        bit_pos += 1;

        // choose left or right child depending on bit value
        node_id = if bit_value == 0 { node.left } else { node.right };

        // load child node
        node = BTSB_TRIE_NODES.add_suffix(&node_id.to_be_bytes()).load(storage)?;
    }

    Ok((node, node_id, bit_pos))
}


// merges a dwb entry into the current node's bucket
pub fn merge_dwb_entry(storage: &mut dyn Storage, dwb_entry: DelayedWriteBufferEntry) -> StdResult<()> {
    // locate the node that the given entry belongs in
    let (mut node, node_id, bit_pos) = locate_btsb_node(storage, &dwb_entry.recipient()?)?;

    // load that node's current bucket
    let mut bucket = node.bucket(storage)?;

    // search for an existing entry
    match bucket.constant_time_find_address(&dwb_entry.recipient()?) {
        // found existing entry
        Some(mut found_entry) => {
            // merge amount and history from dwb entry
            found_entry.merge_dwb_entry(&dwb_entry);

            // save updated bucket to storage
            node.set_and_save_bucket(storage, bucket);
        },

        // need to insert new entry
        None => {
            // create new stored balance entry
            let btsb_entry = StoredBalanceEntry::from(dwb_entry)?;

            /* TODO:
                create new storage for dwb_entry's history
             */

            // try to add to the current bucket
            match bucket.add_entry(storage, &btsb_entry, bit_pos) {
                // bucket has capcity and it added the new entry
                Ok(capacity) => {
                    // save bucket to storage
                    node.set_and_save_bucket(storage, bucket);
                }

                // bucket is full; split on next bit position
                Err(_) => {
                    // create new left and right buckets
                    let left_bucket = BtsbBucket::new()?;
                    let right_bucket = BtsbBucket::new()?;

                    // each entry
                    for (idx, entry) in bucket.entries.iter().enumerate() {
                        /* TODO:
                            let key := hkdf(ikm=contractInternalSecret, info=canonical(addr), length=256bits)
                            let bit_value := (key >> (255 - bit_pos)) & 1
                            if bit_value == 0:
                                left_bucket.add_entry(entry)
                            else:
                                right_bucket.add_entry(entry)
                        */
                    }

                    // save left node's bucket to storage, recycling this node's bucket ID
                    let left_bucket_id = node.bucket;
                    BTSB_BUCKETS.add_suffix(&left_bucket_id.to_be_bytes()).save(storage, &left_bucket);

                    // global count of buckets
                    let mut buckets_count = BTSB_BUCKETS_COUNT.load(storage).unwrap_or_default();

                    // bucket ID for right node
                    buckets_count += 1;
                    let right_bucket_id = buckets_count;
                    BTSB_BUCKETS.add_suffix(&right_bucket_id.to_be_bytes()).save(storage, &right_bucket);

                    // save updated count
                    BTSB_BUCKETS_COUNT.save(storage, &buckets_count)?;

                    // globl count of trie nodes
                    let mut nodes_count = BTSB_TRIE_NODES_COUNT.load(storage).unwrap_or_default();

                    // ID for left node
                    nodes_count += 1;
                    let left_id = nodes_count;

                    // ID for right node
                    nodes_count += 1;
                    let right_id = nodes_count;

                    // save updated count
                    BTSB_TRIE_NODES_COUNT.save(storage, &nodes_count)?;

                    // create left and right nodes
                    let left = BitwiseTrieNode {
                        left: 0,
                        right: 0,
                        bucket: left_bucket_id,
                    };
                    let right = BitwiseTrieNode {
                        left: 0,
                        right: 0,
                        bucket: right_bucket_id,
                    };

                    // save left and right node to storage
                    BTSB_TRIE_NODES.add_suffix(&left_id.to_be_bytes()).save(storage, &left)?;
                    BTSB_TRIE_NODES.add_suffix(&right_id.to_be_bytes()).save(storage, &right)?;

                    // convert this into a branch node
                    node.left = left_id;
                    node.right = right_id;
                    node.bucket = 0;

                    // save node
                    BTSB_TRIE_NODES.add_suffix(&node_id.to_be_bytes()).save(storage, &node);

                    // --

                    /* TODO
                        determine which child node the dwb entry belongs in, then retry insertion,
                        looping as many times as needed until the bucket has capacity for a new entry
                     */
                }
            }
        },
    }

    Ok(())
}


// for fetching an account's stored balance during transfer executions
pub fn constant_time_get_btsb_entry(storage: &mut dyn Storage, address: CanonicalAddr) -> StdResult<Option<StoredBalanceEntry>> {
    let (mut node, node_id, bit_pos) = locate_btsb_node(storage, &address)?;

    Ok(node.bucket(storage)?.constant_time_find_address(&address))
}

// for fetching account's stored balance and/or history during queries
pub fn quick_get_btsb_entry(storage: &mut dyn Storage, address: CanonicalAddr) -> StdResult<Option<StoredBalanceEntry>> {
    let (mut node, node_id, bit_pos) = locate_btsb_node(storage, &address)?;

    Ok(node.bucket(storage)?.quick_find_entry(&address))
}
