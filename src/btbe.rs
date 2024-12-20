//! BTBE stands for bitwise-trie of bucketed entries

include!(concat!(env!("OUT_DIR"), "/config.rs"));

use constant_time_eq::constant_time_eq;
use cosmwasm_std::{CanonicalAddr, StdError, StdResult, Storage};
use secret_toolkit::{
    serialization::{Bincode2, Serde},
    storage::Item,
};
use secret_toolkit_crypto::hkdf_sha_256;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::constants::{ADDRESS_BYTES_LEN, IMPOSSIBLE_ADDR};
use crate::dwb::{amount_u64, constant_time_if_else_u32, DelayedWriteBufferEntry, TxBundle};
#[cfg(feature = "gas_tracking")]
use crate::gas_tracker::GasTracker;
use crate::state::{safe_add, safe_add_u64, INTERNAL_SECRET_SENSITIVE};

pub const KEY_BTBE_ENTRY_HISTORY: &[u8] = b"btbe-entry-hist";
pub const KEY_BTBE_BUCKETS_COUNT: &[u8] = b"btbe-buckets-cnt";
pub const KEY_BTBE_BUCKETS: &[u8] = b"btbe-buckets";
pub const KEY_BTBE_TRIE_NODES: &[u8] = b"btbe-trie-nodes";
pub const KEY_BTBE_TRIE_NODES_COUNT: &[u8] = b"btbe-trie-nodes-cnt";

const BUCKETING_SALT_BYTES: &[u8; 14] = b"bucketing-salt";

const U32_BYTES: usize = 4;
const U128_BYTES: usize = 16;

const BTBE_BUCKET_ADDRESS_BYTES: usize = ADDRESS_BYTES_LEN;
const BTBE_BUCKET_BALANCE_BYTES: usize = 8; // Max 16 (u64)
const BTBE_BUCKET_HISTORY_BYTES: usize = 4; // Max 4  (u32)
const BTBE_BUCKET_CACHE_BYTES: usize = 0;

const_assert!(BTBE_BUCKET_BALANCE_BYTES <= U128_BYTES);
const_assert!(BTBE_BUCKET_HISTORY_BYTES <= U32_BYTES);

const BTBE_BUCKET_ENTRY_BYTES: usize = BTBE_BUCKET_ADDRESS_BYTES
    + BTBE_BUCKET_BALANCE_BYTES
    + BTBE_BUCKET_HISTORY_BYTES
    + BTBE_BUCKET_CACHE_BYTES;

/// A `StoredEntry` consists of the address, balance, and tx bundle history length in a byte array representation.
/// The methods of the struct implementation also handle pushing and getting the tx bundle history in a simplified
/// append store.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[cfg_attr(test, derive(Eq))]
pub struct StoredEntry(#[serde(with = "BigArray")] [u8; BTBE_BUCKET_ENTRY_BYTES]);

impl StoredEntry {
    fn new(address: &CanonicalAddr) -> StdResult<Self> {
        let address = address.as_slice();

        if address.len() != BTBE_BUCKET_ADDRESS_BYTES {
            return Err(StdError::generic_err("bucket: invalid address length"));
        }

        let mut result = [0u8; BTBE_BUCKET_ENTRY_BYTES];
        result[..BTBE_BUCKET_ADDRESS_BYTES].copy_from_slice(address);
        Ok(Self { 0: result })
    }

    fn from(
        storage: &mut dyn Storage,
        dwb_entry: &DelayedWriteBufferEntry,
        amount_spent: Option<u128>,
    ) -> StdResult<Self> {
        let mut entry = StoredEntry::new(&dwb_entry.recipient()?)?;

        let amount_spent = amount_u64(amount_spent)?;

        // error should never happen because already checked in `settle_sender_or_owner_account`
        let balance = if let Some(new_balance) = dwb_entry.amount()?.checked_sub(amount_spent) {
            new_balance
        } else {
            return Err(StdError::generic_err(format!(
                "insufficient funds while creating StoredEntry; balance:{}, amount_spent:{}",
                dwb_entry.amount()?,
                amount_spent,
            )));
        };

        entry.set_balance(balance)?;
        entry.push_tx_bundle(
            storage,
            &TxBundle {
                head_node: dwb_entry.head_node()?,
                list_len: dwb_entry.list_len()?,
                offset: 0,
            },
        )?;

        Ok(entry)
    }

    fn address_slice(&self) -> &[u8] {
        &self.0[..BTBE_BUCKET_ADDRESS_BYTES]
    }

    fn address(&self) -> StdResult<CanonicalAddr> {
        let result = CanonicalAddr::try_from(self.address_slice())
            .or(Err(StdError::generic_err("Get bucket address error")))?;
        Ok(result)
    }

    pub fn balance(&self) -> StdResult<u64> {
        let start = BTBE_BUCKET_ADDRESS_BYTES;
        let end = start + BTBE_BUCKET_BALANCE_BYTES;
        let amount_slice = &self.0[start..end];
        let result = amount_slice
            .try_into()
            .or(Err(StdError::generic_err("Get bucket balance error")))?;
        Ok(u64::from_be_bytes(result))
    }

    fn set_balance(&mut self, val: u64) -> StdResult<()> {
        let start = BTBE_BUCKET_ADDRESS_BYTES;
        let end = start + BTBE_BUCKET_BALANCE_BYTES;
        self.0[start..end].copy_from_slice(&val.to_be_bytes());
        Ok(())
    }

    pub fn history_len(&self) -> StdResult<u32> {
        let start = BTBE_BUCKET_ADDRESS_BYTES + BTBE_BUCKET_BALANCE_BYTES;
        let end = start + BTBE_BUCKET_HISTORY_BYTES;
        let history_len_slice = &self.0[start..end];
        let mut result = [0u8; U32_BYTES];
        result[U32_BYTES - BTBE_BUCKET_HISTORY_BYTES..].copy_from_slice(history_len_slice);
        Ok(u32::from_be_bytes(result))
    }

    fn set_history_len(&mut self, val: u32) -> StdResult<()> {
        let start = BTBE_BUCKET_ADDRESS_BYTES + BTBE_BUCKET_BALANCE_BYTES;
        let end = start + BTBE_BUCKET_HISTORY_BYTES;
        let val_bytes = &val.to_be_bytes()[U32_BYTES - BTBE_BUCKET_HISTORY_BYTES..];
        if val_bytes.len() != BTBE_BUCKET_HISTORY_BYTES {
            return Err(StdError::generic_err("Set bucket history len error"));
        }
        self.0[start..end].copy_from_slice(val_bytes);
        Ok(())
    }

    pub fn save_hash_cache(&mut self, storage: &dyn Storage) -> StdResult<()> {
        let hash_bytes = hkdf_sha_256(
            &Some(BUCKETING_SALT_BYTES.to_vec()),
            INTERNAL_SECRET_SENSITIVE.load(storage)?.as_slice(),
            self.address_slice(),
            32,
        )?;

        let start =
            BTBE_BUCKET_ADDRESS_BYTES + BTBE_BUCKET_BALANCE_BYTES + BTBE_BUCKET_HISTORY_BYTES;
        let end = start + BTBE_BUCKET_CACHE_BYTES;
        self.0[start..end].copy_from_slice(&hash_bytes.as_slice()[0..BTBE_BUCKET_CACHE_BYTES]);
        Ok(())
    }

    pub fn routes_to_right_node(&self, bit_pos: usize, secret: &[u8]) -> StdResult<bool> {
        // target byte value
        let byte;

        // bit pos is cached
        if bit_pos < (BTBE_BUCKET_CACHE_BYTES << 3) {
            // select the byte from cache corresponding to this bit position
            byte = self.0[BTBE_BUCKET_ADDRESS_BYTES
                + BTBE_BUCKET_BALANCE_BYTES
                + BTBE_BUCKET_HISTORY_BYTES
                + (bit_pos >> 3)];
        }
        // not cached; calculate on the fly
        else {
            // create key bytes
            let key_bytes = hkdf_sha_256(
                &Some(BUCKETING_SALT_BYTES.to_vec()),
                secret,
                self.address_slice(),
                32,
            )?;

            // select the byte containing the target bit
            byte = key_bytes[bit_pos >> 3];
        }

        // extract value at bit position and turn into bool
        return Ok(((byte >> (7 - (bit_pos % 8))) & 1) != 0);
    }

    pub fn merge_dwb_entry(
        &mut self,
        storage: &mut dyn Storage,
        dwb_entry: &DelayedWriteBufferEntry,
        amount_spent: Option<u128>,
    ) -> StdResult<()> {
        // increase account's stored balance
        let mut balance = self.balance()?;
        safe_add_u64(&mut balance, dwb_entry.amount()?);

        // safety check amount spent before spending from balance
        let amount_spent = amount_u64(amount_spent)?;

        // error should never happen because already checked in `settle_sender_or_owner_account`
        let balance = if let Some(new_balance) = balance.checked_sub(amount_spent) {
            new_balance
        } else {
            return Err(StdError::generic_err(format!(
                "insufficient funds while merging entry; balance:{}, amount_spent:{}",
                balance, amount_spent
            )));
        };

        // set new balance to stored entry
        self.set_balance(balance)?;

        // retrieve currenty history length
        let history_len = self.history_len()?;

        // flag if history is empty
        let empty_history = (history_len == 0) as u32;

        // position of last tx bundle to read
        let bundle_pos = constant_time_if_else_u32(
            empty_history,
            0u32,
            history_len.wrapping_sub(1), // constant-time subtraction with underflow
        );

        // peek at the last tx bundle added (read the dummy one if its void)
        let last_tx_bundle_result = self.get_tx_bundle_at_unchecked(storage, bundle_pos);
        if last_tx_bundle_result.is_err() {
            return Err(StdError::generic_err(format!(
                "missing tx bundle while merging dwb entry!",
            )));
        }

        // unwrap
        let last_tx_bundle = last_tx_bundle_result?;

        // calculate the appropriate bundle offset to use
        let bundle_offset = constant_time_if_else_u32(
            empty_history,
            0u32,
            last_tx_bundle.offset + (last_tx_bundle.list_len as u32),
        );

        // create new tx bundle
        let tx_bundle = TxBundle {
            head_node: dwb_entry.head_node()?,
            list_len: dwb_entry.list_len()?,
            offset: bundle_offset,
        };

        // add to list
        self.push_tx_bundle(storage, &tx_bundle)?;

        Ok(())
    }

    // simplified appendstore impl for tx history

    /// gets the element at pos if within bounds
    pub fn get_tx_bundle_at(&self, storage: &dyn Storage, pos: u32) -> StdResult<TxBundle> {
        let len = self.history_len()?;
        if pos >= len {
            return Err(StdError::generic_err("access out of bounds"));
        }
        self.get_tx_bundle_at_unchecked(storage, pos)
    }

    /// tries to get the element at pos
    fn get_tx_bundle_at_unchecked(&self, storage: &dyn Storage, pos: u32) -> StdResult<TxBundle> {
        let bundle_data = storage.get(
            &[
                KEY_BTBE_ENTRY_HISTORY,
                self.address_slice(),
                pos.to_be_bytes().as_slice(),
            ]
            .concat(),
        );
        let bundle_data = bundle_data.ok_or_else(|| {
            return StdError::generic_err("tx bundle not found");
        })?;
        Bincode2::deserialize(&bundle_data)
    }

    /// Sets data at a given index
    fn set_tx_bundle_at_unchecked(
        &self,
        storage: &mut dyn Storage,
        pos: u32,
        bundle: &TxBundle,
    ) -> StdResult<()> {
        let bundle_data = Bincode2::serialize(bundle)?;
        storage.set(
            &[
                KEY_BTBE_ENTRY_HISTORY,
                self.address_slice(),
                pos.to_be_bytes().as_slice(),
            ]
            .concat(),
            &bundle_data,
        );
        Ok(())
    }

    /// Pushes a tx bundle
    fn push_tx_bundle(&mut self, storage: &mut dyn Storage, bundle: &TxBundle) -> StdResult<()> {
        let len = self.history_len()?;
        self.set_tx_bundle_at_unchecked(storage, len, bundle)?;
        // if the head node is null, then add this as a ghost bundle that does not contribute to len of list,
        // and will be overwritten next time
        let len_add = constant_time_if_else_u32((bundle.head_node == 0) as u32, 0, 1);
        self.set_history_len(len.saturating_add(len_add))?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct BtbeBucket {
    pub capacity: u16,
    #[serde(with = "BigArray")]
    pub entries: [StoredEntry; BTBE_CAPACITY as usize],
}

//static BTBE_ENTRY_HISTORY: Item<u64> = Item::new(KEY_BTBE_ENTRY_HISTORY);
static BTBE_BUCKETS_COUNT: Item<u64> = Item::new(KEY_BTBE_BUCKETS_COUNT);
static BTBE_BUCKETS: Item<BtbeBucket> = Item::new(KEY_BTBE_BUCKETS);

// create type alias to refer to position of a bucket entry, which is its index in the array plus 1
type BucketEntryPosition = usize;

impl BtbeBucket {
    pub fn new() -> StdResult<Self> {
        Ok(Self {
            capacity: BTBE_CAPACITY,
            entries: [StoredEntry::new(&CanonicalAddr::from(&IMPOSSIBLE_ADDR))?;
                BTBE_CAPACITY as usize],
        })
    }

    /// Attempts to add an entry to the bucket; returns false if bucket is at capacity, or true on success
    pub fn add_entry(&mut self, entry: &StoredEntry) -> bool {
        // buffer is at capacity
        if self.capacity == 0 {
            return false;
        }

        // has capacity for a new entry; save entry to bucket
        self.entries[(BTBE_CAPACITY - self.capacity) as usize] = entry.clone();

        // update capacity
        self.capacity -= 1;

        // done
        true
    }

    /// Searches the bucket for an entry containing the given address
    pub fn constant_time_find_address(
        &self,
        address: &CanonicalAddr,
    ) -> Option<(usize, StoredEntry)> {
        let address = address.as_slice();

        // contant-time only applies to this part, so that the index of the entry cannot be distinguished
        let mut matched_index_p1: BucketEntryPosition = 0;
        for (idx, entry) in self.entries.iter().enumerate() {
            let equals = constant_time_eq(address, entry.address_slice()) as usize;
            matched_index_p1 |= (idx + 1) * equals;
        }

        match matched_index_p1 {
            0 => None,
            idx => Some((idx - 1, self.entries[idx - 1])),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct BitwiseTrieNode {
    pub left: u64,
    pub right: u64,
    pub bucket: u64,
}

pub static BTBE_TRIE_NODES: Item<BitwiseTrieNode> = Item::new(KEY_BTBE_TRIE_NODES);
pub static BTBE_TRIE_NODES_COUNT: Item<u64> = Item::new(KEY_BTBE_TRIE_NODES_COUNT);

impl BitwiseTrieNode {
    // creates a new leaf node
    pub fn new_leaf(storage: &mut dyn Storage, bucket: BtbeBucket) -> StdResult<Self> {
        let buckets_count = BTBE_BUCKETS_COUNT.load(storage).unwrap_or_default() + 1;

        // ID for new bucket
        let bucket_id = buckets_count;

        // save updated count
        BTBE_BUCKETS_COUNT.save(storage, &buckets_count)?;

        // save bucket to storage
        BTBE_BUCKETS
            .add_suffix(&bucket_id.to_be_bytes())
            .save(storage, &bucket)?;

        // create new node
        Ok(Self {
            left: 0,
            right: 0,
            bucket: bucket_id,
        })
    }

    // loads the node's bucket from storage
    pub fn bucket(self, storage: &dyn Storage) -> StdResult<BtbeBucket> {
        if self.bucket == 0 {
            return Err(StdError::generic_err(
                "btbe: attempted to load bucket of branch node",
            ));
        }

        // load bucket from storage
        BTBE_BUCKETS
            .add_suffix(&self.bucket.to_be_bytes())
            .load(storage)
    }

    // stores the bucket associated with this node
    fn set_and_save_bucket(self, storage: &mut dyn Storage, bucket: BtbeBucket) -> StdResult<()> {
        if self.bucket == 0 {
            return Err(StdError::generic_err(
                "btbe: attempted to store a bucket to a branch node",
            ));
        }

        BTBE_BUCKETS
            .add_suffix(&self.bucket.to_be_bytes())
            .save(storage, &bucket)
    }
}

/// Locates a btbe node given an address; returns tuple of (node, node_id, bit position)
pub fn locate_btbe_node(
    storage: &dyn Storage,
    address: &CanonicalAddr,
) -> StdResult<(BitwiseTrieNode, u64, usize)> {
    // load internal contract secret
    let secret = INTERNAL_SECRET_SENSITIVE.load(storage)?;
    let secret = secret.as_slice();

    // create key bytes
    let hash = hkdf_sha_256(
        &Some(BUCKETING_SALT_BYTES.to_vec()),
        secret,
        address.as_slice(),
        32,
    )?;

    // start at root of trie
    let mut node_id: u64 = 1;
    let mut node = BTBE_TRIE_NODES
        .add_suffix(&node_id.to_be_bytes())
        .load(storage)?;

    // bit position
    let mut bit_pos: usize = 0;

    // while the node has children
    while node.bucket == 0 {
        // calculate bit value at current bit position
        let bit_value = (hash[(bit_pos / 8) as usize] >> (7 - (bit_pos % 8))) & 1;

        // increment bit position
        bit_pos += 1;

        // choose left or right child depending on bit value
        node_id = if bit_value == 0 {
            node.left
        } else {
            node.right
        };

        // load child node
        node = BTBE_TRIE_NODES
            .add_suffix(&node_id.to_be_bytes())
            .load(storage)?;
    }

    Ok((node, node_id, bit_pos))
}

/// Does a binary search on the append store to find the bundle where the `start_idx` tx can be found.
/// For a paginated search `start_idx` = `page` * `page_size`.
/// Returns the bundle index, the bundle, and the index in the bundle list to start at
pub fn find_start_bundle(
    storage: &dyn Storage,
    account: &CanonicalAddr,
    start_idx: u32,
) -> StdResult<Option<(u32, TxBundle, u32)>> {
    let (node, _, _) = locate_btbe_node(storage, account)?;
    let bucket = node.bucket(storage)?;
    if let Some((_, entry)) = bucket.constant_time_find_address(account) {
        let mut left = 0u32;
        let mut right = entry.history_len()?;

        while left <= right {
            let mid = (left + right) / 2;
            let mid_bundle = entry.get_tx_bundle_at(storage, mid)?;
            if start_idx >= mid_bundle.offset
                && start_idx < mid_bundle.offset + (mid_bundle.list_len as u32)
            {
                // we have the correct bundle
                // which index in list to start at?
                let start_at = (mid_bundle.list_len as u32) - (start_idx - mid_bundle.offset) - 1;
                return Ok(Some((mid, mid_bundle, start_at)));
            } else if start_idx < mid_bundle.offset {
                right = mid - 1;
            } else {
                left = mid + 1;
            }
        }
    }

    Ok(None)
}

/// gets the StoredEntry for a given account
pub fn stored_entry(
    storage: &dyn Storage,
    account: &CanonicalAddr,
) -> StdResult<Option<StoredEntry>> {
    let (node, _, _) = locate_btbe_node(storage, account)?;
    let bucket = node.bucket(storage)?;
    Ok(bucket.constant_time_find_address(account).map(|b| b.1))
}

/// returns the current stored balance for an entry
pub fn stored_balance(storage: &dyn Storage, address: &CanonicalAddr) -> StdResult<u128> {
    if let Some(entry) = stored_entry(storage, address)? {
        Ok(entry.balance()? as u128)
    } else {
        Ok(0_u128)
    }
}

/// Returns the total number of settled transactions for an account by peeking at last bundle
pub fn stored_tx_count(storage: &dyn Storage, entry: &Option<StoredEntry>) -> StdResult<u32> {
    if let Some(entry) = entry {
        // peek at last entry
        let len = entry.history_len()?;
        if len > 0 {
            let bundle = entry.get_tx_bundle_at(storage, len - 1)?;
            return Ok(bundle.offset + bundle.list_len as u32);
        }
    }
    Ok(0)
}

// settles a dwb entry into its appropriate bucket
// `amount_spent` is any required subtraction due to being sender of tx
pub fn settle_dwb_entry(
    storage: &mut dyn Storage,
    dwb_entry: &DelayedWriteBufferEntry,
    amount_spent: Option<u128>,
    #[cfg(feature = "gas_tracking")] tracker: &mut GasTracker,
) -> StdResult<()> {
    #[cfg(feature = "gas_tracking")]
    let mut group1 = tracker.group("#merge_dwb_entry.1");

    // ref the entry's recipient address
    let address = &dwb_entry.recipient()?;

    // locate the node that the given entry belongs in
    let (mut node, mut node_id, mut bit_pos) = locate_btbe_node(storage, address)?;

    // load that node's current bucket
    let mut bucket = node.bucket(storage)?;

    // bucket ID for logging purposes
    let mut bucket_id = node.bucket;

    // search for an existing entry
    if let Some((idx, mut found_entry)) = bucket.constant_time_find_address(address) {
        // found existing entry
        // merge amount and history from dwb entry
        found_entry.merge_dwb_entry(storage, &dwb_entry, amount_spent)?;
        bucket.entries[idx] = found_entry;

        #[cfg(feature = "gas_tracking")]
        group1.logf(format!(
            "merged {} into node #{}, bucket #{} at position {} ",
            address, node_id, bucket_id, idx
        ));

        // save updated bucket to storage
        node.set_and_save_bucket(storage, bucket)?;
    }
    // nothing was stored yet
    else {
        // need to insert new entry
        // create new stored balance entry
        let mut btbe_entry = StoredEntry::from(storage, &dwb_entry, amount_spent)?;

        // cache the address
        btbe_entry.save_hash_cache(storage)?;

        // load contract's internal secret
        let secret = INTERNAL_SECRET_SENSITIVE.load(storage)?;
        let secret = secret.as_slice();

        loop {
            // looping as many times as needed until the bucket has capacity for a new entry
            // try to add to the current bucket
            if bucket.add_entry(&btbe_entry) {
                #[cfg(feature = "gas_tracking")]
                group1.logf(format!(
                    "inserted into node #{}, bucket #{} (bitpos: {}) at position {}",
                    node_id,
                    bucket_id,
                    bit_pos,
                    BTBE_CAPACITY - bucket.capacity - 1
                ));

                // bucket has capacity and it added the new entry
                // save bucket to storage
                node.set_and_save_bucket(storage, bucket)?;
                // break out of the loop
                break;
            } else {
                // bucket is full; split on next bit position
                // create new left and right buckets
                let mut left_bucket = BtbeBucket::new()?;
                let mut right_bucket = BtbeBucket::new()?;

                // each entry
                for entry in bucket.entries {
                    // route entry
                    if entry.routes_to_right_node(bit_pos, secret)? {
                        right_bucket.add_entry(&entry);
                    } else {
                        left_bucket.add_entry(&entry);
                    }
                }

                // save left node's bucket to storage, recycling this node's bucket ID
                let left_bucket_id = node.bucket;
                BTBE_BUCKETS
                    .add_suffix(&left_bucket_id.to_be_bytes())
                    .save(storage, &left_bucket)?;

                // global count of buckets
                let mut buckets_count = BTBE_BUCKETS_COUNT.load(storage).unwrap_or_default();

                // bucket ID for right node
                buckets_count += 1;
                let right_bucket_id = buckets_count;
                BTBE_BUCKETS
                    .add_suffix(&right_bucket_id.to_be_bytes())
                    .save(storage, &right_bucket)?;

                // save updated count
                BTBE_BUCKETS_COUNT.save(storage, &buckets_count)?;

                // global count of trie nodes
                let mut nodes_count = BTBE_TRIE_NODES_COUNT.load(storage).unwrap_or_default();

                // ID for left node
                nodes_count += 1;
                let left_id = nodes_count;

                // ID for right node
                nodes_count += 1;
                let right_id = nodes_count;

                // save updated count
                BTBE_TRIE_NODES_COUNT.save(storage, &nodes_count)?;

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
                BTBE_TRIE_NODES
                    .add_suffix(&left_id.to_be_bytes())
                    .save(storage, &left)?;
                BTBE_TRIE_NODES
                    .add_suffix(&right_id.to_be_bytes())
                    .save(storage, &right)?;

                // convert this into a branch node
                node.left = left_id;
                node.right = right_id;
                node.bucket = 0;

                // save node
                BTBE_TRIE_NODES
                    .add_suffix(&node_id.to_be_bytes())
                    .save(storage, &node)?;

                #[cfg(feature = "gas_tracking")]
                group1.logf(format!(
                    "split node #{}, bucket #{} at bitpos {}, ",
                    node_id, bucket_id, bit_pos
                ));

                // route entry
                if btbe_entry.routes_to_right_node(bit_pos, secret)? {
                    node = right;
                    node_id = right_id;
                    bucket = right_bucket;
                    bucket_id = right_bucket_id;
                } else {
                    node = left;
                    node_id = left_id;
                    bucket = left_bucket;
                    bucket_id = left_bucket_id;
                }

                // increment bit position for next iteration of the loop
                bit_pos += 1;
            }
        }
    }

    Ok(())
}

/// initializes the btbe
pub fn initialize_btbe(storage: &mut dyn Storage) -> StdResult<()> {
    let bucket = BtbeBucket::new()?;
    let node = BitwiseTrieNode::new_leaf(storage, bucket)?;

    // save count
    BTBE_TRIE_NODES_COUNT.save(storage, &1)?;

    // save root node to storage
    BTBE_TRIE_NODES
        .add_suffix(&1_u64.to_be_bytes())
        .save(storage, &node)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::any::Any;

    use crate::contract::instantiate;
    use crate::msg::{InitialBalance, InstantiateMsg, QueryAnswer};
    use cosmwasm_std::{
        from_binary, testing::*, Addr, Api, Binary, OwnedDeps, QueryResponse, Response, Uint128,
    };

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

    fn extract_error_msg<T: Any>(error: StdResult<T>) -> String {
        match error {
            Ok(response) => {
                let bin_err = (&response as &dyn Any)
                    .downcast_ref::<QueryResponse>()
                    .expect("An error was expected, but no error could be extracted");
                match from_binary(bin_err).unwrap() {
                    QueryAnswer::ViewingKeyError { msg } => msg,
                    _ => panic!("Unexpected query answer"),
                }
            }
            Err(err) => match err {
                StdError::GenericErr { msg, .. } => msg,
                _ => panic!("Unexpected result from init"),
            },
        }
    }

    #[test]
    fn test_stored_entry() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);

        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let canonical = deps
            .api
            .addr_canonicalize(Addr::unchecked("bob".to_string()).as_str())
            .unwrap();

        let entry = StoredEntry::new(&canonical).unwrap();
        assert_eq!(entry.address().unwrap(), canonical);
        assert_eq!(entry.balance().unwrap(), 0_u64);

        let dwb_entry = DelayedWriteBufferEntry::new(&canonical).unwrap();

        // expect error if trying to spend too much
        let entry = StoredEntry::from(&mut deps.storage, &dwb_entry, Some(1));
        let error = extract_error_msg(entry);
        assert!(error.contains("insufficient funds"));

        let entry = StoredEntry::from(&mut deps.storage, &dwb_entry, None).unwrap();
        assert_eq!(entry.address().unwrap(), canonical);
        assert_eq!(entry.balance().unwrap(), 0_u64);
    }

    #[test]
    fn test_btbe() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let storage = &mut deps.storage;

        let _ = initialize_btbe(storage).unwrap();

        let btbe_node_count = BTBE_TRIE_NODES_COUNT.load(storage).unwrap();
        assert_eq!(btbe_node_count, 1);

        for i in 1..=64 {
            let canonical = deps
                .api
                .addr_canonicalize(Addr::unchecked(format!("{i}zzzzzz")).as_str())
                .unwrap();

            let mut entry = StoredEntry::new(&canonical).unwrap();
            let _ = entry.save_hash_cache(storage).unwrap();

            assert_eq!(entry.address().unwrap(), canonical);
            assert_eq!(entry.balance().unwrap(), 0_u64);

            let mut dwb_entry = DelayedWriteBufferEntry::new(&canonical).unwrap();

            let _result = settle_dwb_entry(storage, &mut dwb_entry, None);

            let btbe_node_count = BTBE_TRIE_NODES_COUNT.load(storage).unwrap();
            assert_eq!(btbe_node_count, 1);

            let (node, node_id, bit_pos) = locate_btbe_node(storage, &canonical).unwrap();
            assert_eq!(
                node,
                BitwiseTrieNode {
                    left: 0,
                    right: 0,
                    bucket: 2,
                }
            );
            assert_eq!(node_id, 1);
            assert_eq!(bit_pos, 0);
        }

        // btbe trie should split nodes when get to 65th entry
        let canonical = deps
            .api
            .addr_canonicalize(Addr::unchecked(format!("bob")).as_str())
            .unwrap();
        let mut entry = StoredEntry::new(&canonical).unwrap();
        let _ = entry.save_hash_cache(storage);
        assert_eq!(entry.address().unwrap(), canonical);
        assert_eq!(entry.balance().unwrap(), 0_u64);

        let mut dwb_entry = DelayedWriteBufferEntry::new(&canonical).unwrap();

        let _result = settle_dwb_entry(&mut deps.storage, &mut dwb_entry, None);

        let btbe_node_count = BTBE_TRIE_NODES_COUNT.load(&deps.storage).unwrap();
        assert_eq!(btbe_node_count, 3);
        let (node, node_id, bit_pos) = locate_btbe_node(&deps.storage, &canonical).unwrap();
        assert_eq!(
            node,
            BitwiseTrieNode {
                left: 0,
                right: 0,
                bucket: 3,
            }
        );
        assert_eq!(node_id, 3);
        assert_eq!(bit_pos, 1);

        // have other addresses been moved to new nodes
        let first = deps
            .api
            .addr_canonicalize(Addr::unchecked(format!("1zzzzzz")).as_str())
            .unwrap();
        let (node, node_id, bit_pos) = locate_btbe_node(&deps.storage, &first).unwrap();
        assert_eq!(
            node,
            BitwiseTrieNode {
                left: 0,
                right: 0,
                bucket: 2,
            }
        );
        assert_eq!(node_id, 2);
        assert_eq!(bit_pos, 1);

        let second = deps
            .api
            .addr_canonicalize(Addr::unchecked(format!("2zzzzzz")).as_str())
            .unwrap();
        let (node, node_id, bit_pos) = locate_btbe_node(&deps.storage, &second).unwrap();
        assert_eq!(
            node,
            BitwiseTrieNode {
                left: 0,
                right: 0,
                bucket: 2,
            }
        );
        assert_eq!(node_id, 2);
        assert_eq!(bit_pos, 1);

        let canonical_entry = stored_entry(&deps.storage, &canonical).unwrap().unwrap();
        assert_eq!(canonical_entry.balance().unwrap(), 0);
        let first_entry = stored_entry(&deps.storage, &first).unwrap().unwrap();
        assert_eq!(first_entry.balance().unwrap(), 0);
        let second_entry = stored_entry(&deps.storage, &second).unwrap().unwrap();
        assert_eq!(second_entry.balance().unwrap(), 0);
        let not_entry = stored_entry(
            &deps.storage,
            &deps
                .api
                .addr_canonicalize(Addr::unchecked("alice".to_string()).as_str())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(not_entry, None);
    }
}
