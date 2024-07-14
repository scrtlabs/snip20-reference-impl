//! BTBE stands for bitwise-trie of bucketed entries

use constant_time_eq::constant_time_eq;
use primitive_types::U256;
use secret_toolkit::{notification::hkdf_sha_256, serialization::{Bincode2, Serde}, storage::Item};
use serde::{Serialize, Deserialize,};
use serde_big_array::BigArray;
use cosmwasm_std::{CanonicalAddr, StdError, StdResult, Storage};

use crate::dwb::{amount_u64, DelayedWriteBufferEntry, TxBundle};
use crate::state::{safe_add_u64, INTERNAL_SECRET};

pub const KEY_BTBE_ENTRY_HISTORY: &[u8] = b"btbe-entry-hist";
pub const KEY_BTBE_BUCKETS_COUNT: &[u8] = b"btbe-buckets-cnt";
pub const KEY_BTBE_BUCKETS: &[u8] = b"btbe-buckets";
pub const KEY_BTBE_TRIE_NODES: &[u8] = b"btbe-trie-nodes";
pub const KEY_BTBE_TRIE_NODES_COUNT: &[u8] = b"btbe-trie-nodes-cnt";

const BUCKETING_SALT_BYTES: &[u8; 14] = b"bucketing-salt";

const U16_BYTES: usize = 2;
const U32_BYTES: usize = 4;
const U64_BYTES: usize = 8;
const U128_BYTES: usize = 16;

#[cfg(test)]
const BTBE_BUCKET_ADDRESS_BYTES: usize = 54;
#[cfg(not(test))]
const BTBE_BUCKET_ADDRESS_BYTES: usize = 20;
const BTBE_BUCKET_BALANCE_BYTES: usize = 8;  // Max 16 (u128)
const BTBE_BUCKET_HISTORY_BYTES: usize = 4;  // Max 4  (u32)

const_assert!(BTBE_BUCKET_BALANCE_BYTES <= U128_BYTES);
const_assert!(BTBE_BUCKET_HISTORY_BYTES <= U32_BYTES);

const BTBE_BUCKET_ENTRY_BYTES: usize = BTBE_BUCKET_ADDRESS_BYTES + BTBE_BUCKET_BALANCE_BYTES + BTBE_BUCKET_HISTORY_BYTES;

/// canonical address bytes corresponding to the 33-byte null public key, in hexadecimal
#[cfg(test)]
const IMPOSSIBLE_ADDR: [u8; BTBE_BUCKET_ADDRESS_BYTES] = [0x29,0xCF,0xC6,0x37,0x62,0x55,0xA7,0x84,0x51,0xEE,0xB4,0xB1,0x29,0xED,0x8E,0xAC,0xFF,0xA2,0xFE,0xEF,
                                                          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
#[cfg(not(test))]
const IMPOSSIBLE_ADDR: [u8; BTBE_BUCKET_ADDRESS_BYTES] = [0x29,0xCF,0xC6,0x37,0x62,0x55,0xA7,0x84,0x51,0xEE,0xB4,0xB1,0x29,0xED,0x8E,0xAC,0xFF,0xA2,0xFE,0xEF];

/// A `StoredEntry` consists of the address, balance, and tx bundle history length in a byte array representation.
/// The methods of the struct implementation also handle pushing and getting the tx bundle history in a simplified 
/// append store.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[cfg_attr(test, derive(Eq))]
pub struct StoredEntry(
    #[serde(with = "BigArray")]
    [u8; BTBE_BUCKET_ENTRY_BYTES],
);

impl StoredEntry {
    fn new(address: CanonicalAddr) -> StdResult<Self> {
        let address = address.as_slice();

        if address.len() != BTBE_BUCKET_ADDRESS_BYTES {
            return Err(StdError::generic_err("bucket: invalid address length"));
        }

        let mut result = [0u8; BTBE_BUCKET_ENTRY_BYTES];
        result[..BTBE_BUCKET_ADDRESS_BYTES].copy_from_slice(address);
        Ok(Self {
            0: result,
        })
    }

    fn from(storage: &mut dyn Storage, dwb_entry: &DelayedWriteBufferEntry, amount_spent: Option<u128>) -> StdResult<Self> {
        let mut entry = StoredEntry::new(dwb_entry.recipient()?)?;

        let amount_spent = amount_u64(amount_spent)?;

        // error should never happen because already checked in `settle_sender_or_owner_account`
        let balance = if let Some(new_balance) = dwb_entry.amount()?.checked_sub(amount_spent) {
            new_balance
        } else {
            return Err(StdError::generic_err(format!(
                "insufficient funds",
            )));
        };

        entry.set_balance(balance)?;
        entry.push_tx_bundle(
            storage, 
            &TxBundle {
                head_node: dwb_entry.head_node()?,
                list_len: dwb_entry.list_len()?,
                offset: 0,
            }
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

    pub fn merge_dwb_entry(
        &mut self, 
        storage: &mut dyn Storage, 
        dwb_entry: &DelayedWriteBufferEntry, 
        amount_spent: Option<u128>
    ) -> StdResult<()> {
        let history_len = self.history_len()?;
        if history_len == 0 {
            return Err(StdError::generic_err("use `from` to create new entry from dwb_entry"));
        }

        let mut balance = self.balance()?;
        safe_add_u64(&mut balance, dwb_entry.amount()?);

        let amount_spent = amount_u64(amount_spent)?;

        // error should never happen because already checked in `settle_sender_or_owner_account`
        let balance = if let Some(new_balance) = balance.checked_sub(amount_spent) {
            new_balance
        } else {
            return Err(StdError::generic_err(format!(
                "insufficient funds",
            )));
        };

        self.set_balance(balance)?;

        // peek at the last tx bundle added
        let last_tx_bundle = self.get_tx_bundle_at(storage, history_len - 1)?;
        let tx_bundle = TxBundle {
            head_node: dwb_entry.head_node()?,
            list_len: dwb_entry.list_len()?,
            offset: last_tx_bundle.offset + u32::from(last_tx_bundle.list_len),
        };
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
        let bundle_data = storage.get(&[KEY_BTBE_ENTRY_HISTORY, self.address_slice(), pos.to_be_bytes().as_slice()].concat());
        let bundle_data = bundle_data.ok_or_else(|| { return StdError::generic_err("tx bundle not found"); } )?;
        Bincode2::deserialize(
            &bundle_data
        )
    }

    /// Sets data at a given index
    fn set_tx_bundle_at_unchecked(&self, storage: &mut dyn Storage, pos: u32, bundle: &TxBundle) -> StdResult<()> {
        let bundle_data = Bincode2::serialize(bundle)?;
        storage.set(&[KEY_BTBE_ENTRY_HISTORY, self.address_slice(), pos.to_be_bytes().as_slice()].concat(), &bundle_data);
        Ok(())
    }

    /// Pushes a tx bundle
    fn push_tx_bundle(&mut self, storage: &mut dyn Storage, bundle: &TxBundle) -> StdResult<()> {
        let len = self.history_len()?;
        self.set_tx_bundle_at_unchecked(storage, len, bundle)?;
        self.set_history_len(len.saturating_add(1))?;
        Ok(())
    }
}

const BTBE_BUCKET_LEN: u16 = 128;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct BtbeBucket {
    pub capacity: u16,
    #[serde(with = "BigArray")]
    pub entries: [StoredEntry; BTBE_BUCKET_LEN as usize],
}

//static BTBE_ENTRY_HISTORY: Item<u64> = Item::new(KEY_BTBE_ENTRY_HISTORY);
static BTBE_BUCKETS_COUNT: Item<u64> = Item::new(KEY_BTBE_BUCKETS_COUNT);
static BTBE_BUCKETS: Item<BtbeBucket> = Item::new(KEY_BTBE_BUCKETS);

// create type alias to refer to position of a bucket entry, which is its index in the array plus 1
type BucketEntryPosition = usize;

impl BtbeBucket {
    pub fn new() -> StdResult<Self> {
        Ok(Self {
            capacity: BTBE_BUCKET_LEN,
            entries: [
                StoredEntry::new(CanonicalAddr::from(&IMPOSSIBLE_ADDR))?; BTBE_BUCKET_LEN as usize
            ]
        })
    }

    /// Attempts to add an entry to the bucket; returns false if bucket is at capacity, or true on success
    pub fn add_entry(&mut self, entry: &StoredEntry) -> bool {
        // buffer is at capacity
        if self.capacity == 0 {
            return false;
        }

        // has capacity for a new entry; save entry to bucket 
        self.entries[self.entries.len() - self.capacity as usize] = entry.clone();

        // update capacity
        self.capacity -= 1;

        // done
        true
    }

    /// Searches the bucket for an entry containing the given address
    pub fn constant_time_find_address(&self, address: &CanonicalAddr) -> Option<(usize, StoredEntry)> {
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
        BTBE_BUCKETS.add_suffix(&bucket_id.to_be_bytes()).save(storage, &bucket)?;

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
            return Err(StdError::generic_err("btbe: attempted to load bucket of branch node"));
        }

        // load bucket from storage
        BTBE_BUCKETS.add_suffix(&self.bucket.to_be_bytes()).load(storage)
    }

    // stores the bucket associated with this node
    fn set_and_save_bucket(self, storage: &mut dyn Storage, bucket: BtbeBucket) -> StdResult<()> {
        if self.bucket == 0 {
            return Err(StdError::generic_err("btbe: attempted to store a bucket to a branch node"));
        }

        BTBE_BUCKETS.add_suffix(&self.bucket.to_be_bytes()).save(storage, &bucket)
    }
}

/// Determines whether a given entry belongs in the left node (true) or right node (false)
fn entry_belongs_in_left_node(secret: &[u8], entry: StoredEntry, bit_pos: u8) -> StdResult<bool> {
    // create key bytes
    let key_bytes = hkdf_sha_256(&Some(BUCKETING_SALT_BYTES.to_vec()), secret, entry.address_slice(), 256)?;

    // convert to u258
    let key_u256 = U256::from_big_endian(&key_bytes);

    // extract the bit value at the target bit position
    return Ok(U256::from(0) == (key_u256 >> (255 - bit_pos)) & U256::from(1));
}

/// Locates a btbe node given an address; returns tuple of (node, bit position)
pub fn locate_btbe_node(storage: &dyn Storage, address: &CanonicalAddr) -> StdResult<(BitwiseTrieNode, u64, u8)> {
    // load internal contract secret
    let secret = INTERNAL_SECRET.load(storage)?;
    let secret = secret.as_slice();

    // create key bytes
    let hash = hkdf_sha_256(&Some(BUCKETING_SALT_BYTES.to_vec()), secret, address.as_slice(), 256)?;
    
    // start at root of trie
    let mut node_id: u64 = 1;
    let mut node = BTBE_TRIE_NODES.add_suffix(&node_id.to_be_bytes()).load(storage)?;
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
        node = BTBE_TRIE_NODES.add_suffix(&node_id.to_be_bytes()).load(storage)?;
    }

    Ok((node, node_id, bit_pos))
}

/// Does a binary search on the append store to find the bundle where the `start_idx` tx can be found.
/// For a paginated search `start_idx` = `page` * `page_size`.
/// Returns the bundle index, the bundle, and the index in the bundle list to start at
pub fn find_start_bundle(storage: &dyn Storage, account: &CanonicalAddr, start_idx: u32) -> StdResult<Option<(u32, TxBundle, u32)>> {
    let (node, _, _) = locate_btbe_node(storage, account)?;
    let bucket = node.bucket(storage)?;
    if let Some((_, entry)) = bucket.constant_time_find_address(account) {
        let mut left = 0u32;
        let mut right = entry.history_len()?;
    
        while left <= right {
            let mid = (left + right) / 2;
            let mid_bundle = entry.get_tx_bundle_at(storage, mid)?;
            if start_idx >= mid_bundle.offset && start_idx < mid_bundle.offset + (mid_bundle.list_len as u32) {
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
pub fn stored_entry(storage: &dyn Storage, account: &CanonicalAddr) -> StdResult<Option<StoredEntry>> {
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


// merges a dwb entry into the current node's bucket
// `spent_amount` is any required subtraction due to being sender of tx
pub fn merge_dwb_entry(storage: &mut dyn Storage, dwb_entry: DelayedWriteBufferEntry, amount_spent: Option<u128>) -> StdResult<()> {
    // locate the node that the given entry belongs in
    let (mut node, node_id, mut bit_pos) = locate_btbe_node(storage, &dwb_entry.recipient()?)?;

    // load that node's current bucket
    let mut bucket = node.bucket(storage)?;

    // search for an existing entry
    if let Some((idx, mut found_entry)) = bucket.constant_time_find_address(&dwb_entry.recipient()?) {
        // found existing entry
        // merge amount and history from dwb entry
        found_entry.merge_dwb_entry(storage, &dwb_entry, amount_spent)?;
        bucket.entries[idx] = found_entry;

        // save updated bucket to storage
        node.set_and_save_bucket(storage, bucket)?;
    } else {
        // need to insert new entry
        // create new stored balance entry
        let btbe_entry = StoredEntry::from(storage, &dwb_entry, amount_spent)?;

        // load contract's internal secret
        let secret = INTERNAL_SECRET.load(storage)?;
        let secret = secret.as_slice();

        loop { // looping as many times as needed until the bucket has capacity for a new entry
            // try to add to the current bucket
            if bucket.add_entry(&btbe_entry) {
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
                    if entry_belongs_in_left_node(secret, entry, bit_pos)? {
                        left_bucket.add_entry(&entry);
                    } else {
                        right_bucket.add_entry(&entry);
                    }
                }

                // save left node's bucket to storage, recycling this node's bucket ID
                let left_bucket_id = node.bucket;
                BTBE_BUCKETS.add_suffix(&left_bucket_id.to_be_bytes()).save(storage, &left_bucket)?;

                // global count of buckets
                let mut buckets_count = BTBE_BUCKETS_COUNT.load(storage).unwrap_or_default();

                // bucket ID for right node
                buckets_count += 1;
                let right_bucket_id = buckets_count;
                BTBE_BUCKETS.add_suffix(&right_bucket_id.to_be_bytes()).save(storage, &right_bucket)?;

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
                BTBE_TRIE_NODES.add_suffix(&left_id.to_be_bytes()).save(storage, &left)?;
                BTBE_TRIE_NODES.add_suffix(&right_id.to_be_bytes()).save(storage, &right)?;

                // convert this into a branch node
                node.left = left_id;
                node.right = right_id;
                node.bucket = 0;

                // save node
                BTBE_TRIE_NODES.add_suffix(&node_id.to_be_bytes()).save(storage, &node)?;

                // route entry
                if entry_belongs_in_left_node(secret, btbe_entry, bit_pos)? {
                    node = left;
                    bucket = left_bucket;
                } else {
                    node = right;
                    bucket = right_bucket;
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
    BTBE_TRIE_NODES.add_suffix(&1_u64.to_be_bytes()).save(storage, &node)?;

    Ok(())
}
