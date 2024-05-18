use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use cosmwasm_std::CanonicalAddr;
use secret_toolkit::storage::Item;

pub const DWB_LEN: u16 = 64;
pub const KEY_DWB: &[u8] = b"dwb";
pub const KEY_NEXT_LIST_ID: &[u8] = b"dwb-list"; 

pub static DWB: Item<DelayedWriteBuffer> = Item::new(KEY_DWB);
pub static NEXT_LIST_ID: Item<u64> = Item::new(KEY_NEXT_LIST_ID);

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

#[derive(Serialize, Deserialize, Debug)]
pub struct DelayedWriteBufferElement {
    pub recipient: CanonicalAddr,
    pub amount: u128,
    pub list_id: u64,
}
