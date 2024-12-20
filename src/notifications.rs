use std::collections::HashMap;

use cosmwasm_std::{Addr, Api, Binary, CanonicalAddr, Response, StdResult};
use minicbor::Encoder;
use primitive_types::{U256, U512};
use secret_toolkit::notification::{
    get_seed, notification_id, xor_bytes, DirectChannel, EncoderExt, GroupChannel, Notification,
    CBL_ADDRESS, CBL_ARRAY_SHORT, CBL_BIGNUM_U64, CBL_TIMESTAMP, CBL_U8,
};
use secret_toolkit_crypto::{hkdf_sha_512, sha_256};
use serde::{Deserialize, Serialize};

const ZERO_ADDR: [u8; 20] = [0u8; 20];

// maximum value that can be stored in 62 bits
const U62_MAX: u128 = (1 << 62) - 1;

// maximum value that can be stored in 63 bits
const U63_MAX: u128 = (1 << 63) - 1;

#[derive(Serialize, Debug, Deserialize, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct RecvdNotification {
    pub amount: u128,
    pub sender: Option<Addr>,
    pub memo_len: usize,
    pub sender_is_owner: bool,
}

/// ```cddl
///  recvd = [
///     amount: biguint .size 8,  ; transfer amount in base denomination
///     sender: bstr .size 20,    ; number of actions the execution performed
///     memo_len: uint .size 1,   ; byte sequence of first recipient's canonical address
/// ]
/// ```
impl DirectChannel for RecvdNotification {
    const CHANNEL_ID: &'static str = "recvd";
    #[cfg(test)]
    const CDDL_SCHEMA: &'static str =
        "recvd=[amount:biguint .size 8,sender:bstr .size 54,memo_len:uint .size 1]";
    #[cfg(not(test))]
    const CDDL_SCHEMA: &'static str =
        "recvd=[amount:biguint .size 8,sender:bstr .size 20,memo_len:uint .size 1]";
    const ELEMENTS: u64 = 3;
    #[cfg(test)]
    const PAYLOAD_SIZE: usize = CBL_ARRAY_SHORT + CBL_BIGNUM_U64 + 55 + CBL_U8;
    #[cfg(not(test))]
    const PAYLOAD_SIZE: usize = CBL_ARRAY_SHORT + CBL_BIGNUM_U64 + CBL_ADDRESS + CBL_U8;

    fn encode_cbor(&self, api: &dyn Api, encoder: &mut Encoder<&mut [u8]>) -> StdResult<()> {
        // amount:biguint (8-byte uint)
        encoder.ext_u64_from_u128(self.amount)?;

        // sender:bstr (20-byte address)
        if let Some(sender) = &self.sender {
            let sender_raw = api.addr_canonicalize(sender.as_str())?;
            encoder.ext_address(sender_raw)?;
        } else {
            encoder.ext_bytes(&ZERO_ADDR)?;
        }

        // memo_len:uint (1-byte uint)
        encoder.ext_u8(self.memo_len.clamp(0, u8::MAX.into()) as u8)?;

        Ok(())
    }
}

/// ```cddl
///  spent = [
///     amount: biguint .size 8,   ; transfer amount in base denomination
///     actions: uint .size 1,     ; number of actions the execution performed
///     recipient: bstr .size 20,  ; byte sequence of first recipient's canonical address
///     balance: biguint .size 8,  ; sender's new balance aactions
/// ]
/// ```
#[derive(Serialize, Debug, Deserialize, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct SpentNotification {
    pub amount: u128,
    pub actions: u32,
    pub recipient: Option<Addr>,
    pub balance: u128,
    pub memo_len: usize,
}

impl DirectChannel for SpentNotification {
    const CHANNEL_ID: &'static str = "spent";
    #[cfg(test)]
    const CDDL_SCHEMA: &'static str = "spent=[amount:biguint .size 8,actions:uint .size 1,recipient:bstr .size 54,balance:biguint .size 8]";
    #[cfg(not(test))]
    const CDDL_SCHEMA: &'static str = "spent=[amount:biguint .size 8,actions:uint .size 1,recipient:bstr .size 20,balance:biguint .size 8]";
    const ELEMENTS: u64 = 4;
    #[cfg(test)]
    const PAYLOAD_SIZE: usize = CBL_ARRAY_SHORT + CBL_BIGNUM_U64 + CBL_U8 + 55 + CBL_BIGNUM_U64;
    #[cfg(not(test))]
    const PAYLOAD_SIZE: usize =
        CBL_ARRAY_SHORT + CBL_BIGNUM_U64 + CBL_U8 + CBL_ADDRESS + CBL_BIGNUM_U64;

    fn encode_cbor(&self, api: &dyn Api, encoder: &mut Encoder<&mut [u8]>) -> StdResult<()> {
        // amount:biguint (8-byte uint), actions:uint (1-byte uint)
        let mut spent_data = encoder
            .ext_u64_from_u128(self.amount)?
            .ext_u8(self.actions.clamp(0, u8::MAX.into()) as u8)?;

        // recipient:bstr (20-byte address)
        if let Some(recipient) = &self.recipient {
            let recipient_raw = api.addr_canonicalize(recipient.as_str())?;
            spent_data = spent_data.ext_address(recipient_raw)?;
        } else {
            spent_data = spent_data.ext_bytes(&ZERO_ADDR)?
        }

        // balance:biguint (8-byte uint)
        spent_data.ext_u64_from_u128(self.balance)?;

        Ok(())
    }
}

///```cddl
/// allowance = [
///    amount: biguint .size 8,   ; allowance amount in base denomination
///    allower: bstr .size 20,    ; byte sequence of allower's canonical address
///    expiration: uint .size 8,  ; epoch seconds of allowance expiration
///]
/// ```
#[derive(Serialize, Debug, Deserialize, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct AllowanceNotification {
    pub amount: u128,
    pub allower: Addr,
    pub expiration: Option<u64>,
}

impl DirectChannel for AllowanceNotification {
    const CHANNEL_ID: &'static str = "allowance";
    #[cfg(test)]
    const CDDL_SCHEMA: &'static str =
        "allowance=[amount:biguint .size 8,allower:bstr .size 54,expiration:uint .size 8]";
    #[cfg(not(test))]
    const CDDL_SCHEMA: &'static str =
        "allowance=[amount:biguint .size 8,allower:bstr .size 20,expiration:uint .size 8]";
    const ELEMENTS: u64 = 3;
    #[cfg(test)]
    const PAYLOAD_SIZE: usize = CBL_ARRAY_SHORT + CBL_BIGNUM_U64 + 55 + CBL_TIMESTAMP;
    #[cfg(not(test))]
    const PAYLOAD_SIZE: usize = CBL_ARRAY_SHORT + CBL_BIGNUM_U64 + CBL_ADDRESS + CBL_TIMESTAMP;

    fn encode_cbor(&self, api: &dyn Api, encoder: &mut Encoder<&mut [u8]>) -> StdResult<()> {
        let allower_raw = api.addr_canonicalize(self.allower.as_str())?;

        // amount:biguint (8-byte uint), allower:bstr (20-byte address), expiration:uint (8-byte timestamp)
        encoder
            .ext_u64_from_u128(self.amount)?
            .ext_bytes(allower_raw.as_slice())?
            .ext_timestamp(self.expiration.unwrap_or_default())?;

        Ok(())
    }
}

pub struct MultiRecvdNotification(pub Vec<Notification<RecvdNotification>>);

impl GroupChannel<RecvdNotification> for MultiRecvdNotification {
    const CHANNEL_ID: &'static str = "multirecvd";

    // bloom parameters for the `multirecvd` channel: <https://hur.st/bloomfilter/?n=16&p=&m=512&k=22>
    const BLOOM_N: usize = 16;
    const BLOOM_M: u32 = 512;
    const BLOOM_K: u32 = 22;

    // flagsAndAmount:8 + ownerId:8 == 16 bytes
    const PACKET_SIZE: usize = 16;

    fn notifications(&self) -> &Vec<Notification<RecvdNotification>> {
        &self.0
    }

    fn build_packet(&self, api: &dyn Api, data: &RecvdNotification) -> StdResult<Vec<u8>> {
        // make the received packet
        let mut packet_plaintext = [0u8; Self::PACKET_SIZE];

        // encode flags and amount into 8 bytes (leftmost 2 bits reserved)
        let amount_bytes = &(data.amount.clamp(0, U62_MAX)
            | (((data.memo_len != 0) as u128) << 63)
            | ((data.sender_is_owner as u128) << 62))
            .to_be_bytes()[8..];

        // packet flag bits and amount bytes (u64 == 8 bytes)
        packet_plaintext[0..8].copy_from_slice(amount_bytes);

        // determine owner address
        let owner_addr: CanonicalAddr;
        let owner_bytes: &[u8];
        if let Some(owner) = &data.sender {
            owner_addr = api.addr_canonicalize(owner.as_str())?;
            owner_bytes = &owner_addr.as_slice()
        } else {
            owner_bytes = &ZERO_ADDR;
        }

        // packet owner address terminal 8 bytes (8 bytes)
        packet_plaintext[8..16].copy_from_slice(&owner_bytes[12..]);

        // 16 bytes total
        Ok(packet_plaintext.to_vec())
    }
}

// maximum supported filter size is currently 512 bits
const_assert!(MultiRecvdNotification::BLOOM_M <= 512);

// ensure m is a power of 2
const_assert!(
    MultiRecvdNotification::BLOOM_M.trailing_zeros() == MultiRecvdNotification::BLOOM_M_LOG2
);

// ensure there are enough bits in the 32-byte source hash to provide entropy for the hashes
const_assert!(MultiRecvdNotification::BLOOM_K * MultiRecvdNotification::BLOOM_M_LOG2 <= 256);

// this implementation is optimized to not check for packet sizes larger than 24 bytes
const_assert!(MultiRecvdNotification::PACKET_SIZE <= 24);

pub struct MultiSpentNotification(pub Vec<Notification<SpentNotification>>);

impl GroupChannel<SpentNotification> for MultiSpentNotification {
    const CHANNEL_ID: &str = "multispent";

    // bloom parameters for the `multispent` channel: <https://hur.st/bloomfilter/?n=4&p=&m=128&k=22>
    const BLOOM_N: usize = 4;
    const BLOOM_M: u32 = 128;
    const BLOOM_K: u32 = 22;

    // flagsAndAmount:8 + recipientId:8 + balance:8 == 24 bytes
    const PACKET_SIZE: usize = 24;

    fn notifications(&self) -> &Vec<Notification<SpentNotification>> {
        &self.0
    }

    fn build_packet(&self, api: &dyn Api, data: &SpentNotification) -> StdResult<Vec<u8>> {
        // prep the packet plaintext
        let mut packet_plaintext = [0u8; Self::PACKET_SIZE];

        // encode flags and amount into 8 bytes (leftmost 2 bits reserved)
        let amount_bytes = &(data.amount.clamp(0, U62_MAX)
            | (((data.memo_len != 0) as u128) << 63))
            .to_be_bytes()[8..];

        // packet flags and amount bytes (u64 == 8 bytes)
        packet_plaintext[0..8].copy_from_slice(amount_bytes);

        // determine recipient address
        let recipient_addr: CanonicalAddr;
        let recipient_bytes: &[u8];
        if let Some(recipient) = &data.recipient {
            recipient_addr = api.addr_canonicalize(recipient.as_str())?;
            recipient_bytes = recipient_addr.as_slice();
        } else {
            recipient_bytes = &ZERO_ADDR;
        }

        // packet recipient address terminal 8 bytes (8 bytes)
        packet_plaintext[8..16].copy_from_slice(&recipient_bytes[12..]);

        // balance bytes (u64 == 8 bytes)
        packet_plaintext[16..24]
            .copy_from_slice(&data.balance.clamp(0, u64::MAX.into()).to_be_bytes()[8..]);

        // 24 bytes total
        Ok(packet_plaintext.to_vec())
    }
}

// maximum supported filter size is currently 512 bits
const_assert!(MultiSpentNotification::BLOOM_M <= 512);

// ensure m is a power of 2
const_assert!(
    MultiSpentNotification::BLOOM_M.trailing_zeros() == MultiSpentNotification::BLOOM_M_LOG2
);

// ensure there are enough bits in the 32-byte source hash to provide entropy for the hashes
const_assert!(MultiSpentNotification::BLOOM_K * MultiSpentNotification::BLOOM_M_LOG2 <= 256);

// this implementation is optimized to not check for packet sizes larger than 24 bytes
const_assert!(MultiSpentNotification::PACKET_SIZE <= 24);

struct BloomFilter {
    filter: U512,
    tx_hash: String,
    secret: Vec<u8>,
}

impl BloomFilter {
    fn add<D: DirectChannel, G: GroupChannel<D>>(
        &mut self,
        recipient: &CanonicalAddr,
        packet_plaintext: &Vec<u8>,
    ) -> StdResult<Vec<u8>> {
        // contribute to received bloom filter
        let seed = get_seed(&recipient, &self.secret)?;
        let id = notification_id(&seed, G::CHANNEL_ID, &self.tx_hash)?;
        let hash_bytes = U256::from_big_endian(&sha_256(id.0.as_slice()));
        let bloom_mask: U256 = U256::from(G::BLOOM_M - 1);

        // each hash section for up to k times
        for i in 0..G::BLOOM_K {
            let bit_index = ((hash_bytes >> (256 - G::BLOOM_M_LOG2 - (i * G::BLOOM_M_LOG2)))
                & bloom_mask)
                .as_usize();
            self.filter |= U512::from(1) << bit_index;
        }

        // use top 64 bits of notification ID for packet ID
        let packet_id = &id.0.as_slice()[0..8];

        // take the bottom bits from the notification ID for key material
        let packet_ikm = &id.0.as_slice()[8..32];

        // create ciphertext by XOR'ing the plaintext with the notification ID
        let packet_ciphertext = xor_bytes(&packet_plaintext[..], &packet_ikm[0..G::PACKET_SIZE]);

        // construct the packet bytes
        let packet_bytes: Vec<u8> = [packet_id.to_vec(), packet_ciphertext].concat();

        Ok(packet_bytes)
    }
}

pub fn render_group_notification<D: DirectChannel, G: GroupChannel<D>>(
    api: &dyn Api,
    group: G,
    tx_hash: &String,
    env_random: Binary,
    secret: &[u8],
    resp: Response,
) -> StdResult<Response> {
    // bloom filter
    let mut bloom_filter = BloomFilter {
        filter: U512::from(0),
        tx_hash: tx_hash.to_string(),
        secret: secret.to_vec(),
    };

    // packet structs
    let mut packets: Vec<(CanonicalAddr, Vec<u8>)> = vec![];

    // keep track of how many times an address shows up in packet data
    let mut recipient_counts: HashMap<CanonicalAddr, u16> = HashMap::new();

    // each notification
    for notification in group.notifications() {
        // who notification is intended for
        let notification_for = api.addr_canonicalize(notification.notification_for.as_str())?;
        let notifyee = notification_for.clone();

        // increment count of recipient occurrence
        recipient_counts.insert(
            notification_for,
            recipient_counts.get(&notifyee).unwrap_or(&0u16) + 1,
        );

        // skip adding this packet if recipient was already seen
        if *recipient_counts.get(&notifyee).unwrap() > 1 {
            continue;
        }

        // build packet
        let packet_plaintext = &group.build_packet(api, &notification.data)?;

        // add to bloom filter
        let packet_bytes = bloom_filter.add::<D, G>(&notifyee, packet_plaintext)?;

        // add to packets data
        packets.push((notifyee, packet_bytes));
    }

    // filter out any notifications for recipients showing up more than once
    let mut packets: Vec<Vec<u8>> = packets
        .into_iter()
        .filter(|(addr, _)| *recipient_counts.get(addr).unwrap_or(&0u16) <= 1)
        .map(|(_, packet)| packet)
        .collect();

    // still too many packets; trim down to size
    if packets.len() > G::BLOOM_N {
        packets = packets[0..G::BLOOM_N].to_vec();
    }

    // now add extra packets, if needed, to hide number of packets
    let padding_size = G::BLOOM_N.saturating_sub(packets.len());
    if padding_size > 0 {
        // fill buffer with secure random bytes
        let decoy_addresses = hkdf_sha_512(
            &Some(vec![0u8; 64]),
            &env_random,
            format!("{}:decoys", G::CHANNEL_ID).as_bytes(),
            padding_size * 20, // 20 bytes per random addr
        )?;

        // handle each padding package
        for i in 0..padding_size {
            // generate address
            let address = CanonicalAddr::from(&decoy_addresses[i * 20..(i + 1) * 20]);

            // nil plaintext
            let packet_plaintext = vec![0u8; G::PACKET_SIZE];

            // produce bytes
            let packet_bytes = bloom_filter.add::<D, G>(&address, &packet_plaintext)?;

            // add to packets list
            packets.push(packet_bytes);
        }
    }

    // prep output bytes
    let mut output_bytes: Vec<u8> = vec![];

    // append bloom filter (taking m bottom bits of 512-bit filter)
    output_bytes.extend_from_slice(
        &bloom_filter.filter.to_big_endian()[((512 - G::BLOOM_M as usize) >> 3)..],
    );

    // append packets
    for packet in packets {
        output_bytes.extend(packet.iter());
    }

    // Ok(output_bytes)
    Ok(resp.add_attribute_plaintext(
        format!("snip52:#{}", G::CHANNEL_ID),
        Binary::from(output_bytes).to_base64(),
    ))
}
