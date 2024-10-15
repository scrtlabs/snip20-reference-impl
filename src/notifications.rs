use std::collections::HashMap;

use cosmwasm_std::{Addr, Api, Binary, CanonicalAddr, StdError, StdResult};
use primitive_types::{U256, U512};
use secret_toolkit::notification::{get_seed, notification_id, xor_bytes, Notification, NotificationData};
use minicbor_ser as cbor;
use secret_toolkit_crypto::{hkdf_sha_512, sha_256};
use serde::{Deserialize, Serialize};

const ZERO_ADDR: [u8; 20] = [0u8; 20];

//  recvd = [
//      amount: biguint,   ; transfer amount in base denomination
//      sender: bstr,      ; byte sequence of sender's canonical address
//      balance: biguint   ; recipient's new balance after the transfer
//  ]

#[derive(Serialize, Debug, Deserialize, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct ReceivedNotificationData {
    pub amount: u128,
    pub sender: Option<Addr>,
}

impl NotificationData for ReceivedNotificationData {
	const CHANNEL_ID: &'static str = "recvd";
	const CDDL_SCHEMA: &'static str = "recvd=[amount:biguint,sender:bstr]";

    fn to_cbor(&self, api: &dyn Api) -> StdResult<Vec<u8>> {
        let received_data;
        if let Some(sender) = &self.sender {
            let sender_raw = api.addr_canonicalize(sender.as_str())?;
            received_data = cbor::to_vec(&(self.amount.to_be_bytes(), sender_raw.as_slice()))
                .map_err(|e| StdError::generic_err(format!("{:?}", e)))?;
        } else {
            received_data = cbor::to_vec(&(self.amount.to_be_bytes(), ZERO_ADDR))
                .map_err(|e| StdError::generic_err(format!("{:?}", e)))?;
        }
        Ok(received_data)
    }
}

// spent = [
//     amount: biguint,   ; transfer amount in base denomination
//     actions: uint      ; number of actions the execution performed
//     recipient: bstr,   ; byte sequence of first recipient's canonical address
//     balance: biguint   ; sender's new balance aactions: uint      ; number of actions the execution performedfter the transfer
// ]

#[derive(Serialize, Debug, Deserialize, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct SpentNotificationData {
    pub amount: u128,
    pub actions: u32,
    pub recipient: Option<Addr>,
    pub balance: u128,
}

impl NotificationData for SpentNotificationData {
    const CHANNEL_ID: &'static str = "spent";
	const CDDL_SCHEMA: &'static str = "spent=[amount:biguint,actions:uint,recipient:bstr,balance:biguint]";
    fn to_cbor(&self, api: &dyn Api) -> StdResult<Vec<u8>> {
        let spent_data;
        if let Some(recipient) = &self.recipient {
            let recipient_raw = api.addr_canonicalize(recipient.as_str())?;
            spent_data = cbor::to_vec(&(
                self.amount.to_be_bytes(),
                self.actions.to_be_bytes(),
                recipient_raw.as_slice(),
                self.balance.to_be_bytes(),
            ))
            .map_err(|e| StdError::generic_err(format!("{:?}", e)))?;
        } else {
            spent_data = cbor::to_vec(&(
                self.amount.to_be_bytes(),
                self.actions.to_be_bytes(),
                ZERO_ADDR,
                self.balance.to_be_bytes(),
            ))
            .map_err(|e| StdError::generic_err(format!("{:?}", e)))?;
        }
        Ok(spent_data)
    }
}

//allowance = [
//    amount: biguint,   ; allowance amount in base denomination
//    allower: bstr,     ; byte sequence of allower's canonical address
//    expiration: uint,  ; epoch seconds of allowance expiration
//]

#[derive(Serialize, Debug, Deserialize, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct AllowanceNotificationData {
    pub amount: u128,
    pub allower: Addr,
    pub expiration: Option<u64>,
}

impl NotificationData for AllowanceNotificationData {
    const CHANNEL_ID: &'static str = "allowance";
    const CDDL_SCHEMA: &'static str = "allowance=[amount:biguint,allower:bstr,expiration:uint]";
    fn to_cbor(&self, api: &dyn Api) -> StdResult<Vec<u8>> {
        let allower_raw = api.addr_canonicalize(self.allower.as_str())?;

        // use CBOR to encode data
        let updated_allowance_data = cbor::to_vec(&(
            self.amount.to_be_bytes(),
            allower_raw.as_slice(),
            self.expiration.unwrap_or(0u64), // expiration == 0 means no expiration
        ))
        .map_err(|e| StdError::generic_err(format!("{:?}", e)))?;
        Ok(updated_allowance_data)
    }
}

// multi recipient push notifications

// id for the `multirecvd` channel
pub const MULTI_RECEIVED_CHANNEL_ID: &str = "multirecvd";
pub const MULTI_RECEIVED_CHANNEL_BLOOM_K: u32 = 15;
pub const MULTI_RECEIVED_CHANNEL_BLOOM_N: u32 = 16;
pub const MULTI_RECEIVED_CHANNEL_PACKET_SIZE: u32 = 24;

// id for the `multispent` channel
pub const MULTI_SPENT_CHANNEL_ID: &str = "multispent";
pub const MULTI_SPENT_CHANNEL_BLOOM_K: u32 = 5;
pub const MULTI_SPENT_CHANNEL_BLOOM_N: u32 = 4;
pub const MULTI_SPENT_CHANNEL_PACKET_SIZE: u32 = 40;

pub fn multi_received_data(
    api: &dyn Api,
    notifications: Vec<Notification<ReceivedNotificationData>>,
    tx_hash: &String,
    env_random: Binary,
    secret: &[u8],
) -> StdResult<Vec<u8>> {
    let mut received_bloom_filter: U512 = U512::from(0);
    let mut received_packets: Vec<(Addr, Vec<u8>)> = vec![];

    // keep track of how often addresses might show up in packet data.
    // we need to remove any address that might show up more than once.
    let mut recipient_counts: HashMap<Addr, u16> = HashMap::new();

    for notification in &notifications {
        recipient_counts.insert(
            notification.notification_for.clone(),
            recipient_counts
                .get(&notification.notification_for)
                .unwrap_or(&0u16)
                + 1,
        );

        // we can short circuit this if recipient count > 1, since we will throw out this packet
        // anyway, and address has already been added to bloom filter
        if *recipient_counts
            .get(&notification.notification_for)
            .unwrap()
            > 1
        {
            continue;
        }

        // contribute to received bloom filter
        let recipient_addr_raw = api.addr_canonicalize(notification.notification_for.as_str())?;
        let seed = get_seed(&recipient_addr_raw, secret)?;
        let id = notification_id(&seed, &MULTI_RECEIVED_CHANNEL_ID.to_string(), &tx_hash)?;
        let mut hash_bytes = U256::from_big_endian(&sha_256(id.0.as_slice()));
        for _ in 0..MULTI_RECEIVED_CHANNEL_BLOOM_K {
            let bit_index = (hash_bytes & U256::from(0x01ff)).as_usize();
            received_bloom_filter = received_bloom_filter | (U512::from(1) << bit_index);
            hash_bytes = hash_bytes >> 9;
        }

        // make the received packet
        let mut received_packet_plaintext: Vec<u8> = vec![];
        // amount bytes (u128 == 16 bytes)
        received_packet_plaintext.extend_from_slice(&notification.data.amount.to_be_bytes());
        // sender account last 8 bytes
        let sender_bytes: &[u8];
        let sender_raw;
        if let Some(sender) = &notification.data.sender {
            sender_raw = api.addr_canonicalize(sender.as_str())?;
            sender_bytes = &sender_raw.as_slice()[sender_raw.0.len() - 8..];
        } else {
            sender_bytes = &ZERO_ADDR[ZERO_ADDR.len() - 8..];
        }
        // 24 bytes total
        received_packet_plaintext.extend_from_slice(sender_bytes);

        let received_packet_id = &id.0.as_slice()[0..8];
        let received_packet_ikm = &id.0.as_slice()[8..32];
        let received_packet_ciphertext =
            xor_bytes(received_packet_plaintext.as_slice(), received_packet_ikm);
        let received_packet_bytes: Vec<u8> =
            [received_packet_id.to_vec(), received_packet_ciphertext].concat();

        received_packets.push((notification.notification_for.clone(), received_packet_bytes));
    }

    // filter out any notifications for recipients showing up more than once
    let mut received_packets: Vec<Vec<u8>> = received_packets
        .into_iter()
        .filter(|(addr, _)| *recipient_counts.get(addr).unwrap_or(&0u16) <= 1)
        .map(|(_, packet)| packet)
        .collect();
    if received_packets.len() > MULTI_RECEIVED_CHANNEL_BLOOM_N as usize {
        // still too many packets
        received_packets = received_packets[0..MULTI_RECEIVED_CHANNEL_BLOOM_N as usize].to_vec();
    }

    // now add extra packets, if needed, to hide number of packets
    let padding_size =
        MULTI_RECEIVED_CHANNEL_BLOOM_N.saturating_sub(received_packets.len() as u32) as usize;
    if padding_size > 0 {
        let padding_addresses = hkdf_sha_512(
            &Some(vec![0u8; 64]),
            &env_random,
            format!("{}:decoys", MULTI_RECEIVED_CHANNEL_ID).as_bytes(),
            padding_size * 20, // 20 bytes per random addr
        )?;

        // handle each padding package
        for i in 0..padding_size {
            let padding_address = &padding_addresses[i * 20..(i + 1) * 20];

            // contribute padding packet to bloom filter
            let seed = get_seed(&CanonicalAddr::from(padding_address), secret)?;
            let id = notification_id(&seed, &MULTI_RECEIVED_CHANNEL_ID.to_string(), &tx_hash)?;
            let mut hash_bytes = U256::from_big_endian(&sha_256(id.0.as_slice()));
            for _ in 0..MULTI_RECEIVED_CHANNEL_BLOOM_K {
                let bit_index = (hash_bytes & U256::from(0x01ff)).as_usize();
                received_bloom_filter = received_bloom_filter | (U512::from(1) << bit_index);
                hash_bytes = hash_bytes >> 9;
            }

            // padding packet plaintext
            let padding_packet_plaintext = [0u8; MULTI_RECEIVED_CHANNEL_PACKET_SIZE as usize];
            let padding_packet_id = &id.0.as_slice()[0..8];
            let padding_packet_ikm = &id.0.as_slice()[8..32];
            let padding_packet_ciphertext =
                xor_bytes(padding_packet_plaintext.as_slice(), padding_packet_ikm);
            let padding_packet_bytes: Vec<u8> =
                [padding_packet_id.to_vec(), padding_packet_ciphertext].concat();
            received_packets.push(padding_packet_bytes);
        }
    }

    let mut received_bloom_filter_bytes: Vec<u8> = vec![];
    for biguint in received_bloom_filter.0 {
        received_bloom_filter_bytes.extend_from_slice(&biguint.to_be_bytes());
    }
    for packet in received_packets {
        received_bloom_filter_bytes.extend(packet.iter());
    }

    Ok(received_bloom_filter_bytes)
}

pub fn multi_spent_data(
    api: &dyn Api,
    notifications: Vec<Notification<SpentNotificationData>>,
    tx_hash: &String,
    env_random: Binary,
    secret: &[u8],
) -> StdResult<Vec<u8>> {
    let mut spent_bloom_filter: U512 = U512::from(0);
    let mut spent_packets: Vec<(Addr, Vec<u8>)> = vec![];

    // keep track of how often addresses might show up in packet data.
    // we need to remove any address that might show up more than once.
    let mut spent_counts: HashMap<Addr, u16> = HashMap::new();

    for notification in &notifications {
        spent_counts.insert(
            notification.notification_for.clone(),
            spent_counts
                .get(&notification.notification_for)
                .unwrap_or(&0u16)
                + 1,
        );

        // we can short circuit this if recipient count > 1, since we will throw out this packet
        // anyway, and address has already been added to bloom filter
        if *spent_counts.get(&notification.notification_for).unwrap() > 1 {
            continue;
        }

        let spender_addr_raw = api.addr_canonicalize(notification.notification_for.as_str())?;
        let seed = get_seed(&spender_addr_raw, secret)?;
        let id = notification_id(&seed, &MULTI_SPENT_CHANNEL_ID.to_string(), &tx_hash)?;
        let mut hash_bytes = U256::from_big_endian(&sha_256(id.0.as_slice()));
        for _ in 0..MULTI_SPENT_CHANNEL_BLOOM_K {
            let bit_index = (hash_bytes & U256::from(0x01ff)).as_usize();
            spent_bloom_filter = spent_bloom_filter | (U512::from(1) << bit_index);
            hash_bytes = hash_bytes >> 9;
        }

        // make the spent packet
        let mut spent_packet_plaintext: Vec<u8> = vec![];
        // amount bytes (u128 == 16 bytes)
        spent_packet_plaintext.extend_from_slice(&notification.data.amount.to_be_bytes());
        // balance bytes (u128 == 16 bytes)
        spent_packet_plaintext.extend_from_slice(&notification.data.balance.to_be_bytes());
        // recipient account last 8 bytes
        let recipient_bytes: &[u8];
        let recipient_raw;
        if let Some(recipient) = &notification.data.recipient {
            recipient_raw = api.addr_canonicalize(recipient.as_str())?;
            recipient_bytes = &recipient_raw.as_slice()[recipient_raw.0.len() - 8..];
        } else {
            recipient_bytes = &ZERO_ADDR[ZERO_ADDR.len() - 8..];
        }
        // 40 bytes total
        spent_packet_plaintext.extend_from_slice(recipient_bytes);

        let spent_packet_size = spent_packet_plaintext.len();
        let spent_packet_id = &id.0.as_slice()[0..8];
        let spent_packet_ikm = &id.0.as_slice()[8..32];
        let spent_packet_key = hkdf_sha_512(
            &Some(vec![0u8; 64]),
            spent_packet_ikm,
            "".as_bytes(),
            spent_packet_size,
        )?;
        let spent_packet_ciphertext = xor_bytes(
            spent_packet_plaintext.as_slice(),
            spent_packet_key.as_slice(),
        );
        let spent_packet_bytes: Vec<u8> =
            [spent_packet_id.to_vec(), spent_packet_ciphertext].concat();

        spent_packets.push((notification.notification_for.clone(), spent_packet_bytes));
    }

    // filter out any notifications for senders showing up more than once
    let mut spent_packets: Vec<Vec<u8>> = spent_packets
        .into_iter()
        .filter(|(addr, _)| *spent_counts.get(addr).unwrap_or(&0u16) <= 1)
        .map(|(_, packet)| packet)
        .collect();
    if spent_packets.len() > MULTI_SPENT_CHANNEL_BLOOM_N as usize {
        // still too many packets
        spent_packets = spent_packets[0..MULTI_SPENT_CHANNEL_BLOOM_N as usize].to_vec();
    }

    // now add extra packets, if needed, to hide number of packets
    let padding_size =
        MULTI_SPENT_CHANNEL_BLOOM_N.saturating_sub(spent_packets.len() as u32) as usize;
    if padding_size > 0 {
        let padding_addresses = hkdf_sha_512(
            &Some(vec![0u8; 64]),
            &env_random,
            format!("{}:decoys", MULTI_SPENT_CHANNEL_ID).as_bytes(),
            padding_size * 20, // 20 bytes per random addr
        )?;

        // handle each padding package
        for i in 0..padding_size {
            let padding_address = &padding_addresses[i * 20..(i + 1) * 20];

            // contribute padding packet to bloom filter
            let seed = get_seed(&CanonicalAddr::from(padding_address), secret)?;
            let id = notification_id(&seed, &MULTI_SPENT_CHANNEL_ID.to_string(), &tx_hash)?;
            let mut hash_bytes = U256::from_big_endian(&sha_256(id.0.as_slice()));
            for _ in 0..MULTI_SPENT_CHANNEL_BLOOM_K {
                let bit_index = (hash_bytes & U256::from(0x01ff)).as_usize();
                spent_bloom_filter = spent_bloom_filter | (U512::from(1) << bit_index);
                hash_bytes = hash_bytes >> 9;
            }

            // padding packet plaintext
            let padding_packet_plaintext = [0u8; MULTI_SPENT_CHANNEL_PACKET_SIZE as usize];
            let padding_plaintext_size = MULTI_SPENT_CHANNEL_PACKET_SIZE as usize;
            let padding_packet_id = &id.0.as_slice()[0..8];
            let padding_packet_ikm = &id.0.as_slice()[8..32];
            let padding_packet_key = hkdf_sha_512(
                &Some(vec![0u8; 64]),
                padding_packet_ikm,
                "".as_bytes(),
                padding_plaintext_size,
            )?;
            let padding_packet_ciphertext = xor_bytes(
                padding_packet_plaintext.as_slice(),
                padding_packet_key.as_slice(),
            );
            let padding_packet_bytes: Vec<u8> =
                [padding_packet_id.to_vec(), padding_packet_ciphertext].concat();
            spent_packets.push(padding_packet_bytes);
        }
    }

    let mut spent_bloom_filter_bytes: Vec<u8> = vec![];
    for biguint in spent_bloom_filter.0 {
        spent_bloom_filter_bytes.extend_from_slice(&biguint.to_be_bytes());
    }
    for packet in spent_packets {
        spent_bloom_filter_bytes.extend(packet.iter());
    }

    Ok(spent_bloom_filter_bytes)
}