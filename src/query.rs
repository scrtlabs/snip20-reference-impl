use cosmwasm_std::{to_binary, Addr, Binary, CanonicalAddr, Deps, Env, StdError, StdResult, Storage, Uint128, Uint64};
use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};
use secret_toolkit::notification::{get_seed, notification_id, BloomParameters, ChannelInfoData, Descriptor, DirectChannel, FlatDescriptor, GroupChannel, StructDescriptor};
use secret_toolkit::permit::{RevokedPermits, RevokedPermitsStore};

use crate::{btbe::{find_start_bundle, stored_balance, stored_entry, stored_tx_count}, dwb::{DWB, TX_NODES}, msg::{AllowanceGivenResult, AllowanceReceivedResult, QueryAnswer}, notifications::{AllowanceNotification, MultiRecvdNotification, MultiSpentNotification, RecvdNotification, SpentNotification}, state::{AllowancesStore, MintersStore, CHANNELS, CONFIG, CONTRACT_STATUS, INTERNAL_SECRET_RELAXED, INTERNAL_SECRET_SENSITIVE, TOTAL_SUPPLY}, transaction_history::Tx};

pub fn query_exchange_rate(storage: &dyn Storage) -> StdResult<Binary> {
    let constants = CONFIG.load(storage)?;

    if constants.deposit_is_enabled || constants.redeem_is_enabled {
        let rate: Uint128;
        let denom: String;
        // if token has more decimals than SCRT, you get magnitudes of SCRT per token
        if constants.decimals >= 6 {
            rate = Uint128::new(10u128.pow(constants.decimals as u32 - 6));
            denom = "SCRT".to_string();
        // if token has less decimals, you get magnitudes token for SCRT
        } else {
            rate = Uint128::new(10u128.pow(6 - constants.decimals as u32));
            denom = constants.symbol;
        }
        return to_binary(&QueryAnswer::ExchangeRate { rate, denom });
    }
    to_binary(&QueryAnswer::ExchangeRate {
        rate: Uint128::zero(),
        denom: String::new(),
    })
}

pub fn query_token_info(storage: &dyn Storage) -> StdResult<Binary> {
    let constants = CONFIG.load(storage)?;

    let total_supply = if constants.total_supply_is_public {
        Some(Uint128::new(TOTAL_SUPPLY.load(storage)?))
    } else {
        None
    };

    to_binary(&QueryAnswer::TokenInfo {
        name: constants.name,
        symbol: constants.symbol,
        decimals: constants.decimals,
        total_supply,
    })
}

pub fn query_token_config(storage: &dyn Storage) -> StdResult<Binary> {
    let constants = CONFIG.load(storage)?;

    to_binary(&QueryAnswer::TokenConfig {
        public_total_supply: constants.total_supply_is_public,
        deposit_enabled: constants.deposit_is_enabled,
        redeem_enabled: constants.redeem_is_enabled,
        mint_enabled: constants.mint_is_enabled,
        burn_enabled: constants.burn_is_enabled,
        supported_denoms: constants.supported_denoms,
    })
}

pub fn query_contract_status(storage: &dyn Storage) -> StdResult<Binary> {
    let contract_status = CONTRACT_STATUS.load(storage)?;

    to_binary(&QueryAnswer::ContractStatus {
        status: contract_status,
    })
}

pub fn query_transactions(
    deps: Deps,
    account: String,
    page: u32,
    page_size: u32,
) -> StdResult<Binary> {
    if page_size == 0 {
        return Err(StdError::generic_err("invalid page size"));
    }

    // Notice that if query_transactions() was called by a viewing-key call, the address of
    // 'account' has already been validated.
    // The address of 'account' should not be validated if query_transactions() was called by a
    // permit call, for compatibility with non-Secret addresses.
    let account = Addr::unchecked(account);
    let account_raw = deps.api.addr_canonicalize(account.as_str())?;

    let start = page * page_size;
    let mut end = start + page_size; // one more than end index

    // first check if there are any transactions in dwb
    let dwb = DWB.load(deps.storage)?;
    let dwb_index = dwb.recipient_match(&account_raw);
    let mut txs_in_dwb = vec![];
    let txs_in_dwb_count = dwb.entries[dwb_index].list_len()?;
    if dwb_index > 0 && txs_in_dwb_count > 0 && start < txs_in_dwb_count as u32 {
        // skip if start is after buffer entries
        let head_node_index = dwb.entries[dwb_index].head_node()?;

        // only look if head node is not null
        if head_node_index > 0 {
            let head_node = TX_NODES
                .add_suffix(&head_node_index.to_be_bytes())
                .load(deps.storage)?;
            txs_in_dwb = head_node.to_vec(deps.storage, deps.api)?;
        }
    }

    //let account_slice = account_raw.as_slice();
    let account_stored_entry = stored_entry(deps.storage, &account_raw)?;
    let settled_tx_count = stored_tx_count(deps.storage, &account_stored_entry)?;
    let total = txs_in_dwb_count as u32 + settled_tx_count as u32;
    if end > total {
        end = total;
    }

    let mut txs: Vec<Tx> = vec![];

    let txs_in_dwb_count = txs_in_dwb_count as u32;
    if start < txs_in_dwb_count && end < txs_in_dwb_count {
        // option 1, start and end are both in dwb
        //println!("OPTION 1");
        txs = txs_in_dwb[start as usize..end as usize].to_vec(); // reverse chronological
    } else if start < txs_in_dwb_count && end >= txs_in_dwb_count {
        // option 2, start is in dwb and end is in settled txs
        // in this case, we do not need to search for txs, just begin at last bundle and move backwards
        //println!("OPTION 2");
        txs = txs_in_dwb[start as usize..].to_vec(); // reverse chronological
        let mut txs_left = (end - start).saturating_sub(txs.len() as u32);
        if let Some(entry) = account_stored_entry {
            let tx_bundles_idx_len = entry.history_len()?;
            if tx_bundles_idx_len > 0 {
                let mut bundle_idx = tx_bundles_idx_len - 1;
                loop {
                    let tx_bundle = entry.get_tx_bundle_at(deps.storage, bundle_idx.clone())?;

                    // only look if head node is not null
                    if tx_bundle.head_node > 0 {
                        let head_node = TX_NODES
                            .add_suffix(&tx_bundle.head_node.to_be_bytes())
                            .load(deps.storage)?;

                        let list_len = tx_bundle.list_len as u32;
                        if txs_left <= list_len {
                            txs.extend_from_slice(
                                &head_node.to_vec(deps.storage, deps.api)?[0..txs_left as usize],
                            );
                            break;
                        }
                        txs.extend(head_node.to_vec(deps.storage, deps.api)?);
                        txs_left = txs_left.saturating_sub(list_len);
                    }
                    if bundle_idx > 0 {
                        bundle_idx -= 1;
                    } else {
                        break;
                    }
                }
            }
        }
    } else if start >= txs_in_dwb_count {
        // option 3, start is not in dwb
        // in this case, search for where the beginning bundle is using binary search

        // bundle tx offsets are chronological, but we need reverse chronological
        // so get the settled start index as if order is reversed
        //println!("OPTION 3");
        let settled_start = settled_tx_count
            .saturating_sub(start - txs_in_dwb_count)
            .saturating_sub(1);

        if let Some((bundle_idx, tx_bundle, start_at)) =
            find_start_bundle(deps.storage, &account_raw, settled_start)?
        {
            let mut txs_left = end - start;
            let list_len = tx_bundle.list_len as u32;
            if start_at + txs_left <= list_len {
                // only look if head node is not null
                if tx_bundle.head_node > 0 {
                    let head_node = TX_NODES
                        .add_suffix(&tx_bundle.head_node.to_be_bytes())
                        .load(deps.storage)?;
                    // this first bundle has all the txs we need
                    txs = head_node.to_vec(deps.storage, deps.api)?
                        [start_at as usize..(start_at + txs_left) as usize]
                        .to_vec();
                }
            } else {
                // only look if head node is not null
                if tx_bundle.head_node > 0 {
                    let head_node = TX_NODES
                        .add_suffix(&tx_bundle.head_node.to_be_bytes())
                        .load(deps.storage)?;
                    // get the rest of the txs in this bundle and then go back through history
                    txs = head_node.to_vec(deps.storage, deps.api)?[start_at as usize..].to_vec();
                    txs_left = txs_left.saturating_sub(list_len - start_at);
                }

                if bundle_idx > 0 && txs_left > 0 {
                    // get the next earlier bundle
                    let mut bundle_idx = bundle_idx - 1;
                    if let Some(entry) = account_stored_entry {
                        loop {
                            let tx_bundle =
                                entry.get_tx_bundle_at(deps.storage, bundle_idx.clone())?;
                            // only look if head node is not null
                            if tx_bundle.head_node > 0 {
                                let head_node = TX_NODES
                                    .add_suffix(&tx_bundle.head_node.to_be_bytes())
                                    .load(deps.storage)?;
                                let list_len = tx_bundle.list_len as u32;
                                if txs_left <= list_len {
                                    txs.extend_from_slice(
                                        &head_node.to_vec(deps.storage, deps.api)?
                                            [0..txs_left as usize],
                                    );
                                    break;
                                }
                                txs.extend(head_node.to_vec(deps.storage, deps.api)?);
                                txs_left = txs_left.saturating_sub(list_len);
                            }
                            if bundle_idx > 0 {
                                bundle_idx -= 1;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // deterministically obfuscate ids so they are not serial to prevent metadata leak
    let internal_secret = INTERNAL_SECRET_RELAXED.load(deps.storage)?;
    let internal_secret_u64: u64 = u64::from_be_bytes(internal_secret[..8].try_into().unwrap());
    let txs = txs
        .iter()
        .map(|tx| {
            // PRNG(PRNG(serial_id) ^ secret)
            let mut rng = ChaChaRng::seed_from_u64(tx.id);
            let serial_id_rand = rng.next_u64();
            let new_seed = serial_id_rand ^ internal_secret_u64;
            let mut rng = ChaChaRng::seed_from_u64(new_seed);
            let new_id = rng.next_u64() >> (64 - 53);
            Tx {
                id: new_id,
                action: tx.action.clone(),
                coins: tx.coins.clone(),
                memo: tx.memo.clone(),
                block_height: tx.block_height,
                block_time: tx.block_time,
            }
        })
        .collect();

    let result = QueryAnswer::TransactionHistory {
        txs,
        total: Some(total as u64),
    };
    to_binary(&result)
}

pub fn query_balance(deps: Deps, account: String) -> StdResult<Binary> {
    // Notice that if query_balance() was called by a viewing key call, the address of 'account'
    // has already been validated.
    // The address of 'account' should not be validated if query_balance() was called by a permit
    // call, for compatibility with non-Secret addresses.
    let account = Addr::unchecked(account);
    let account = deps.api.addr_canonicalize(account.as_str())?;

    let mut amount = stored_balance(deps.storage, &account)?;
    let dwb = DWB.load(deps.storage)?;
    let dwb_index = dwb.recipient_match(&account);
    if dwb_index > 0 {
        amount = amount.saturating_add(dwb.entries[dwb_index].amount()? as u128);
    }
    let amount = Uint128::new(amount);
    let response = QueryAnswer::Balance { amount };
    to_binary(&response)
}

pub fn query_minters(deps: Deps) -> StdResult<Binary> {
    let minters = MintersStore::load(deps.storage)?;

    let response = QueryAnswer::Minters { minters };
    to_binary(&response)
}

pub fn query_allowance(deps: Deps, owner: String, spender: String) -> StdResult<Binary> {
    // Notice that if query_allowance() was called by a viewing-key call, the addresses of 'owner'
    // and 'spender' have already been validated.
    // The addresses of 'owner' and 'spender' should not be validated if query_allowance() was
    // called by a permit call, for compatibility with non-Secret addresses.
    let owner = Addr::unchecked(owner);
    let spender = Addr::unchecked(spender);

    let allowance = AllowancesStore::load(deps.storage, &owner, &spender);

    let response = QueryAnswer::Allowance {
        owner,
        spender,
        allowance: Uint128::new(allowance.amount),
        expiration: allowance.expiration,
    };
    to_binary(&response)
}

pub fn query_allowances_given(
    deps: Deps,
    owner: String,
    page: u32,
    page_size: u32,
) -> StdResult<Binary> {
    // Notice that if query_all_allowances_given() was called by a viewing-key call,
    // the address of 'owner' has already been validated.
    // The addresses of 'owner' should not be validated if query_all_allowances_given() was
    // called by a permit call, for compatibility with non-Secret addresses.
    let owner = Addr::unchecked(owner);

    let all_allowances =
        AllowancesStore::all_allowances(deps.storage, &owner, page, page_size).unwrap_or(vec![]);

    let allowances_result = all_allowances
        .into_iter()
        .map(|(spender, allowance)| AllowanceGivenResult {
            spender,
            allowance: Uint128::from(allowance.amount),
            expiration: allowance.expiration,
        })
        .collect();

    let response = QueryAnswer::AllowancesGiven {
        owner: owner.clone(),
        allowances: allowances_result,
        count: AllowancesStore::num_allowances(deps.storage, &owner),
    };
    to_binary(&response)
}

pub fn query_allowances_received(
    deps: Deps,
    spender: String,
    page: u32,
    page_size: u32,
) -> StdResult<Binary> {
    // Notice that if query_all_allowances_received() was called by a viewing-key call,
    // the address of 'spender' has already been validated.
    // The addresses of 'spender' should not be validated if query_all_allowances_received() was
    // called by a permit call, for compatibility with non-Secret addresses.
    let spender = Addr::unchecked(spender);

    let all_allowed =
        AllowancesStore::all_allowed(deps.storage, &spender, page, page_size).unwrap_or(vec![]);

    let allowances = all_allowed
        .into_iter()
        .map(|(owner, allowance)| AllowanceReceivedResult {
            owner,
            allowance: Uint128::from(allowance.amount),
            expiration: allowance.expiration,
        })
        .collect();

    let response = QueryAnswer::AllowancesReceived {
        spender: spender.clone(),
        allowances,
        count: AllowancesStore::num_allowed(deps.storage, &spender),
    };
    to_binary(&response)
}

// *****************
// SNIP-24.1 query function
// *****************

pub fn query_list_permit_revocations(deps: Deps, account: &str) -> StdResult<Binary> {
    let revocations = RevokedPermits::list_revocations(
        deps.storage, 
        account
    )?;

    to_binary(&QueryAnswer::ListPermitRevocations { revocations })
}

// *****************
// SNIP-52 query functions
// *****************

///
/// ListChannels query
///
///   Public query to list all notification channels.
///
pub fn query_list_channels(deps: Deps) -> StdResult<Binary> {
    let channels: Vec<String> = CHANNELS
        .iter(deps.storage)?
        .map(|channel| channel.unwrap())
        .collect();
    to_binary(&QueryAnswer::ListChannels { channels })
}

///
/// ChannelInfo query
///
///   Authenticated query allows clients to obtain the seed,
///   and Notification ID of an event for a specific tx_hash, for a specific channel.
///
pub fn query_channel_info(
    deps: Deps,
    env: Env,
    channels: Vec<String>,
    txhash: Option<String>,
    sender_raw: CanonicalAddr,
) -> StdResult<Binary> {
    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();
    let seed = get_seed(&sender_raw, secret)?;
    let mut channels_data = vec![];
    for channel in channels {
        let answer_id;
        if let Some(tx_hash) = &txhash {
            answer_id = Some(notification_id(&seed, &channel, tx_hash)?);
        } else {
            answer_id = None;
        }
        match channel.as_str() {
            RecvdNotification::CHANNEL_ID => {
                let channel_info_data = ChannelInfoData {
                    mode: "txhash".to_string(),
                    channel,
                    answer_id,
                    parameters: None,
                    data: None,
                    next_id: None,
                    counter: None,
                    cddl: Some(RecvdNotification::CDDL_SCHEMA.to_string()),
                };
                channels_data.push(channel_info_data);
            }
            SpentNotification::CHANNEL_ID => {
                let channel_info_data = ChannelInfoData {
                    mode: "txhash".to_string(),
                    channel,
                    answer_id,
                    parameters: None,
                    data: None,
                    next_id: None,
                    counter: None,
                    cddl: Some(SpentNotification::CDDL_SCHEMA.to_string()),
                };
                channels_data.push(channel_info_data);
            }
            AllowanceNotification::CHANNEL_ID => {
                let channel_info_data = ChannelInfoData {
                    mode: "txhash".to_string(),
                    channel,
                    answer_id,
                    parameters: None,
                    data: None,
                    next_id: None,
                    counter: None,
                    cddl: Some(AllowanceNotification::CDDL_SCHEMA.to_string()),
                };
                channels_data.push(channel_info_data);
            }
            MultiRecvdNotification::CHANNEL_ID => {
                let channel_info_data = ChannelInfoData {
                    mode: "bloom".to_string(),
                    channel,
                    answer_id,
                    parameters: Some(BloomParameters {
                        m: MultiRecvdNotification::BLOOM_M,
                        k: MultiRecvdNotification::BLOOM_K,
                        h: "sha256".to_string(),
                    }),
                    data: Some(Descriptor {
                        r#type: format!("packet[{}]", MultiRecvdNotification::BLOOM_N),
                        version: "1".to_string(),
                        packet_size: MultiRecvdNotification::PACKET_SIZE as u32,
                        data: StructDescriptor {
                            r#type: "struct".to_string(),
                            label: "transfer".to_string(),
                            members: vec![
                                FlatDescriptor {
                                    r#type: "uint64".to_string(),
                                    label: "flagsAndAmount".to_string(),
                                    description: Some(
                                        "Bit field of [0]: non-empty memo; [2]: sender is owner; [2..]: uint62 transfer amount in base denomination".to_string(),
                                    ),
                                },
                                FlatDescriptor {
                                    r#type: "bytes8".to_string(),
                                    label: "ownerId".to_string(),
                                    description: Some(
                                        "The last 8 bytes of the owner's canonical address".to_string(),
                                    ),
                                },
                            ],
                        },
                    }),
                    counter: None,
                    next_id: None,
                    cddl: None,
                };
                channels_data.push(channel_info_data);
            }
            MultiSpentNotification::CHANNEL_ID => {
                let channel_info_data = ChannelInfoData {
                    mode: "bloom".to_string(),
                    channel,
                    answer_id,
                    parameters: Some(BloomParameters {
                        m: MultiSpentNotification::BLOOM_M,
                        k: MultiSpentNotification::BLOOM_K,
                        h: "sha256".to_string(),
                    }),
                    data: Some(Descriptor {
                        r#type: format!("packet[{}]", MultiSpentNotification::BLOOM_N),
                        version: "1".to_string(),
                        packet_size: MultiSpentNotification::PACKET_SIZE as u32,
                        data: StructDescriptor {
                            r#type: "struct".to_string(),
                            label: "transfer".to_string(),
                            members: vec![
                                FlatDescriptor {
                                    r#type: "uint64".to_string(),
                                    label: "flagsAndAmount".to_string(),
                                    description: Some(
                                        "Bit field of [0]: non-empty memo; [1]: reserved; [2..] uint62 transfer amount in base denomination".to_string(),
                                    ),
                                },
                                FlatDescriptor {
                                    r#type: "bytes8".to_string(),
                                    label: "recipientId".to_string(),
                                    description: Some(
                                        "The last 8 bytes of the recipient's canonical address".to_string(),
                                    ),
                                },
                                FlatDescriptor {
                                    r#type: "uint64".to_string(),
                                    label: "balance".to_string(),
                                    description: Some(
                                        "Spender's new balance after the transfer".to_string(),
                                    ),
                                },
                            ],
                        },
                    }),
                    counter: None,
                    next_id: None,
                    cddl: None,
                };
                channels_data.push(channel_info_data);
            }
            _ => {
                return Err(StdError::generic_err(format!(
                    "`{}` channel is undefined",
                    channel
                )));
            }
        }
    }

    to_binary(&QueryAnswer::ChannelInfo {
        as_of_block: Uint64::from(env.block.height),
        channels: channels_data,
        seed,
    })
}

// *****************
// End SNIP-52 query functions
// *****************
