/// This contract implements SNIP-20 standard:
/// https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md
use cosmwasm_std::{
    entry_point, to_binary, Binary, 
    Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, 
};
#[cfg(feature = "gas_evaporation")]
use cosmwasm_std::Api;
use secret_toolkit::notification::{GroupChannel, DirectChannel,};
use secret_toolkit::permit::{Permit, TokenPermissions};
use secret_toolkit::utils::{pad_handle_result, pad_query_result};
use secret_toolkit::viewing_key::{ViewingKey, ViewingKeyStore};
use secret_toolkit_crypto::{hkdf_sha_256, sha_256, ContractPrng};

use crate::{execute, execute_admin, execute_deposit_redeem, execute_mint_burn, execute_transfer_send, query};

#[cfg(feature = "gas_tracking")]
use crate::dwb::log_dwb;
use crate::dwb::{DelayedWriteBuffer, DWB};

use crate::btbe::initialize_btbe;

#[cfg(feature = "gas_tracking")]
use crate::gas_tracker::{GasTracker, LoggingExt};
#[cfg(feature = "gas_evaporation")]
use crate::msg::Evaporator;
use crate::msg::{
    ContractStatusLevel, ExecuteMsg, InstantiateMsg, QueryAnswer, QueryMsg, QueryWithPermit,
};
use crate::notifications::{
    AllowanceNotification, MultiRecvdNotification, MultiSpentNotification, RecvdNotification, SpentNotification
};
use crate::state::{
    Config, MintersStore, CHANNELS, CONFIG, CONTRACT_STATUS, INTERNAL_SECRET_RELAXED, INTERNAL_SECRET_SENSITIVE, NOTIFICATIONS_ENABLED, 
    TOTAL_SUPPLY,
};
use crate::strings::TRANSFER_HISTORY_UNSUPPORTED_MSG;

/// We make sure that responses from `handle` are padded to a multiple of this size.
pub const RESPONSE_BLOCK_SIZE: usize = 256;
pub const NOTIFICATION_BLOCK_SIZE: usize = 1;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // Check name, symbol, decimals
    if !is_valid_name(&msg.name) {
        return Err(StdError::generic_err(
            "Name is not in the expected format (3-30 UTF-8 bytes)",
        ));
    }
    if !is_valid_symbol(&msg.symbol) {
        return Err(StdError::generic_err(
            "Ticker symbol is not in expected format [A-Z]{3,20}",
        ));
    }
    if msg.decimals > 18 {
        return Err(StdError::generic_err("Decimals must not exceed 18"));
    }

    let init_config = msg.config.unwrap_or_default();

    let admin = match msg.admin {
        Some(admin_addr) => deps.api.addr_validate(admin_addr.as_str())?,
        None => info.sender.clone(),
    };

    let mut total_supply: u128 = 0;

    // initialize the bitwise-trie of bucketed entries
    initialize_btbe(deps.storage)?;

    // initialize the delay write buffer
    DWB.save(deps.storage, &DelayedWriteBuffer::new()?)?;

    let initial_balances = msg.initial_balances.unwrap_or_default();
    let raw_admin = deps.api.addr_canonicalize(admin.as_str())?;
    let rng_seed = env.block.random.as_ref().unwrap();

    // use entropy and env.random to create an internal secret for the contract
    let entropy = msg.prng_seed.0.as_slice();
    let entropy_len = 16 + info.sender.to_string().len() + entropy.len();
    let mut rng_entropy = Vec::with_capacity(entropy_len);
    rng_entropy.extend_from_slice(&env.block.height.to_be_bytes());
    rng_entropy.extend_from_slice(&env.block.time.seconds().to_be_bytes());
    rng_entropy.extend_from_slice(info.sender.as_bytes());
    rng_entropy.extend_from_slice(entropy);

    // create internal secrets
    let salt = Some(sha_256(&rng_entropy).to_vec());
    let internal_secret_sensitive = hkdf_sha_256(
        &salt,
        rng_seed.0.as_slice(),
        "contract_internal_secret_sensitive".as_bytes(),
        32,
    )?;
    INTERNAL_SECRET_SENSITIVE.save(deps.storage, &internal_secret_sensitive)?;

    let internal_secret_relaxed = hkdf_sha_256(
        &salt,
        rng_seed.0.as_slice(),
        "contract_internal_secret_relaxed".as_bytes(),
        32,
    )?;
    INTERNAL_SECRET_RELAXED.save(deps.storage, &internal_secret_relaxed)?;

    // Hard-coded channels
    let channels: Vec<String> = vec![
        RecvdNotification::CHANNEL_ID.to_string(),
        SpentNotification::CHANNEL_ID.to_string(),
        AllowanceNotification::CHANNEL_ID.to_string(),
        MultiRecvdNotification::CHANNEL_ID.to_string(),
        MultiSpentNotification::CHANNEL_ID.to_string(),
    ];

    for channel in channels {
        CHANNELS.insert(deps.storage, &channel)?;
    }

    NOTIFICATIONS_ENABLED.save(deps.storage, &true)?;

    let mut rng = ContractPrng::new(rng_seed.as_slice(), &sha_256(&msg.prng_seed.0));
    for balance in initial_balances {
        let amount = balance.amount.u128();
        let balance_address = deps.api.addr_canonicalize(balance.address.as_str())?;
        #[cfg(feature = "gas_tracking")]
        let mut tracker = GasTracker::new(deps.api);
        execute_mint_burn::perform_mint(
            deps.storage,
            &mut rng,
            &raw_admin,
            &balance_address,
            amount,
            msg.symbol.clone(),
            Some("Initial Balance".to_string()),
            &env.block,
            #[cfg(feature = "gas_tracking")]
            &mut tracker,
        )?;

        if let Some(new_total_supply) = total_supply.checked_add(amount) {
            total_supply = new_total_supply;
        } else {
            return Err(StdError::generic_err(
                "The sum of all initial balances exceeds the maximum possible total supply",
            ));
        }
    }

    let supported_denoms = match msg.supported_denoms {
        None => vec![],
        Some(x) => x,
    };

    CONFIG.save(
        deps.storage,
        &Config {
            name: msg.name,
            symbol: msg.symbol,
            decimals: msg.decimals,
            admin: admin.clone(),
            total_supply_is_public: init_config.public_total_supply(),
            deposit_is_enabled: init_config.deposit_enabled(),
            redeem_is_enabled: init_config.redeem_enabled(),
            mint_is_enabled: init_config.mint_enabled(),
            burn_is_enabled: init_config.burn_enabled(),
            contract_address: env.contract.address,
            supported_denoms,
            can_modify_denoms: init_config.can_modify_denoms(),
        },
    )?;
    TOTAL_SUPPLY.save(deps.storage, &total_supply)?;
    CONTRACT_STATUS.save(deps.storage, &ContractStatusLevel::NormalRun)?;
    let minters = if init_config.mint_enabled() {
        Vec::from([admin])
    } else {
        Vec::new()
    };
    MintersStore::save(deps.storage, minters)?;

    let vk_seed = hkdf_sha_256(
        &salt,
        rng_seed.0.as_slice(),
        "contract_viewing_key".as_bytes(),
        32,
    )?;
    ViewingKey::set_seed(deps.storage, &vk_seed);

    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let mut rng = ContractPrng::from_env(&env);

    let contract_status = CONTRACT_STATUS.load(deps.storage)?;

    #[cfg(feature = "gas_evaporation")]
    let api = deps.api;
    match contract_status {
        ContractStatusLevel::StopAll | ContractStatusLevel::StopAllButRedeems => {
            let response = match msg {
                ExecuteMsg::SetContractStatus { level, .. } => {
                    // load contract config from storage
                    let config = CONFIG.load(deps.storage)?;

                    // check that message sender is the admin
                    if config.admin != info.sender {
                        return Err(StdError::generic_err(
                            "This is an admin command. Admin commands can only be run from admin address",
                        ));
                    }

                    execute_admin::set_contract_status(deps, level)
                }
                ExecuteMsg::Redeem { amount, denom, .. }
                    if contract_status == ContractStatusLevel::StopAllButRedeems =>
                {
                    execute_deposit_redeem::try_redeem(deps, env, info, amount, denom)
                }
                _ => Err(StdError::generic_err(
                    "This contract is stopped and this action is not allowed",
                )),
            };
            return pad_handle_result(response, RESPONSE_BLOCK_SIZE);
        }
        ContractStatusLevel::NormalRun => {} // If it's a normal run just continue
    }

    let response = match msg.clone() {
        // Native
        ExecuteMsg::Deposit { .. } => execute_deposit_redeem::try_deposit(deps, env, info, &mut rng),
        ExecuteMsg::Redeem { amount, denom, .. } => execute_deposit_redeem::try_redeem(deps, env, info, amount, denom),

        // Base
        ExecuteMsg::Transfer {
            recipient,
            amount,
            memo,
            ..
        } => execute_transfer_send::try_transfer(deps, env, info, &mut rng, recipient, amount, memo),
        ExecuteMsg::Send {
            recipient,
            recipient_code_hash,
            amount,
            msg,
            memo,
            ..
        } => execute_transfer_send::try_send(
            deps,
            env,
            info,
            &mut rng,
            recipient,
            recipient_code_hash,
            amount,
            memo,
            msg,
        ),
        ExecuteMsg::BatchTransfer { actions, .. } => {
            execute_transfer_send::try_batch_transfer(deps, env, info, &mut rng, actions)
        }
        ExecuteMsg::BatchSend { actions, .. } => execute_transfer_send::try_batch_send(deps, env, info, &mut rng, actions),
        ExecuteMsg::Burn { amount, memo, .. } => execute_mint_burn::try_burn(deps, env, info, amount, memo),
        ExecuteMsg::RegisterReceive { code_hash, .. } => {
            execute::try_register_receive(deps, info, code_hash)
        }
        ExecuteMsg::CreateViewingKey { entropy, .. } => execute::try_create_key(deps, env, info, entropy, &mut rng),
        ExecuteMsg::SetViewingKey { key, .. } => execute::try_set_key(deps, info, key),

        // Allowance
        ExecuteMsg::IncreaseAllowance {
            spender,
            amount,
            expiration,
            ..
        } => execute::try_increase_allowance(deps, env, info, spender, amount, expiration),
        ExecuteMsg::DecreaseAllowance {
            spender,
            amount,
            expiration,
            ..
        } => execute::try_decrease_allowance(deps, env, info, spender, amount, expiration),
        ExecuteMsg::TransferFrom {
            owner,
            recipient,
            amount,
            memo,
            ..
        } => execute_transfer_send::try_transfer_from(deps, &env, info, &mut rng, owner, recipient, amount, memo),
        ExecuteMsg::SendFrom {
            owner,
            recipient,
            recipient_code_hash,
            amount,
            msg,
            memo,
            ..
        } => execute_transfer_send::try_send_from(
            deps,
            env,
            &info,
            &mut rng,
            owner,
            recipient,
            recipient_code_hash,
            amount,
            memo,
            msg,
        ),
        ExecuteMsg::BatchTransferFrom { actions, .. } => {
            execute_transfer_send::try_batch_transfer_from(deps, &env, info, &mut rng, actions)
        }
        ExecuteMsg::BatchSendFrom { actions, .. } => {
            execute_transfer_send::try_batch_send_from(deps, env, &info, &mut rng, actions)
        }
        ExecuteMsg::BurnFrom {
            owner,
            amount,
            memo,
            ..
        } => execute_mint_burn::try_burn_from(deps, &env, info, owner, amount, memo),
        ExecuteMsg::BatchBurnFrom { actions, .. } => execute_mint_burn::try_batch_burn_from(deps, &env, info, actions),

        // Mint
        ExecuteMsg::Mint {
            recipient,
            amount,
            memo,
            ..
        } => execute_mint_burn::try_mint(deps, env, info, &mut rng, recipient, amount, memo),
        ExecuteMsg::BatchMint { actions, .. } => execute_mint_burn::try_batch_mint(deps, env, info, &mut rng, actions),

        // SNIP-24
        ExecuteMsg::RevokePermit { permit_name, .. } => execute::revoke_permit(deps, info, permit_name),

        // SNIP-24.1
        ExecuteMsg::RevokeAllPermits { interval, .. } => execute::revoke_all_permits(deps, info, interval),
        ExecuteMsg::DeletePermitRevocation { revocation_id, .. } => execute::delete_permit_revocation(deps, info, revocation_id),

        // Admin functions
        _ => admin_execute(deps, info, msg)
    };

    let padded_result = pad_handle_result(response, RESPONSE_BLOCK_SIZE);

    #[cfg(feature = "gas_evaporation")]
    let evaporated = msg.evaporate_to_target(api)?;

    padded_result
}

pub fn admin_execute(deps: DepsMut, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    // load contract config from storage
    let mut config = CONFIG.load(deps.storage)?;

    // check that message sender is the admin
    if config.admin != info.sender {
        return Err(StdError::generic_err(
            "This is an admin command. Admin commands can only be run from admin address",
        ));
    }

    match msg {
        ExecuteMsg::ChangeAdmin { address, .. } => execute_admin::change_admin(deps, &mut config, address),
        ExecuteMsg::SetContractStatus { level, .. } => execute_admin::set_contract_status(deps, level),
        ExecuteMsg::AddMinters { minters, .. } => execute_admin::add_minters(deps, &config, minters),
        ExecuteMsg::RemoveMinters { minters, .. } => execute_admin::remove_minters(deps, &config, minters),
        ExecuteMsg::SetMinters { minters, .. } => execute_admin::set_minters(deps, &config, minters),
        ExecuteMsg::AddSupportedDenoms { denoms, .. } => execute_admin::add_supported_denoms(deps, &mut config, denoms),
        ExecuteMsg::RemoveSupportedDenoms { denoms, .. } => {
            execute_admin::remove_supported_denoms(deps, &mut config, denoms)
        },

        // SNIP-52
        ExecuteMsg::SetNotificationStatus { enabled, .. } => {
            execute_admin::set_notification_status(deps, enabled)
        },
        _ => panic!("This execute type is not an admin function"),
    }
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    pad_query_result(
        match msg {
            QueryMsg::TokenInfo {} => query::query_token_info(deps.storage),
            QueryMsg::TokenConfig {} => query::query_token_config(deps.storage),
            QueryMsg::ContractStatus {} => query::query_contract_status(deps.storage),
            QueryMsg::ExchangeRate {} => query::query_exchange_rate(deps.storage),
            QueryMsg::Minters { .. } => query::query_minters(deps),
            QueryMsg::ListChannels {} => query::query_list_channels(deps),
            QueryMsg::WithPermit { permit, query } => permit_queries(deps, env, permit, query),

            #[cfg(feature = "gas_tracking")]
            QueryMsg::Dwb {} => log_dwb(deps.storage),

            _ => viewing_keys_queries(deps, env, msg),
        },
        RESPONSE_BLOCK_SIZE,
    )
}

fn permit_queries(deps: Deps, env: Env, permit: Permit, query: QueryWithPermit) -> Result<Binary, StdError> {
    // Validate permit content
    let token_address = CONFIG.load(deps.storage)?.contract_address;

    let account = secret_toolkit::permit::validate(
        deps,
        &env,
        &permit,
        token_address.into_string(),
        None,
    )?;

    // Permit validated! We can now execute the query.
    match query {
        QueryWithPermit::Balance {} => {
            if !permit.check_permission(&TokenPermissions::Balance) {
                return Err(StdError::generic_err(format!(
                    "No permission to query balance, got permissions {:?}",
                    permit.params.permissions
                )));
            }

            query::query_balance(deps, account)
        }
        QueryWithPermit::TransferHistory { .. } => {
            return Err(StdError::generic_err(TRANSFER_HISTORY_UNSUPPORTED_MSG));
        }
        QueryWithPermit::TransactionHistory { page, page_size } => {
            if !permit.check_permission(&TokenPermissions::History) {
                return Err(StdError::generic_err(format!(
                    "No permission to query history, got permissions {:?}",
                    permit.params.permissions
                )));
            }

            query::query_transactions(deps, account, page.unwrap_or(0), page_size)
        }
        QueryWithPermit::Allowance { owner, spender } => {
            if !permit.check_permission(&TokenPermissions::Allowance) {
                return Err(StdError::generic_err(format!(
                    "No permission to query allowance, got permissions {:?}",
                    permit.params.permissions
                )));
            }

            if account != owner && account != spender {
                return Err(StdError::generic_err(format!(
                    "Cannot query allowance. Requires permit for either owner {:?} or spender {:?}, got permit for {:?}",
                    owner.as_str(), spender.as_str(), account.as_str()
                )));
            }

            query::query_allowance(deps, owner, spender)
        }
        QueryWithPermit::AllowancesGiven {
            owner,
            page,
            page_size,
        } => {
            if account != owner {
                return Err(StdError::generic_err(
                    "Cannot query allowance. Requires permit for owner",
                ));
            }

            // we really should add a check_permission(s) function.. an owner permit should
            // just give you permissions to do everything
            if !permit.check_permission(&TokenPermissions::Allowance)
                && !permit.check_permission(&TokenPermissions::Owner)
            {
                return Err(StdError::generic_err(format!(
                    "No permission to query all allowances, got permissions {:?}",
                    permit.params.permissions
                )));
            }
            query::query_allowances_given(deps, account, page.unwrap_or(0), page_size)
        }
        QueryWithPermit::AllowancesReceived {
            spender,
            page,
            page_size,
        } => {
            if account != spender {
                return Err(StdError::generic_err(
                    "Cannot query allowance. Requires permit for spender",
                ));
            }

            if !permit.check_permission(&TokenPermissions::Allowance)
                && !permit.check_permission(&TokenPermissions::Owner)
            {
                return Err(StdError::generic_err(format!(
                    "No permission to query all allowed, got permissions {:?}",
                    permit.params.permissions
                )));
            }
            query::query_allowances_received(deps, account, page.unwrap_or(0), page_size)
        }
        QueryWithPermit::ChannelInfo { channels, txhash } => query::query_channel_info(
            deps,
            env,
            channels,
            txhash,
            deps.api.addr_canonicalize(account.as_str())?,
        ),
        QueryWithPermit::ListPermitRevocations { .. } => {
            if !permit.check_permission(&TokenPermissions::Owner) {
                return Err(StdError::generic_err(format!(
                    "No permission to query list permit revocations, got permissions {:?}",
                    permit.params.permissions
                )));
            } 
            query::query_list_permit_revocations(deps, account.as_str()) 
        },
    }
}

pub fn viewing_keys_queries(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let (addresses, key) = msg.get_validation_params(deps.api)?;

    for address in addresses {
        let result = ViewingKey::check(deps.storage, address.as_str(), key.as_str());
        if result.is_ok() {
            return match msg {
                // Base
                QueryMsg::Balance { address, .. } => query::query_balance(deps, address),
                QueryMsg::TransferHistory { .. } => {
                    return Err(StdError::generic_err(TRANSFER_HISTORY_UNSUPPORTED_MSG));
                }
                QueryMsg::TransactionHistory {
                    address,
                    page,
                    page_size,
                    ..
                } => query::query_transactions(deps, address, page.unwrap_or(0), page_size),
                QueryMsg::Allowance { owner, spender, .. } => query::query_allowance(deps, owner, spender),
                QueryMsg::AllowancesGiven {
                    owner,
                    page,
                    page_size,
                    ..
                } => query::query_allowances_given(deps, owner, page.unwrap_or(0), page_size),
                QueryMsg::AllowancesReceived {
                    spender,
                    page,
                    page_size,
                    ..
                } => query::query_allowances_received(deps, spender, page.unwrap_or(0), page_size),
                QueryMsg::ChannelInfo {
                    channels,
                    txhash,
                    viewer,
                } => query::query_channel_info(
                    deps,
                    env,
                    channels,
                    txhash,
                    deps.api.addr_canonicalize(viewer.address.as_str())?,
                ),
                QueryMsg::ListPermitRevocations{viewer, .. } => query::query_list_permit_revocations(deps, viewer.address.as_str()),
                _ => panic!("This query type does not require authentication"),
            };
        }
    }

    to_binary(&QueryAnswer::ViewingKeyError {
        msg: "Wrong viewing key for this address or viewing key not set".to_string(),
    })
}

// pub fn migrate(
//     _deps: DepsMut,
//     _env: Env,
//     _msg: MigrateMsg,
// ) -> StdResult<MigrateResponse> {
//     Ok(MigrateResponse::default())
//     Ok(MigrateResponse::default())
// }

// helper functions

fn is_valid_name(name: &str) -> bool {
    let len = name.len();
    (3..=30).contains(&len)
}

fn is_valid_symbol(symbol: &str) -> bool {
    let len = symbol.len();
    let len_is_valid = (3..=20).contains(&len);

    len_is_valid && symbol.bytes().all(|byte| byte.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use std::any::Any;

    use cosmwasm_std::{
        from_binary, testing::*, Addr, Api, BlockInfo, Coin, ContractInfo, CosmosMsg, MessageInfo, OwnedDeps, QueryResponse, ReplyOn, SubMsg, Timestamp, TransactionInfo, Uint128, WasmMsg
    };
    use secret_toolkit::permit::{PermitParams, PermitSignature, PubKey};

    use crate::batch;
    use crate::btbe::stored_balance;
    use crate::dwb::{TX_NODES, TX_NODES_COUNT};
    use crate::msg::{ExecuteAnswer, InitConfig, InitialBalance, ResponseStatus, ResponseStatus::Success};
    use crate::receiver::Snip20ReceiveMsg;
    use crate::state::{AllowancesStore, ReceiverHashStore, TX_COUNT};
    use crate::transaction_history::{Tx, TxAction};

    use super::*;

    pub const VIEWING_KEY_SIZE: usize = 32;

    // Helper functions

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

    fn init_helper_with_config(
        initial_balances: Vec<InitialBalance>,
        enable_deposit: bool,
        enable_redeem: bool,
        enable_mint: bool,
        enable_burn: bool,
        contract_bal: u128,
        supported_denoms: Vec<String>,
    ) -> (
        StdResult<Response>,
        OwnedDeps<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies_with_balance(&[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128::new(contract_bal),
        }]);

        let env = mock_env();
        let info = mock_info("instantiator", &[]);

        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":false,
            \"enable_deposit\":{},
            \"enable_redeem\":{},
            \"enable_mint\":{},
            \"enable_burn\":{}}}",
                enable_deposit, enable_redeem, enable_mint, enable_burn
            )
            .as_bytes(),
        ))
        .unwrap();
        let init_msg = InstantiateMsg {
            name: "sec-sec".to_string(),
            admin: Some("admin".to_string()),
            symbol: "SECSEC".to_string(),
            decimals: 8,
            initial_balances: Some(initial_balances),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
            supported_denoms: Some(supported_denoms),
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

    fn ensure_success(handle_result: Response) -> bool {
        let handle_result: ExecuteAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

        match handle_result {
            ExecuteAnswer::Deposit { status }
            | ExecuteAnswer::Redeem { status }
            | ExecuteAnswer::Transfer { status }
            | ExecuteAnswer::Send { status }
            | ExecuteAnswer::Burn { status }
            | ExecuteAnswer::RegisterReceive { status }
            | ExecuteAnswer::SetViewingKey { status }
            | ExecuteAnswer::TransferFrom { status }
            | ExecuteAnswer::SendFrom { status }
            | ExecuteAnswer::BurnFrom { status }
            | ExecuteAnswer::Mint { status }
            | ExecuteAnswer::ChangeAdmin { status }
            | ExecuteAnswer::SetContractStatus { status }
            | ExecuteAnswer::SetMinters { status }
            | ExecuteAnswer::AddMinters { status }
            | ExecuteAnswer::RemoveMinters { status } => {
                matches!(status, ResponseStatus::Success { .. })
            }
            _ => panic!(
                "HandleAnswer not supported for success extraction: {:?}",
                handle_result
            ),
        }
    }

    /// creates a cosmos_msg sending this struct to the named contract
    pub fn into_cosmos_submsg(
        msg: Snip20ReceiveMsg,
        code_hash: String,
        contract_addr: Addr,
        id: u64,
    ) -> StdResult<SubMsg> {
        let msg = msg.into_binary()?;
        let execute = SubMsg {
            id,
            msg: WasmMsg::Execute {
                contract_addr: contract_addr.into_string(),
                code_hash,
                msg,
                funds: vec![],
            }
            .into(),
            // TODO: Discuss the wanted behavior
            reply_on: match id {
                0 => ReplyOn::Never,
                _ => ReplyOn::Always,
            },
            gas_limit: None,
        };

        Ok(execute)
    }

    // Init tests

    #[test]
    fn test_init_sanity() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "lebron".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert_eq!(init_result.unwrap(), Response::default());

        let constants = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(TOTAL_SUPPLY.load(&deps.storage).unwrap(), 5000);
        assert_eq!(
            CONTRACT_STATUS.load(&deps.storage).unwrap(),
            ContractStatusLevel::NormalRun
        );
        assert_eq!(constants.name, "sec-sec".to_string());
        assert_eq!(constants.admin, Addr::unchecked("admin".to_string()));
        assert_eq!(constants.symbol, "SECSEC".to_string());
        assert_eq!(constants.decimals, 8);
        assert_eq!(constants.total_supply_is_public, false);

        ViewingKey::set(deps.as_mut().storage, "lebron", "lolz fun yay");
        let is_vk_correct = ViewingKey::check(&deps.storage, "lebron", "lolz fun yay");
        assert!(
            is_vk_correct.is_ok(),
            "Viewing key verification failed!: {}",
            is_vk_correct.err().unwrap()
        );
    }

    #[test]
    fn test_init_with_config_sanity() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: "lebron".to_string(),
                amount: Uint128::new(5000),
            }],
            true,
            true,
            true,
            true,
            0,
            vec!["uscrt".to_string()],
        );
        assert_eq!(init_result.unwrap(), Response::default());

        let constants = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(TOTAL_SUPPLY.load(&deps.storage).unwrap(), 5000);
        assert_eq!(
            CONTRACT_STATUS.load(&deps.storage).unwrap(),
            ContractStatusLevel::NormalRun
        );
        assert_eq!(constants.name, "sec-sec".to_string());
        assert_eq!(constants.admin, Addr::unchecked("admin".to_string()));
        assert_eq!(constants.symbol, "SECSEC".to_string());
        assert_eq!(constants.decimals, 8);
        assert_eq!(constants.total_supply_is_public, false);
        assert_eq!(constants.deposit_is_enabled, true);
        assert_eq!(constants.redeem_is_enabled, true);
        assert_eq!(constants.mint_is_enabled, true);
        assert_eq!(constants.burn_is_enabled, true);

        ViewingKey::set(deps.as_mut().storage, "lebron", "lolz fun yay");
        let is_vk_correct = ViewingKey::check(&deps.storage, "lebron", "lolz fun yay");
        assert!(
            is_vk_correct.is_ok(),
            "Viewing key verification failed!: {}",
            is_vk_correct.err().unwrap()
        );
    }

    #[test]
    fn test_total_supply_overflow_dwb() {
        // with this implementation of dwbs the max amount a user can get transferred or minted is u64::MAX
        // for 18 digit coins, u128 amounts might be stored in the dwb (see `fn add_amount` in dwb.rs)
        let (init_result, _deps) = init_helper(vec![InitialBalance {
            address: "lebron".to_string(),
            amount: Uint128::new(u64::max_value().into()),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
    }

    // Handle tests

    #[test]
    fn test_execute_transfer_dwb() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let tx_nodes_count = TX_NODES_COUNT.load(&deps.storage).unwrap_or_default();
        // should be 2 because we minted 5000 to bob at initialization
        assert_eq!(2, tx_nodes_count);
        let tx_count = TX_COUNT.load(&deps.storage).unwrap_or_default();
        assert_eq!(1, tx_count); // due to mint

        let handle_msg = ExecuteMsg::Transfer {
            recipient: "alice".to_string(),
            amount: Uint128::new(1000),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);
        let mut env = mock_env();
        env.block.random = Some(Binary::from(&[0u8; 32]));
        let handle_result = execute(deps.as_mut(), env, info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let bob_addr = deps
            .api
            .addr_canonicalize(Addr::unchecked("bob").as_str())
            .unwrap();
        let alice_addr = deps
            .api
            .addr_canonicalize(Addr::unchecked("alice").as_str())
            .unwrap();

        assert_eq!(
            5000 - 1000,
            stored_balance(&deps.storage, &bob_addr).unwrap()
        );
        // alice has not been settled yet
        assert_ne!(1000, stored_balance(&deps.storage, &alice_addr).unwrap());

        let dwb = DWB.load(&deps.storage).unwrap();
        println!("DWB: {dwb:?}");
        // assert we have decremented empty_space_counter
        assert_eq!(62, dwb.empty_space_counter);
        // assert first entry has correct information for alice
        let alice_entry = dwb.entries[2];
        assert_eq!(1, alice_entry.list_len().unwrap());
        assert_eq!(1000, alice_entry.amount().unwrap());
        // the id of the head_node
        assert_eq!(4, alice_entry.head_node().unwrap());
        let tx_count = TX_COUNT.load(&deps.storage).unwrap_or_default();
        assert_eq!(2, tx_count);

        // now send 100 to charlie from bob
        let handle_msg = ExecuteMsg::Transfer {
            recipient: "charlie".to_string(),
            amount: Uint128::new(100),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let mut env = mock_env();
        env.block.random = Some(Binary::from(&[1u8; 32]));
        let handle_result = execute(deps.as_mut(), env, info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let charlie_addr = deps
            .api
            .addr_canonicalize(Addr::unchecked("charlie").as_str())
            .unwrap();

        assert_eq!(
            5000 - 1000 - 100,
            stored_balance(&deps.storage, &bob_addr).unwrap()
        );
        // alice has not been settled yet
        assert_ne!(1000, stored_balance(&deps.storage, &alice_addr).unwrap());
        // charlie has not been settled yet
        assert_ne!(100, stored_balance(&deps.storage, &charlie_addr).unwrap());

        let dwb = DWB.load(&deps.storage).unwrap();
        //println!("DWB: {dwb:?}");
        // assert we have decremented empty_space_counter
        assert_eq!(61, dwb.empty_space_counter);
        // assert entry has correct information for charlie
        let charlie_entry = dwb.entries[3];
        assert_eq!(1, charlie_entry.list_len().unwrap());
        assert_eq!(100, charlie_entry.amount().unwrap());
        // the id of the head_node
        assert_eq!(6, charlie_entry.head_node().unwrap());
        let tx_count = TX_COUNT.load(&deps.storage).unwrap_or_default();
        assert_eq!(3, tx_count);

        // send another 500 to alice from bob
        let handle_msg = ExecuteMsg::Transfer {
            recipient: "alice".to_string(),
            amount: Uint128::new(500),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);
        let mut env = mock_env();
        env.block.random = Some(Binary::from(&[2u8; 32]));
        let handle_result = execute(deps.as_mut(), env, info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        assert_eq!(
            5000 - 1000 - 100 - 500,
            stored_balance(&deps.storage, &bob_addr).unwrap()
        );
        // make sure alice has not been settled yet
        assert_ne!(1500, stored_balance(&deps.storage, &alice_addr).unwrap());

        let dwb = DWB.load(&deps.storage).unwrap();
        //println!("DWB: {dwb:?}");
        // assert we have not decremented empty_space_counter
        assert_eq!(61, dwb.empty_space_counter);
        // assert entry has correct information for alice
        let alice_entry = dwb.entries[2];
        assert_eq!(2, alice_entry.list_len().unwrap());
        assert_eq!(1500, alice_entry.amount().unwrap());
        // the id of the head_node
        assert_eq!(8, alice_entry.head_node().unwrap());
        let tx_count = TX_COUNT.load(&deps.storage).unwrap_or_default();
        assert_eq!(4, tx_count);

        // convert head_node to vec
        let alice_nodes = TX_NODES
            .add_suffix(&alice_entry.head_node().unwrap().to_be_bytes())
            .load(&deps.storage)
            .unwrap()
            .to_vec(&deps.storage, &deps.api)
            .unwrap();

        let expected_alice_nodes: Vec<Tx> = vec![
            Tx {
                id: 4,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    amount: Uint128::from(500_u128),
                    denom: "SECSEC".to_string(),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 2,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    amount: Uint128::from(1000_u128),
                    denom: "SECSEC".to_string(),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
        ];
        assert_eq!(alice_nodes, expected_alice_nodes);

        // now send 200 to ernie from bob
        let handle_msg = ExecuteMsg::Transfer {
            recipient: "ernie".to_string(),
            amount: Uint128::new(200),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let mut env = mock_env();
        env.block.random = Some(Binary::from(&[3u8; 32]));
        let handle_result = execute(deps.as_mut(), env, info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let ernie_addr = deps
            .api
            .addr_canonicalize(Addr::unchecked("ernie").as_str())
            .unwrap();

        assert_eq!(
            5000 - 1000 - 100 - 500 - 200,
            stored_balance(&deps.storage, &bob_addr).unwrap()
        );
        // alice has not been settled yet
        assert_ne!(1500, stored_balance(&deps.storage, &alice_addr).unwrap());
        // charlie has not been settled yet
        assert_ne!(100, stored_balance(&deps.storage, &charlie_addr).unwrap());
        // ernie has not been settled yet
        assert_ne!(200, stored_balance(&deps.storage, &ernie_addr).unwrap());

        let dwb = DWB.load(&deps.storage).unwrap();
        //println!("DWB: {dwb:?}");

        // assert we have decremented empty_space_counter
        assert_eq!(60, dwb.empty_space_counter);
        // assert entry has correct information for ernie
        let ernie_entry = dwb.entries[4];
        assert_eq!(1, ernie_entry.list_len().unwrap());
        assert_eq!(200, ernie_entry.amount().unwrap());
        // the id of the head_node
        assert_eq!(10, ernie_entry.head_node().unwrap());
        let tx_count = TX_COUNT.load(&deps.storage).unwrap_or_default();
        assert_eq!(5, tx_count);

        // now alice sends 50 to dora
        // this should settle alice and create entry for dora
        let handle_msg = ExecuteMsg::Transfer {
            recipient: "dora".to_string(),
            amount: Uint128::new(50),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);
        let mut env = mock_env();
        env.block.random = Some(Binary::from(&[4u8; 32]));
        let handle_result = execute(deps.as_mut(), env, info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let dora_addr = deps
            .api
            .addr_canonicalize(Addr::unchecked("dora").as_str())
            .unwrap();

        // alice has been settled
        assert_eq!(
            1500 - 50,
            stored_balance(&deps.storage, &alice_addr).unwrap()
        );
        // dora has not been settled
        assert_ne!(50, stored_balance(&deps.storage, &dora_addr).unwrap());

        let dwb = DWB.load(&deps.storage).unwrap();
        //println!("DWB: {dwb:?}");

        // assert we have decremented empty_space_counter
        assert_eq!(59, dwb.empty_space_counter);
        // assert entry has correct information for ernie
        let dora_entry = dwb.entries[5];
        assert_eq!(1, dora_entry.list_len().unwrap());
        assert_eq!(50, dora_entry.amount().unwrap());
        // the id of the head_node
        assert_eq!(12, dora_entry.head_node().unwrap());
        let tx_count = TX_COUNT.load(&deps.storage).unwrap_or_default();
        assert_eq!(6, tx_count);

        // now we will send to 60 more addresses to fill up the buffer
        for i in 1..=59 {
            let recipient = format!("receipient{i}");
            // now send 1 to recipient from bob
            let handle_msg = ExecuteMsg::Transfer {
                recipient,
                amount: Uint128::new(1),
                memo: None,
                #[cfg(feature = "gas_evaporation")]
                gas_target: None,
                padding: None,
            };
            let info = mock_info("bob", &[]);
            let mut env = mock_env();
            env.block.random = Some(Binary::from(&[255 - i; 32]));
            let handle_result = execute(deps.as_mut(), env, info, handle_msg);

            let result = handle_result.unwrap();
            assert!(ensure_success(result));
        }
        assert_eq!(
            5000 - 1000 - 100 - 500 - 200 - 59,
            stored_balance(&deps.storage, &bob_addr).unwrap()
        );

        let dwb = DWB.load(&deps.storage).unwrap();
        //println!("DWB: {dwb:?}");

        // assert we have filled the buffer
        assert_eq!(0, dwb.empty_space_counter);

        let recipient = format!("receipient_over");
        // now send 1 to recipient from bob
        let handle_msg = ExecuteMsg::Transfer {
            recipient,
            amount: Uint128::new(1),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);
        let mut env = mock_env();
        env.block.random = Some(Binary::from(&[50; 32]));
        let handle_result = execute(deps.as_mut(), env, info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        assert_eq!(
            5000 - 1000 - 100 - 500 - 200 - 59 - 1,
            stored_balance(&deps.storage, &bob_addr).unwrap()
        );

        //let dwb = DWB.load(&deps.storage).unwrap();
        //println!("DWB: {dwb:?}");

        let recipient = format!("receipient_over_2");
        // now send 1 to recipient from bob
        let handle_msg = ExecuteMsg::Transfer {
            recipient,
            amount: Uint128::new(1),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);
        let mut env = mock_env();
        env.block.random = Some(Binary::from(&[12; 32]));
        let handle_result = execute(deps.as_mut(), env, info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        assert_eq!(
            5000 - 1000 - 100 - 500 - 200 - 59 - 1 - 1,
            stored_balance(&deps.storage, &bob_addr).unwrap()
        );

        //let dwb = DWB.load(&deps.storage).unwrap();
        //println!("DWB: {dwb:?}");

        // now we send 50 transactions to alice from bob
        for i in 1..=50 {
            // send 1 to alice from bob
            let handle_msg = ExecuteMsg::Transfer {
                recipient: "alice".to_string(),
                amount: Uint128::new(i.into()),
                memo: None,
                #[cfg(feature = "gas_evaporation")]
                gas_target: None,
                padding: None,
            };

            let info = mock_info("bob", &[]);
            let mut env = mock_env();
            env.block.random = Some(Binary::from(&[125 - i; 32]));
            let handle_result = execute(deps.as_mut(), env, info, handle_msg);

            let result = handle_result.unwrap();
            assert!(ensure_success(result));

            // alice should not settle
            assert_eq!(
                1500 - 50,
                stored_balance(&deps.storage, &alice_addr).unwrap()
            );
        }

        // alice sends 1 to dora to settle
        // this should settle alice and create entry for dora
        let handle_msg = ExecuteMsg::Transfer {
            recipient: "dora".to_string(),
            amount: Uint128::new(1),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);
        let mut env = mock_env();
        env.block.random = Some(Binary::from(&[61; 32]));
        let handle_result = execute(deps.as_mut(), env, info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        assert_eq!(2724, stored_balance(&deps.storage, &alice_addr).unwrap());

        // now we send 50 more transactions to alice from bob
        for i in 1..=50 {
            // send 1 to alice from bob
            let handle_msg = ExecuteMsg::Transfer {
                recipient: "alice".to_string(),
                amount: Uint128::new(i.into()),
                memo: None,
                #[cfg(feature = "gas_evaporation")]
                gas_target: None,
                padding: None,
            };

            let info = mock_info("bob", &[]);
            let mut env = mock_env();
            env.block.random = Some(Binary::from(&[200 - i; 32]));
            let handle_result = execute(deps.as_mut(), env, info, handle_msg);

            let result = handle_result.unwrap();
            assert!(ensure_success(result));

            // alice should not settle
            assert_eq!(2724, stored_balance(&deps.storage, &alice_addr).unwrap());
        }

        let handle_msg = ExecuteMsg::SetViewingKey {
            key: "key".to_string(),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        // check that alice's balance when queried is correct (includes both settled and dwb amounts)
        // settled = 2724
        // dwb = 1275
        // total should be = 3999
        let query_msg = QueryMsg::Balance {
            address: "alice".to_string(),
            key: "key".to_string(),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let balance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Balance { amount } => amount,
            _ => panic!("Unexpected"),
        };
        assert_eq!(balance, Uint128::new(3999));

        // now we use alice to check query transaction history pagination works

        //
        // check last 3 transactions for alice (all in dwb)
        //
        let query_msg = QueryMsg::TransactionHistory {
            address: "alice".to_string(),
            key: "key".to_string(),
            page: None,
            page_size: 3,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransactionHistory { txs, .. } => txs,
            other => panic!("Unexpected: {:?}", other),
        };
        //println!("transfers: {transfers:?}");
        let expected_transfers = vec![
            Tx {
                id: 8845804139732984,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(50u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 3692043167097969,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(49u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 3808363917805648,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(48u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
        ];
        assert_eq!(transfers, expected_transfers);

        //
        // check 6 transactions for alice that span over end of the 50 in dwb and settled
        // page: 8, page size: 6
        // start is index 48
        //
        let query_msg = QueryMsg::TransactionHistory {
            address: "alice".to_string(),
            key: "key".to_string(),
            page: Some(8),
            page_size: 6,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransactionHistory { txs, .. } => txs,
            other => panic!("Unexpected: {:?}", other),
        };
        //println!("transfers: {transfers:?}");
        let expected_transfers = vec![
            Tx {
                id: 7611337451915155,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(2u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 7288023700190802,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(1u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 6449330804541894,
                action: TxAction::Transfer {
                    from: Addr::unchecked("alice"),
                    sender: Addr::unchecked("alice"),
                    recipient: Addr::unchecked("dora"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(1u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 1600285134972748,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(50u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 7899356969158249,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(49u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 5178919937687208,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(48u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
        ];
        assert_eq!(transfers, expected_transfers);

        //
        // check transactions for alice, starting in settled across different bundles with `end` past the last transaction
        // there are 104 transactions total for alice
        // page: 3, page size: 99
        // start is index 99 (100th tx)
        //
        let query_msg = QueryMsg::TransactionHistory {
            address: "alice".to_string(),
            key: "key".to_string(),
            page: Some(3),
            page_size: 33,
            //page: None,
            //page_size: 500,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransactionHistory { txs, .. } => txs,
            other => panic!("Unexpected: {:?}", other),
        };
        //println!("transfers: {transfers:?}");
        let expected_transfers = vec![
            Tx {
                id: 7879504399954008,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(2u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 7625837293820843,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(1u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 2105964828411645,
                action: TxAction::Transfer {
                    from: Addr::unchecked("alice"),
                    sender: Addr::unchecked("alice"),
                    recipient: Addr::unchecked("dora"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(50u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 5298675660782133,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(500u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 3942814133456943,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob"),
                    sender: Addr::unchecked("bob"),
                    recipient: Addr::unchecked("alice"),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::from(1000u128),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
        ];

        //let transfers_len = transfers.len();
        //println!("transfers.len(): {transfers_len}");

        assert_eq!(transfers, expected_transfers);

        // now try invalid transfer
        let handle_msg = ExecuteMsg::Transfer {
            recipient: "alice".to_string(),
            amount: Uint128::new(10000),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient funds"));
    }

    #[test]
    fn test_handle_send() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::RegisterReceive {
            code_hash: "this_is_a_hash_of_a_code".to_string(),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("contract", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let handle_msg = ExecuteMsg::Send {
            recipient: "contract".to_string(),
            recipient_code_hash: None,
            amount: Uint128::new(100),
            memo: Some("my memo".to_string()),
            padding: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            msg: Some(to_binary("hey hey you you").unwrap()),
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result.clone()));
        let id = 0;
        assert!(result.messages.contains(&SubMsg {
            id,
            msg: CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: "contract".to_string(),
                code_hash: "this_is_a_hash_of_a_code".to_string(),
                msg: Snip20ReceiveMsg::new(
                    Addr::unchecked("bob".to_string()),
                    Addr::unchecked("bob".to_string()),
                    Uint128::new(100),
                    Some("my memo".to_string()),
                    Some(to_binary("hey hey you you").unwrap())
                )
                .into_binary()
                .unwrap(),
                funds: vec![],
            })
            .into(),
            reply_on: match id {
                0 => ReplyOn::Never,
                _ => ReplyOn::Always,
            },
            gas_limit: None,
        }));
    }

    #[test]
    fn test_handle_register_receive() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::RegisterReceive {
            code_hash: "this_is_a_hash_of_a_code".to_string(),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("contract", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let hash =
            ReceiverHashStore::may_load(&deps.storage, &Addr::unchecked("contract".to_string()))
                .unwrap()
                .unwrap();
        assert_eq!(hash, "this_is_a_hash_of_a_code".to_string());
    }

    #[test]
    fn test_handle_create_viewing_key() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::CreateViewingKey {
            entropy: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let answer: ExecuteAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();

        let key = match answer {
            ExecuteAnswer::CreateViewingKey { key } => key,
            _ => panic!("NOPE"),
        };
        // let bob_canonical = deps.as_mut().api.addr_canonicalize("bob").unwrap();

        let result = ViewingKey::check(&deps.storage, "bob", key.as_str());
        assert!(result.is_ok());

        // let saved_vk = read_viewing_key(&deps.storage, &bob_canonical).unwrap();
        // assert!(key.check_viewing_key(saved_vk.as_slice()));
    }

    #[test]
    fn test_handle_set_viewing_key() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Set VK
        let handle_msg = ExecuteMsg::SetViewingKey {
            key: "hi lol".to_string(),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let unwrapped_result: ExecuteAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
            .unwrap(),
        );

        // Set valid VK
        let actual_vk = "x".to_string().repeat(VIEWING_KEY_SIZE);
        let handle_msg = ExecuteMsg::SetViewingKey {
            key: actual_vk.clone(),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let unwrapped_result: ExecuteAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::SetViewingKey { status: Success }).unwrap(),
        );

        let result = ViewingKey::check(&deps.storage, "bob", actual_vk.as_str());
        assert!(result.is_ok());
    }

    fn revoke_permit(
        permit_name: &str,
        user_address: &str,
        deps: &mut OwnedDeps<cosmwasm_std::MemoryStorage, MockApi, MockQuerier>,
    ) -> Result<Response, StdError> {
        let handle_msg = ExecuteMsg::RevokePermit {
            permit_name: permit_name.to_string(),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info(user_address, &[]);
        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);
        handle_result
    }

    fn get_balance_with_permit_qry_msg(
        permit_name: &str,
        chain_id: &str,
        pub_key_value: &str,
        signature: &str,
    ) -> QueryMsg {
        let permit = gen_permit_obj(
            permit_name,
            chain_id,
            pub_key_value,
            signature,
            TokenPermissions::Balance,
        );

        QueryMsg::WithPermit {
            permit,
            query: QueryWithPermit::Balance {},
        }
    }

    fn gen_permit_obj(
        permit_name: &str,
        chain_id: &str,
        pub_key_value: &str,
        signature: &str,
        permit_type: TokenPermissions,
    ) -> Permit {
        let permit: Permit = Permit {
            params: PermitParams {
                allowed_tokens: vec![MOCK_CONTRACT_ADDR.to_string()],
                permit_name: permit_name.to_string(),
                chain_id: chain_id.to_string(),
                permissions: vec![permit_type],
                created: None,
                expires: None,
            },
            signature: PermitSignature {
                pub_key: PubKey {
                    r#type: "tendermint/PubKeySecp256k1".to_string(),
                    value: Binary::from_base64(pub_key_value).unwrap(),
                },
                signature: Binary::from_base64(signature).unwrap(),
            },
        };
        permit
    }

    fn get_allowances_given_permit(
        permit_name: &str,
        chain_id: &str,
        pub_key_value: &str,
        signature: &str,
        spender: String,
    ) -> QueryMsg {
        let permit = gen_permit_obj(
            permit_name,
            chain_id,
            pub_key_value,
            signature,
            TokenPermissions::Owner,
        );

        QueryMsg::WithPermit {
            permit,
            query: QueryWithPermit::AllowancesReceived {
                spender,
                page: None,
                page_size: 0,
            },
        }
    }

    #[test]
    fn test_permit_query_allowances_given_should_fail() {
        let user_address = "secret18mdrja40gfuftt5yx6tgj0fn5lurplezyp894y";
        let permit_name = "default";
        let chain_id = "secretdev-1";
        let pub_key = "AkZqxdKMtPq2w0kGDGwWGejTAed0H7azPMHtrCX0XYZG";
        let signature = "ZXyFMlAy6guMG9Gj05rFvcMi5/JGfClRtJpVTHiDtQY3GtSfBHncY70kmYiTXkKIxSxdnh/kS8oXa+GSX5su6Q==";

        // Init the contract
        let (init_result, deps) = init_helper(vec![InitialBalance {
            address: user_address.to_string(),
            amount: Uint128::new(50000000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let msg = get_allowances_given_permit(
            permit_name,
            chain_id,
            pub_key,
            signature,
            "secret1kmgdagt5efcz2kku0ak9ezfgntg29g2vr88q0e".to_string(),
        );
        let query_result = query(deps.as_ref(), mock_env(), msg);

        assert_eq!(query_result.is_err(), true);
    }

    #[test]
    fn test_permit_query_allowances_given() {
        let user_address = "secret18mdrja40gfuftt5yx6tgj0fn5lurplezyp894y";
        let permit_name = "default";
        let chain_id = "secretdev-1";
        let pub_key = "AkZqxdKMtPq2w0kGDGwWGejTAed0H7azPMHtrCX0XYZG";
        let signature = "ZXyFMlAy6guMG9Gj05rFvcMi5/JGfClRtJpVTHiDtQY3GtSfBHncY70kmYiTXkKIxSxdnh/kS8oXa+GSX5su6Q==";

        // Init the contract
        let (init_result, deps) = init_helper(vec![InitialBalance {
            address: user_address.to_string(),
            amount: Uint128::new(50000000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let msg = get_allowances_given_permit(
            permit_name,
            chain_id,
            pub_key,
            signature,
            "secret18mdrja40gfuftt5yx6tgj0fn5lurplezyp894y".to_string(),
        );
        let query_result = query(deps.as_ref(), mock_env(), msg);

        assert_eq!(query_result.is_ok(), true);
    }

    #[test]
    fn test_permit_revoke() {
        let user_address = "secret1kmgdagt5efcz2kku0ak9ezfgntg29g2vr88q0e";
        let permit_name = "to_be_revoked";
        let chain_id = "blabla";

        // Note that 'signature'was generated with the specific values of the above:
        // user_address, permit_name, chain_id, pub_key_value
        let pub_key_value = "Ahlb7vwjo4aTY6dqfgpPmPYF7XhTAIReVwncQwlq8Sct";
        let signature = "VS13F7iv1qxKABxrCAvZQPy2IruLQsIyfTewy/PIhNtybtq417lr3FxsWjV/i9YTqCUxg7weoZwHmYs0YgYX4w==";

        // Init the contract
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: user_address.to_string(),
            amount: Uint128::new(50000000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Query the account's balance
        let balance_with_permit_msg =
            get_balance_with_permit_qry_msg(permit_name, chain_id, pub_key_value, signature);
        let query_result = query(deps.as_ref(), mock_env(), balance_with_permit_msg);
        let balance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Balance { amount } => amount,
            _ => panic!("Unexpected result from query"),
        };
        assert_eq!(balance.u128(), 50000000);

        // Revoke the Balance permit
        let handle_result = revoke_permit(permit_name, user_address, &mut deps);
        let status = match from_binary(&handle_result.unwrap().data.unwrap()).unwrap() {
            ExecuteAnswer::RevokePermit { status } => status,
            _ => panic!("NOPE"),
        };
        assert_eq!(status, ResponseStatus::Success);

        // Try to query the balance with permit and fail because the permit is now revoked
        let balance_with_permit_msg =
            get_balance_with_permit_qry_msg(permit_name, chain_id, pub_key_value, signature);
        let query_result = query(deps.as_ref(), mock_env(), balance_with_permit_msg);
        let error = extract_error_msg(query_result);
        assert!(
            error.contains(format!("Permit \"{}\" was revoked by account", permit_name).as_str())
        );
    }

    #[test]
    fn test_execute_transfer_from() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Transfer before allowance
        let handle_msg = ExecuteMsg::TransferFrom {
            owner: "bob".to_string(),
            recipient: "alice".to_string(),
            amount: Uint128::new(2500),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Transfer more than allowance
        let handle_msg = ExecuteMsg::IncreaseAllowance {
            spender: "alice".to_string(),
            amount: Uint128::new(2000),
            padding: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            expiration: Some(1_571_797_420),
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let handle_msg = ExecuteMsg::TransferFrom {
            owner: "bob".to_string(),
            recipient: "alice".to_string(),
            amount: Uint128::new(2500),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Transfer after allowance expired
        let handle_msg = ExecuteMsg::TransferFrom {
            owner: "bob".to_string(),
            recipient: "alice".to_string(),
            amount: Uint128::new(2000),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };

        let info = MessageInfo {
            sender: Addr::unchecked("bob".to_string()),
            funds: vec![],
        };

        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 12_345,
                    time: Timestamp::from_seconds(1_571_797_420),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: Some(Binary::from(&[
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                    ])),
                },
                transaction: Some(TransactionInfo {
                    index: 3,
                    hash: "1010".to_string(),
                }),
                contract: ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR.to_string()),
                    code_hash: "".to_string(),
                },
            },
            info,
            handle_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Sanity check
        let handle_msg = ExecuteMsg::TransferFrom {
            owner: "bob".to_string(),
            recipient: "alice".to_string(),
            amount: Uint128::new(2000),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let bob_canonical = deps
            .api
            .addr_canonicalize(Addr::unchecked("bob".to_string()).as_str())
            .unwrap();
        let alice_canonical = deps
            .api
            .addr_canonicalize(Addr::unchecked("alice".to_string()).as_str())
            .unwrap();

        let bob_balance = stored_balance(&deps.storage, &bob_canonical).unwrap();
        let alice_balance = stored_balance(&deps.storage, &alice_canonical).unwrap();
        assert_eq!(bob_balance, 5000 - 2000);
        assert_ne!(alice_balance, 2000);
        let total_supply = TOTAL_SUPPLY.load(&deps.storage).unwrap();
        assert_eq!(total_supply, 5000);

        // Second send more than allowance
        let handle_msg = ExecuteMsg::TransferFrom {
            owner: "bob".to_string(),
            recipient: "alice".to_string(),
            amount: Uint128::new(1),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));
    }

    #[test]
    fn test_handle_send_from() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Send before allowance
        let handle_msg = ExecuteMsg::SendFrom {
            owner: "bob".to_string(),
            recipient: "alice".to_string(),
            recipient_code_hash: None,
            amount: Uint128::new(2500),
            memo: None,
            msg: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Send more than allowance
        let handle_msg = ExecuteMsg::IncreaseAllowance {
            spender: "alice".to_string(),
            amount: Uint128::new(2000),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
            expiration: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let handle_msg = ExecuteMsg::SendFrom {
            owner: "bob".to_string(),
            recipient: "alice".to_string(),
            recipient_code_hash: None,
            amount: Uint128::new(2500),
            memo: None,
            msg: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Sanity check
        let handle_msg = ExecuteMsg::RegisterReceive {
            code_hash: "lolz".to_string(),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("contract", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let send_msg = Binary::from(r#"{ "some_msg": { "some_key": "some_val" } }"#.as_bytes());
        let snip20_msg = Snip20ReceiveMsg::new(
            Addr::unchecked("alice".to_string()),
            Addr::unchecked("bob".to_string()),
            Uint128::new(2000),
            Some("my memo".to_string()),
            Some(send_msg.clone()),
        );
        let handle_msg = ExecuteMsg::SendFrom {
            owner: "bob".to_string(),
            recipient: "contract".to_string(),
            recipient_code_hash: None,
            amount: Uint128::new(2000),
            memo: Some("my memo".to_string()),
            msg: Some(send_msg),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        assert!(handle_result.unwrap().messages.contains(
            &into_cosmos_submsg(
                snip20_msg,
                "lolz".to_string(),
                Addr::unchecked("contract".to_string()),
                0
            )
            .unwrap()
        ));

        let bob_canonical = deps
            .api
            .addr_canonicalize(Addr::unchecked("bob".to_string()).as_str())
            .unwrap();
        let contract_canonical = deps
            .api
            .addr_canonicalize(Addr::unchecked("contract".to_string()).as_str())
            .unwrap();

        let bob_balance = stored_balance(&deps.storage, &bob_canonical).unwrap();
        let contract_balance = stored_balance(&deps.storage, &contract_canonical).unwrap();
        assert_eq!(bob_balance, 5000 - 2000);
        assert_ne!(contract_balance, 2000);
        let total_supply = TOTAL_SUPPLY.load(&deps.storage).unwrap();
        assert_eq!(total_supply, 5000);

        // Second send more than allowance
        let handle_msg = ExecuteMsg::SendFrom {
            owner: "bob".to_string(),
            recipient: "alice".to_string(),
            recipient_code_hash: None,
            amount: Uint128::new(1),
            memo: None,
            msg: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));
    }

    #[test]
    fn test_handle_burn_from() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: "bob".to_string(),
                amount: Uint128::new(10000),
            }],
            false,
            false,
            false,
            true,
            0,
            vec![],
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(10000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when burn disabled
        let handle_msg = ExecuteMsg::BurnFrom {
            owner: "bob".to_string(),
            amount: Uint128::new(2500),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Burn functionality is not enabled for this token."));

        // Burn before allowance
        let handle_msg = ExecuteMsg::BurnFrom {
            owner: "bob".to_string(),
            amount: Uint128::new(2500),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Burn more than allowance
        let handle_msg = ExecuteMsg::IncreaseAllowance {
            spender: "alice".to_string(),
            amount: Uint128::new(2000),
            padding: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            expiration: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let handle_msg = ExecuteMsg::BurnFrom {
            owner: "bob".to_string(),
            amount: Uint128::new(2500),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Sanity check
        let handle_msg = ExecuteMsg::BurnFrom {
            owner: "bob".to_string(),
            amount: Uint128::new(2000),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let bob_canonical = deps
            .api
            .addr_canonicalize(Addr::unchecked("bob".to_string()).as_str())
            .unwrap();

        let bob_balance = stored_balance(&deps.storage, &bob_canonical).unwrap();
        assert_eq!(bob_balance, 10000 - 2000);
        let total_supply = TOTAL_SUPPLY.load(&deps.storage).unwrap();
        assert_eq!(total_supply, 10000 - 2000);

        // Second burn more than allowance
        let handle_msg = ExecuteMsg::BurnFrom {
            owner: "bob".to_string(),
            amount: Uint128::new(1),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));
    }

    #[test]
    fn test_handle_batch_burn_from() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![
                InitialBalance {
                    address: "bob".to_string(),
                    amount: Uint128::new(10000),
                },
                InitialBalance {
                    address: "jerry".to_string(),
                    amount: Uint128::new(10000),
                },
                InitialBalance {
                    address: "mike".to_string(),
                    amount: Uint128::new(10000),
                },
            ],
            false,
            false,
            false,
            true,
            0,
            vec![],
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(10000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when burn disabled
        let actions: Vec<_> = ["bob", "jerry", "mike"]
            .iter()
            .map(|name| batch::BurnFromAction {
                owner: name.to_string(),
                amount: Uint128::new(2500),
                memo: None,
            })
            .collect();
        let handle_msg = ExecuteMsg::BatchBurnFrom {
            actions,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);
        let handle_result = execute(
            deps_for_failure.as_mut(),
            mock_env(),
            info,
            handle_msg.clone(),
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Burn functionality is not enabled for this token."));

        // Burn before allowance
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Burn more than allowance
        let allowance_size = 2000;
        for name in &["bob", "jerry", "mike"] {
            let handle_msg = ExecuteMsg::IncreaseAllowance {
                spender: "alice".to_string(),
                amount: Uint128::new(allowance_size),
                padding: None,
                #[cfg(feature = "gas_evaporation")]
                gas_target: None,
                expiration: None,
            };
            let info = mock_info(*name, &[]);
            let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

            assert!(
                handle_result.is_ok(),
                "handle() failed: {}",
                handle_result.err().unwrap()
            );
            let handle_msg = ExecuteMsg::BurnFrom {
                owner: "name".to_string(),
                amount: Uint128::new(2500),
                memo: None,
                #[cfg(feature = "gas_evaporation")]
                gas_target: None,
                padding: None,
            };
            let info = mock_info("alice", &[]);

            let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

            let error = extract_error_msg(handle_result);
            assert!(error.contains("insufficient allowance"));
        }

        // Burn some of the allowance
        let actions: Vec<_> = [("bob", 200_u128), ("jerry", 300), ("mike", 400)]
            .iter()
            .map(|(name, amount)| batch::BurnFromAction {
                owner: name.to_string(),
                amount: Uint128::new(*amount),
                memo: None,
            })
            .collect();

        let handle_msg = ExecuteMsg::BatchBurnFrom {
            actions,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        for (name, amount) in &[("bob", 200_u128), ("jerry", 300), ("mike", 400)] {
            let name_canon = deps
                .api
                .addr_canonicalize(Addr::unchecked(name.to_string()).as_str())
                .unwrap();
            let balance = stored_balance(&deps.storage, &name_canon).unwrap();
            assert_eq!(balance, 10000 - amount);
        }
        let total_supply = TOTAL_SUPPLY.load(&deps.storage).unwrap();
        assert_eq!(total_supply, 10000 * 3 - (200 + 300 + 400));

        // Burn the rest of the allowance
        let actions: Vec<_> = [("bob", 200_u128), ("jerry", 300), ("mike", 400)]
            .iter()
            .map(|(name, amount)| batch::BurnFromAction {
                owner: name.to_string(),
                amount: Uint128::new(allowance_size - *amount),
                memo: None,
            })
            .collect();

        let handle_msg = ExecuteMsg::BatchBurnFrom {
            actions,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        for name in &["bob", "jerry", "mike"] {
            let name_canon = deps
                .api
                .addr_canonicalize(Addr::unchecked(name.to_string()).as_str())
                .unwrap();
            let balance = stored_balance(&deps.storage, &name_canon).unwrap();
            assert_eq!(balance, 10000 - allowance_size);
        }
        let total_supply = TOTAL_SUPPLY.load(&deps.storage).unwrap();
        assert_eq!(total_supply, 3 * (10000 - allowance_size));

        // Second burn more than allowance
        let actions: Vec<_> = ["bob", "jerry", "mike"]
            .iter()
            .map(|name| batch::BurnFromAction {
                owner: name.to_string(),
                amount: Uint128::new(1),
                memo: None,
            })
            .collect();
        let handle_msg = ExecuteMsg::BatchBurnFrom {
            actions,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));
    }

    #[test]
    fn test_handle_decrease_allowance() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::DecreaseAllowance {
            spender: "alice".to_string(),
            amount: Uint128::new(2000),
            padding: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            expiration: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let bob_canonical = Addr::unchecked("bob".to_string());
        let alice_canonical = Addr::unchecked("alice".to_string());

        let allowance = AllowancesStore::load(&deps.storage, &bob_canonical, &alice_canonical);
        assert_eq!(
            allowance,
            crate::state::Allowance {
                amount: 0,
                expiration: None
            }
        );

        let handle_msg = ExecuteMsg::IncreaseAllowance {
            spender: "alice".to_string(),
            amount: Uint128::new(2000),
            padding: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            expiration: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::DecreaseAllowance {
            spender: "alice".to_string(),
            amount: Uint128::new(50),
            padding: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            expiration: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let allowance = AllowancesStore::load(&deps.storage, &bob_canonical, &alice_canonical);
        assert_eq!(
            allowance,
            crate::state::Allowance {
                amount: 1950,
                expiration: None
            }
        );
    }

    #[test]
    fn test_handle_increase_allowance() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::IncreaseAllowance {
            spender: "alice".to_string(),
            amount: Uint128::new(2000),
            padding: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            expiration: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let bob_canonical = Addr::unchecked("bob".to_string());
        let alice_canonical = Addr::unchecked("alice".to_string());

        let allowance = AllowancesStore::load(&deps.storage, &bob_canonical, &alice_canonical);
        assert_eq!(
            allowance,
            crate::state::Allowance {
                amount: 2000,
                expiration: None
            }
        );

        let handle_msg = ExecuteMsg::IncreaseAllowance {
            spender: "alice".to_string(),
            amount: Uint128::new(2000),
            padding: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            expiration: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let allowance = AllowancesStore::load(&deps.storage, &bob_canonical, &alice_canonical);
        assert_eq!(
            allowance,
            crate::state::Allowance {
                amount: 4000,
                expiration: None
            }
        );
    }

    #[test]
    fn test_handle_change_admin() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::ChangeAdmin {
            address: "bob".to_string(),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let admin = CONFIG.load(&deps.storage).unwrap().admin;
        assert_eq!(admin, Addr::unchecked("bob".to_string()));
    }

    #[test]
    fn test_handle_set_contract_status() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "admin".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatusLevel::StopAll,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let contract_status = CONTRACT_STATUS.load(&deps.storage).unwrap();
        assert!(matches!(
            contract_status,
            ContractStatusLevel::StopAll { .. }
        ));
    }

    #[test]
    fn test_handle_redeem() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: "butler".to_string(),
                amount: Uint128::new(5000),
            }],
            false,
            true,
            false,
            false,
            1000,
            vec!["uscrt".to_string()],
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result_no_reserve, mut deps_no_reserve) = init_helper_with_config(
            vec![InitialBalance {
                address: "butler".to_string(),
                amount: Uint128::new(5000),
            }],
            false,
            true,
            false,
            false,
            0,
            vec!["uscrt".to_string()],
        );
        assert!(
            init_result_no_reserve.is_ok(),
            "Init failed: {}",
            init_result_no_reserve.err().unwrap()
        );

        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: "butler".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when redeem disabled
        let handle_msg = ExecuteMsg::Redeem {
            amount: Uint128::new(1000),
            denom: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("butler", &[]);

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Redeem functionality is not enabled for this token."));

        // try to redeem when contract has 0 balance
        let handle_msg = ExecuteMsg::Redeem {
            amount: Uint128::new(1000),
            denom: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("butler", &[]);

        let handle_result = execute(deps_no_reserve.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert_eq!(
            error,
            "You are trying to redeem for more uscrt than the contract has in its reserve"
        );

        // test without denom
        let handle_msg = ExecuteMsg::Redeem {
            amount: Uint128::new(1000),
            denom: None,
            padding: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
        };
        let info = mock_info("butler", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        // test with denom specified
        let handle_msg = ExecuteMsg::Redeem {
            amount: Uint128::new(1000),
            denom: Option::from("uscrt".to_string()),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("butler", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let canonical = deps
            .api
            .addr_canonicalize(Addr::unchecked("butler".to_string()).as_str())
            .unwrap();
        assert_eq!(stored_balance(&deps.storage, &canonical).unwrap(), 3000)
    }

    #[test]
    fn test_handle_deposit() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: "lebron".to_string(),
                amount: Uint128::new(5000),
            }],
            true,
            false,
            false,
            false,
            0,
            vec!["uscrt".to_string()],
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: "lebron".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when deposit disabled
        let handle_msg = ExecuteMsg::Deposit {
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info(
            "lebron",
            &[Coin {
                denom: "uscrt".to_string(),
                amount: Uint128::new(1000),
            }],
        );

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Tried to deposit an unsupported coin uscrt"));

        let handle_msg = ExecuteMsg::Deposit {
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };

        let info = mock_info(
            "lebron",
            &[Coin {
                denom: "uscrt".to_string(),
                amount: Uint128::new(1000),
            }],
        );

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let canonical = deps
            .api
            .addr_canonicalize(Addr::unchecked("lebron".to_string()).as_str())
            .unwrap();

        // stored balance not updated, still in dwb
        assert_ne!(stored_balance(&deps.storage, &canonical).unwrap(), 6000);

        let create_vk_msg = ExecuteMsg::CreateViewingKey {
            entropy: Some("34".to_string()),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("lebron", &[]);
        let handle_response = execute(deps.as_mut(), mock_env(), info, create_vk_msg).unwrap();
        let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
            ExecuteAnswer::CreateViewingKey { key } => key,
            _ => panic!("Unexpected result from handle"),
        };

        let query_balance_msg = QueryMsg::Balance {
            address: "lebron".to_string(),
            key: vk,
        };

        let query_response = query(deps.as_ref(), mock_env(), query_balance_msg).unwrap();
        let balance = match from_binary(&query_response).unwrap() {
            QueryAnswer::Balance { amount } => amount,
            _ => panic!("Unexpected result from query"),
        };
        assert_eq!(balance, Uint128::new(6000));
    }

    #[test]
    fn test_handle_burn() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: "lebron".to_string(),
                amount: Uint128::new(5000),
            }],
            false,
            false,
            false,
            true,
            0,
            vec![],
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: "lebron".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when burn disabled
        let handle_msg = ExecuteMsg::Burn {
            amount: Uint128::new(100),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("lebron", &[]);

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Burn functionality is not enabled for this token."));

        let supply = TOTAL_SUPPLY.load(&deps.storage).unwrap();
        let burn_amount: u128 = 100;
        let handle_msg = ExecuteMsg::Burn {
            amount: Uint128::new(burn_amount),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("lebron", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let new_supply = TOTAL_SUPPLY.load(&deps.storage).unwrap();
        assert_eq!(new_supply, supply - burn_amount);
    }

    #[test]
    fn test_handle_mint() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: "lebron".to_string(),
                amount: Uint128::new(5000),
            }],
            false,
            false,
            true,
            false,
            0,
            vec![],
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: "lebron".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // try to mint when mint is disabled
        let mint_amount: u128 = 100;
        let handle_msg = ExecuteMsg::Mint {
            recipient: "lebron".to_string(),
            amount: Uint128::new(mint_amount),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Mint functionality is not enabled for this token"));

        let supply = TOTAL_SUPPLY.load(&deps.storage).unwrap();
        let mint_amount: u128 = 100;
        let handle_msg = ExecuteMsg::Mint {
            recipient: "lebron".to_string(),
            amount: Uint128::new(mint_amount),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let new_supply = TOTAL_SUPPLY.load(&deps.storage).unwrap();
        assert_eq!(new_supply, supply + mint_amount);
    }

    #[test]
    fn test_handle_admin_commands() {
        let admin_err = "Admin commands can only be run from admin address".to_string();
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: "lebron".to_string(),
                amount: Uint128::new(5000),
            }],
            false,
            false,
            true,
            false,
            0,
            vec![],
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let pause_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatusLevel::StopAllButRedeems,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("not_admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, pause_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));

        let mint_msg = ExecuteMsg::AddMinters {
            minters: vec!["not_admin".to_string()],
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("not_admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, mint_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));

        let mint_msg = ExecuteMsg::RemoveMinters {
            minters: vec!["admin".to_string()],
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("not_admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, mint_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));

        let mint_msg = ExecuteMsg::SetMinters {
            minters: vec!["not_admin".to_string()],
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("not_admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, mint_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));

        let change_admin_msg = ExecuteMsg::ChangeAdmin {
            address: "not_admin".to_string(),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("not_admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, change_admin_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));
    }

    #[test]
    fn test_handle_pause_with_withdrawals() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: "lebron".to_string(),
                amount: Uint128::new(5000),
            }],
            false,
            true,
            false,
            false,
            5000,
            vec!["uscrt".to_string()],
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let pause_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatusLevel::StopAllButRedeems,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };

        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, pause_msg);

        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let send_msg = ExecuteMsg::Transfer {
            recipient: "account".to_string(),
            amount: Uint128::new(123),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, send_msg);

        let error = extract_error_msg(handle_result);
        assert_eq!(
            error,
            "This contract is stopped and this action is not allowed".to_string()
        );

        let withdraw_msg = ExecuteMsg::Redeem {
            amount: Uint128::new(5000),
            denom: Option::from("uscrt".to_string()),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("lebron", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, withdraw_msg);

        assert!(
            handle_result.is_ok(),
            "Withdraw failed: {}",
            handle_result.err().unwrap()
        );
    }

    #[test]
    fn test_handle_pause_all() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "lebron".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let pause_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatusLevel::StopAll,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };

        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, pause_msg);

        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let send_msg = ExecuteMsg::Transfer {
            recipient: "account".to_string(),
            amount: Uint128::new(123),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, send_msg);

        let error = extract_error_msg(handle_result);
        assert_eq!(
            error,
            "This contract is stopped and this action is not allowed".to_string()
        );

        let withdraw_msg = ExecuteMsg::Redeem {
            amount: Uint128::new(5000),
            denom: Option::from("uscrt".to_string()),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("lebron", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, withdraw_msg);

        let error = extract_error_msg(handle_result);
        assert_eq!(
            error,
            "This contract is stopped and this action is not allowed".to_string()
        );
    }

    #[test]
    fn test_handle_set_minters() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: "bob".to_string(),
                amount: Uint128::new(5000),
            }],
            false,
            false,
            true,
            false,
            0,
            vec![],
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // try when mint disabled
        let handle_msg = ExecuteMsg::SetMinters {
            minters: vec!["bob".to_string()],
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Mint functionality is not enabled for this token"));

        let handle_msg = ExecuteMsg::SetMinters {
            minters: vec!["bob".to_string()],
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Admin commands can only be run from admin address"));

        let handle_msg = ExecuteMsg::SetMinters {
            minters: vec!["bob".to_string()],
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Mint {
            recipient: "bob".to_string(),
            amount: Uint128::new(100),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Mint {
            recipient: "bob".to_string(),
            amount: Uint128::new(100),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("allowed to minter accounts only"));
    }

    #[test]
    fn test_handle_add_minters() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: "bob".to_string(),
                amount: Uint128::new(5000),
            }],
            false,
            false,
            true,
            false,
            0,
            vec![],
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // try when mint disabled
        let handle_msg = ExecuteMsg::AddMinters {
            minters: vec!["bob".to_string()],
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Mint functionality is not enabled for this token"));

        let handle_msg = ExecuteMsg::AddMinters {
            minters: vec!["bob".to_string()],
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Admin commands can only be run from admin address"));

        let handle_msg = ExecuteMsg::AddMinters {
            minters: vec!["bob".to_string()],
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Mint {
            recipient: "bob".to_string(),
            amount: Uint128::new(100),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Mint {
            recipient: "bob".to_string(),
            amount: Uint128::new(100),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));
    }

    #[test]
    fn test_handle_remove_minters() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: "bob".to_string(),
                amount: Uint128::new(5000),
            }],
            false,
            false,
            true,
            false,
            0,
            vec![],
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // try when mint disabled
        let handle_msg = ExecuteMsg::RemoveMinters {
            minters: vec!["bob".to_string()],
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Mint functionality is not enabled for this token"));

        let handle_msg = ExecuteMsg::RemoveMinters {
            minters: vec!["admin".to_string()],
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Admin commands can only be run from admin address"));

        let handle_msg = ExecuteMsg::RemoveMinters {
            minters: vec!["admin".to_string()],
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Mint {
            recipient: "bob".to_string(),
            amount: Uint128::new(100),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("allowed to minter accounts only"));

        let handle_msg = ExecuteMsg::Mint {
            recipient: "bob".to_string(),
            amount: Uint128::new(100),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("allowed to minter accounts only"));

        // Removing another extra time to ensure nothing funky happens
        let handle_msg = ExecuteMsg::RemoveMinters {
            minters: vec!["admin".to_string()],
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Mint {
            recipient: "bob".to_string(),
            amount: Uint128::new(100),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("allowed to minter accounts only"));

        let handle_msg = ExecuteMsg::Mint {
            recipient: "bob".to_string(),
            amount: Uint128::new(100),
            memo: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("allowed to minter accounts only"));
    }

    // Query tests

    #[test]
    fn test_authenticated_queries() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "giannis".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let no_vk_yet_query_msg = QueryMsg::Balance {
            address: "giannis".to_string(),
            key: "no_vk_yet".to_string(),
        };
        let query_result = query(deps.as_ref(), mock_env(), no_vk_yet_query_msg);
        let error = extract_error_msg(query_result);
        assert_eq!(
            error,
            "Wrong viewing key for this address or viewing key not set".to_string()
        );

        let create_vk_msg = ExecuteMsg::CreateViewingKey {
            entropy: Some("34".to_string()),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("giannis", &[]);
        let handle_response = execute(deps.as_mut(), mock_env(), info, create_vk_msg).unwrap();
        let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
            ExecuteAnswer::CreateViewingKey { key } => key,
            _ => panic!("Unexpected result from handle"),
        };

        let query_balance_msg = QueryMsg::Balance {
            address: "giannis".to_string(),
            key: vk,
        };

        let query_response = query(deps.as_ref(), mock_env(), query_balance_msg).unwrap();
        let balance = match from_binary(&query_response).unwrap() {
            QueryAnswer::Balance { amount } => amount,
            _ => panic!("Unexpected result from query"),
        };
        assert_eq!(balance, Uint128::new(5000));

        let wrong_vk_query_msg = QueryMsg::Balance {
            address: "giannis".to_string(),
            key: "wrong_vk".to_string(),
        };
        let query_result = query(deps.as_ref(), mock_env(), wrong_vk_query_msg);
        let error = extract_error_msg(query_result);
        assert_eq!(
            error,
            "Wrong viewing key for this address or viewing key not set".to_string()
        );
    }

    #[test]
    fn test_query_token_info() {
        let init_name = "sec-sec".to_string();
        let init_admin = Addr::unchecked("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 8;
        let init_config: InitConfig = from_binary(&Binary::from(
            r#"{ "public_total_supply": true }"#.as_bytes(),
        ))
        .unwrap();
        let init_supply = Uint128::new(5000);

        let mut deps = mock_dependencies_with_balance(&[]);
        let info = mock_info("instantiator", &[]);
        let env = mock_env();
        let init_msg = InstantiateMsg {
            name: init_name.clone(),
            admin: Some(init_admin.into_string()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: "giannis".to_string(),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
            supported_denoms: None,
        };
        let init_result = instantiate(deps.as_mut(), env, info, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::TokenInfo {};
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenInfo {
                name,
                symbol,
                decimals,
                total_supply,
            } => {
                assert_eq!(name, init_name);
                assert_eq!(symbol, init_symbol);
                assert_eq!(decimals, init_decimals);
                assert_eq!(total_supply, Some(Uint128::new(5000)));
            }
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn test_query_token_config() {
        let init_name = "sec-sec".to_string();
        let init_admin = Addr::unchecked("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 8;
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":{},
            \"enable_deposit\":{},
            \"enable_redeem\":{},
            \"enable_mint\":{},
            \"enable_burn\":{}}}",
                true, false, false, true, false
            )
            .as_bytes(),
        ))
        .unwrap();

        let init_supply = Uint128::new(5000);

        let mut deps = mock_dependencies_with_balance(&[]);
        let info = mock_info("instantiator", &[]);
        let env = mock_env();
        let init_msg = InstantiateMsg {
            name: init_name.clone(),
            admin: Some(init_admin.into_string()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: "giannis".to_string(),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
            supported_denoms: None,
        };
        let init_result = instantiate(deps.as_mut(), env, info, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::TokenConfig {};
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenConfig {
                public_total_supply,
                deposit_enabled,
                redeem_enabled,
                mint_enabled,
                burn_enabled,
                supported_denoms,
            } => {
                assert_eq!(public_total_supply, true);
                assert_eq!(deposit_enabled, false);
                assert_eq!(redeem_enabled, false);
                assert_eq!(mint_enabled, true);
                assert_eq!(burn_enabled, false);
                assert_eq!(supported_denoms.len(), 0);
            }
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn test_query_exchange_rate() {
        // test more dec than SCRT
        let init_name = "sec-sec".to_string();
        let init_admin = Addr::unchecked("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 8;

        let init_supply = Uint128::new(5000);

        let mut deps = mock_dependencies_with_balance(&[]);
        let info = mock_info("instantiator", &[]);
        let env = mock_env();
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":{},
                \"enable_deposit\":{},
                \"enable_redeem\":{},
                \"enable_mint\":{},
                \"enable_burn\":{}}}",
                true, true, false, false, false
            )
            .as_bytes(),
        ))
        .unwrap();
        let init_msg = InstantiateMsg {
            name: init_name.clone(),
            admin: Some(init_admin.into_string()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: "giannis".to_string(),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
            supported_denoms: Some(vec!["uscrt".to_string()]),
        };
        let init_result = instantiate(deps.as_mut(), env, info, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::ExchangeRate {};
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ExchangeRate { rate, denom } => {
                assert_eq!(rate, Uint128::new(100));
                assert_eq!(denom, "SCRT");
            }
            _ => panic!("unexpected"),
        }

        // test same number of decimals as SCRT
        let init_name = "sec-sec".to_string();
        let init_admin = Addr::unchecked("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 6;

        let init_supply = Uint128::new(5000);

        let mut deps = mock_dependencies_with_balance(&[]);
        let info = mock_info("instantiator", &[]);
        let env = mock_env();
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":{},
            \"enable_deposit\":{},
            \"enable_redeem\":{},
            \"enable_mint\":{},
            \"enable_burn\":{}}}",
                true, true, false, false, false
            )
            .as_bytes(),
        ))
        .unwrap();
        let init_msg = InstantiateMsg {
            name: init_name.clone(),
            admin: Some(init_admin.into_string()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: "giannis".to_string(),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
            supported_denoms: Some(vec!["uscrt".to_string()]),
        };
        let init_result = instantiate(deps.as_mut(), env, info, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::ExchangeRate {};
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ExchangeRate { rate, denom } => {
                assert_eq!(rate, Uint128::new(1));
                assert_eq!(denom, "SCRT");
            }
            _ => panic!("unexpected"),
        }

        // test less decimal places than SCRT
        let init_name = "sec-sec".to_string();
        let init_admin = Addr::unchecked("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 3;

        let init_supply = Uint128::new(5000);

        let mut deps = mock_dependencies_with_balance(&[]);
        let info = mock_info("instantiator", &[]);
        let env = mock_env();
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":{},
            \"enable_deposit\":{},
            \"enable_redeem\":{},
            \"enable_mint\":{},
            \"enable_burn\":{}}}",
                true, true, false, false, false
            )
            .as_bytes(),
        ))
        .unwrap();
        let init_msg = InstantiateMsg {
            name: init_name.clone(),
            admin: Some(init_admin.into_string()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: "giannis".to_string(),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
            supported_denoms: Some(vec!["uscrt".to_string()]),
        };
        let init_result = instantiate(deps.as_mut(), env, info, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::ExchangeRate {};
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ExchangeRate { rate, denom } => {
                assert_eq!(rate, Uint128::new(1000));
                assert_eq!(denom, "SECSEC");
            }
            _ => panic!("unexpected"),
        }

        // test depost/redeem not enabled
        let init_name = "sec-sec".to_string();
        let init_admin = Addr::unchecked("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 3;

        let init_supply = Uint128::new(5000);

        let mut deps = mock_dependencies_with_balance(&[]);
        let info = mock_info("instantiator", &[]);
        let env = mock_env();
        let init_msg = InstantiateMsg {
            name: init_name.clone(),
            admin: Some(init_admin.into_string()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: "giannis".to_string(),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: None,
            supported_denoms: None,
        };
        let init_result = instantiate(deps.as_mut(), env, info, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::ExchangeRate {};
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ExchangeRate { rate, denom } => {
                assert_eq!(rate, Uint128::new(0));
                assert_eq!(denom, String::new());
            }
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn test_query_allowance() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "giannis".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::IncreaseAllowance {
            spender: "lebron".to_string(),
            amount: Uint128::new(2000),
            padding: None,
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            expiration: None,
        };
        let info = mock_info("giannis", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let vk1 = "key1".to_string();
        let vk2 = "key2".to_string();

        let query_msg = QueryMsg::Allowance {
            owner: "giannis".to_string(),
            spender: "lebron".to_string(),
            key: vk1.clone(),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "Query failed: {}",
            query_result.err().unwrap()
        );
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key"));

        let handle_msg = ExecuteMsg::SetViewingKey {
            key: vk1.clone(),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("lebron", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let unwrapped_result: ExecuteAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
            .unwrap(),
        );

        let handle_msg = ExecuteMsg::SetViewingKey {
            key: vk2.clone(),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("giannis", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let unwrapped_result: ExecuteAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
            .unwrap(),
        );

        let query_msg = QueryMsg::Allowance {
            owner: "giannis".to_string(),
            spender: "lebron".to_string(),
            key: vk1.clone(),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let allowance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Allowance { allowance, .. } => allowance,
            _ => panic!("Unexpected"),
        };
        assert_eq!(allowance, Uint128::new(2000));

        let query_msg = QueryMsg::Allowance {
            owner: "giannis".to_string(),
            spender: "lebron".to_string(),
            key: vk2.clone(),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let allowance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Allowance { allowance, .. } => allowance,
            _ => panic!("Unexpected"),
        };
        assert_eq!(allowance, Uint128::new(2000));

        let query_msg = QueryMsg::Allowance {
            owner: "lebron".to_string(),
            spender: "giannis".to_string(),
            key: vk2.clone(),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let allowance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Allowance { allowance, .. } => allowance,
            _ => panic!("Unexpected"),
        };
        assert_eq!(allowance, Uint128::new(0));
    }

    #[test]
    fn test_query_all_allowances() {
        let num_owners = 3;
        let num_spenders = 20;
        let vk = "key".to_string();

        let initial_balances: Vec<InitialBalance> = (0..num_owners)
            .into_iter()
            .map(|i| InitialBalance {
                address: format!("owner{}", i),
                amount: Uint128::new(5000),
            })
            .collect();
        let (init_result, mut deps) = init_helper(initial_balances);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        for i in 0..num_owners {
            let handle_msg = ExecuteMsg::SetViewingKey {
                key: vk.clone(),
                #[cfg(feature = "gas_evaporation")]
                gas_target: None,
                padding: None,
            };
            let info = mock_info(format!("owner{}", i).as_str(), &[]);

            let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

            let unwrapped_result: ExecuteAnswer =
                from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
            assert_eq!(
                to_binary(&unwrapped_result).unwrap(),
                to_binary(&ExecuteAnswer::SetViewingKey {
                    status: ResponseStatus::Success
                })
                .unwrap(),
            );
        }

        for i in 0..num_owners {
            for j in 0..num_spenders {
                let handle_msg = ExecuteMsg::IncreaseAllowance {
                    spender: format!("spender{}", j),
                    amount: Uint128::new(50),
                    padding: None,
                    #[cfg(feature = "gas_evaporation")]
                    gas_target: None,
                    expiration: None,
                };
                let info = mock_info(format!("owner{}", i).as_str(), &[]);

                let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);
                assert!(
                    handle_result.is_ok(),
                    "handle() failed: {}",
                    handle_result.err().unwrap()
                );

                let handle_msg = ExecuteMsg::SetViewingKey {
                    key: vk.clone(),
                    #[cfg(feature = "gas_evaporation")]
                    gas_target: None,
                    padding: None,
                };
                let info = mock_info(format!("spender{}", j).as_str(), &[]);

                let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

                let unwrapped_result: ExecuteAnswer =
                    from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
                assert_eq!(
                    to_binary(&unwrapped_result).unwrap(),
                    to_binary(&ExecuteAnswer::SetViewingKey {
                        status: ResponseStatus::Success
                    })
                    .unwrap(),
                );
            }
        }

        let query_msg = QueryMsg::AllowancesGiven {
            owner: "owner0".to_string(),
            key: vk.clone(),
            page: None,
            page_size: 5,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::AllowancesGiven {
                owner,
                allowances,
                count,
            } => {
                assert_eq!(owner, "owner0".to_string());
                assert_eq!(allowances.len(), 5);
                assert_eq!(allowances[0].spender, "spender0");
                assert_eq!(allowances[0].allowance, Uint128::from(50_u128));
                assert_eq!(allowances[0].expiration, None);
                assert_eq!(count, num_spenders);
            }
            _ => panic!("Unexpected"),
        };

        let query_msg = QueryMsg::AllowancesGiven {
            owner: "owner1".to_string(),
            key: vk.clone(),
            page: Some(1),
            page_size: 5,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::AllowancesGiven {
                owner,
                allowances,
                count,
            } => {
                assert_eq!(owner, "owner1".to_string());
                assert_eq!(allowances.len(), 5);
                assert_eq!(allowances[0].spender, "spender5");
                assert_eq!(allowances[0].allowance, Uint128::from(50_u128));
                assert_eq!(allowances[0].expiration, None);
                assert_eq!(count, num_spenders);
            }
            _ => panic!("Unexpected"),
        };

        let query_msg = QueryMsg::AllowancesGiven {
            owner: "owner1".to_string(),
            key: vk.clone(),
            page: Some(0),
            page_size: 23,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::AllowancesGiven {
                owner,
                allowances,
                count,
            } => {
                assert_eq!(owner, "owner1".to_string());
                assert_eq!(allowances.len(), 20);
                assert_eq!(count, num_spenders);
            }
            _ => panic!("Unexpected"),
        };

        let query_msg = QueryMsg::AllowancesGiven {
            owner: "owner1".to_string(),
            key: vk.clone(),
            page: Some(2),
            page_size: 8,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::AllowancesGiven {
                owner,
                allowances,
                count,
            } => {
                assert_eq!(owner, "owner1".to_string());
                assert_eq!(allowances.len(), 4);
                assert_eq!(count, num_spenders);
            }
            _ => panic!("Unexpected"),
        };

        let query_msg = QueryMsg::AllowancesGiven {
            owner: "owner2".to_string(),
            key: vk.clone(),
            page: Some(5),
            page_size: 5,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::AllowancesGiven {
                owner,
                allowances,
                count,
            } => {
                assert_eq!(owner, "owner2".to_string());
                assert_eq!(allowances.len(), 0);
                assert_eq!(count, num_spenders);
            }
            _ => panic!("Unexpected"),
        };

        let query_msg = QueryMsg::AllowancesReceived {
            spender: "spender0".to_string(),
            key: vk.clone(),
            page: None,
            page_size: 10,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::AllowancesReceived {
                spender,
                allowances,
                count,
            } => {
                assert_eq!(spender, "spender0".to_string());
                assert_eq!(allowances.len(), 3);
                assert_eq!(allowances[0].owner, "owner0");
                assert_eq!(allowances[0].allowance, Uint128::from(50_u128));
                assert_eq!(allowances[0].expiration, None);
                assert_eq!(count, num_owners);
            }
            _ => panic!("Unexpected"),
        };

        let query_msg = QueryMsg::AllowancesReceived {
            spender: "spender1".to_string(),
            key: vk.clone(),
            page: Some(1),
            page_size: 1,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::AllowancesReceived {
                spender,
                allowances,
                count,
            } => {
                assert_eq!(spender, "spender1".to_string());
                assert_eq!(allowances.len(), 1);
                assert_eq!(allowances[0].owner, "owner1");
                assert_eq!(allowances[0].allowance, Uint128::from(50_u128));
                assert_eq!(allowances[0].expiration, None);
                assert_eq!(count, num_owners);
            }
            _ => panic!("Unexpected"),
        };
    }

    #[test]
    fn test_query_balance() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: "bob".to_string(),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::SetViewingKey {
            key: "key".to_string(),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let unwrapped_result: ExecuteAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&ExecuteAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
            .unwrap(),
        );

        let query_msg = QueryMsg::Balance {
            address: "bob".to_string(),
            key: "wrong_key".to_string(),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key"));

        let query_msg = QueryMsg::Balance {
            address: "bob".to_string(),
            key: "key".to_string(),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let balance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Balance { amount } => amount,
            _ => panic!("Unexpected"),
        };
        assert_eq!(balance, Uint128::new(5000));
    }

    #[test]
    fn test_query_transaction_history() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: "bob".to_string(),
                amount: Uint128::new(10000),
            }],
            true,
            true,
            true,
            true,
            1000,
            vec!["uscrt".to_string()],
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::SetViewingKey {
            key: "key".to_string(),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Burn {
            amount: Uint128::new(1),
            memo: Some("my burn message".to_string()),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::Redeem {
            amount: Uint128::new(1000),
            denom: Option::from("uscrt".to_string()),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::Mint {
            recipient: "bob".to_string(),
            amount: Uint128::new(100),
            memo: Some("my mint message".to_string()),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Deposit {
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info(
            "bob",
            &[Coin {
                denom: "uscrt".to_string(),
                amount: Uint128::new(1000),
            }],
        );

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::Transfer {
            recipient: "alice".to_string(),
            amount: Uint128::new(1000),
            memo: Some("my transfer message #1".to_string()),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let handle_msg = ExecuteMsg::Transfer {
            recipient: "banana".to_string(),
            amount: Uint128::new(500),
            memo: Some("my transfer message #2".to_string()),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let handle_msg = ExecuteMsg::Transfer {
            recipient: "mango".to_string(),
            amount: Uint128::new(2500),
            memo: Some("my transfer message #3".to_string()),
            #[cfg(feature = "gas_evaporation")]
            gas_target: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let query_msg = QueryMsg::TransactionHistory {
            address: "bob".to_string(),
            key: "key".to_string(),
            page: None,
            page_size: 10,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransactionHistory { txs, .. } => txs,
            other => panic!("Unexpected: {:?}", other),
        };

        use crate::transaction_history::TxAction;
        let expected_transfers = [
            Tx {
                id: 8735437960206903,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob".to_string()),
                    sender: Addr::unchecked("bob".to_string()),
                    recipient: Addr::unchecked("mango".to_string()),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::new(2500),
                },
                memo: Some("my transfer message #3".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 6519057655056815,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob".to_string()),
                    sender: Addr::unchecked("bob".to_string()),
                    recipient: Addr::unchecked("banana".to_string()),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::new(500),
                },
                memo: Some("my transfer message #2".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 2105964828411645,
                action: TxAction::Transfer {
                    from: Addr::unchecked("bob".to_string()),
                    sender: Addr::unchecked("bob".to_string()),
                    recipient: Addr::unchecked("alice".to_string()),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::new(1000),
                },
                memo: Some("my transfer message #1".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 7517649082682890,
                action: TxAction::Deposit {},
                coins: Coin {
                    denom: "uscrt".to_string(),
                    amount: Uint128::new(1000),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 5298675660782133,
                action: TxAction::Mint {
                    minter: Addr::unchecked("admin".to_string()),
                    recipient: Addr::unchecked("bob".to_string()),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::new(100),
                },
                memo: Some("my mint message".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 3863562430182029,
                action: TxAction::Redeem {},
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::new(1000),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 3942814133456943,
                action: TxAction::Burn {
                    burner: Addr::unchecked("bob".to_string()),
                    owner: Addr::unchecked("bob".to_string()),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::new(1),
                },
                memo: Some("my burn message".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
            Tx {
                id: 5746099005188254,
                action: TxAction::Mint {
                    minter: Addr::unchecked("admin".to_string()),
                    recipient: Addr::unchecked("bob".to_string()),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::new(10000),
                },

                memo: Some("Initial Balance".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
        ];

        assert_eq!(transfers, expected_transfers);
    }
}
