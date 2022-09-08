/// This contract implements SNIP-20 standard:
/// https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md
use cosmwasm_std::{
    entry_point, to_binary, Addr, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env,
    MessageInfo, Response, StdError, StdResult, Storage, Uint128,
};

use crate::batch;
use crate::msg::QueryWithPermit;
use crate::msg::{
    space_pad, ContractStatusLevel, ExecuteAnswer, ExecuteMsg, InstantiateMsg, QueryAnswer,
    QueryMsg, ResponseStatus::Success,
};
use crate::receiver::Snip20ReceiveMsg;
use crate::state::{
    get_receiver_hash, set_receiver_hash, AllowancesStore, BalancesStore, Constants,
    ContractStatusStore, MintersStore, TotalSupplyStore,
};
use crate::transaction_history::{
    store_burn, store_deposit, store_mint, store_redeem, store_transfer, StoredLegacyTransfer,
    StoredRichTx,
};
use secret_toolkit::crypto::sha_256;

use crate::viewing_key_obj::ViewingKeyObj;
use secret_toolkit::permit::{validate, Permit, RevokedPermits, TokenPermissions};
use secret_toolkit::viewing_key::{ViewingKey, ViewingKeyStore};

/// We make sure that responses from `handle` are padded to a multiple of this size.
pub const RESPONSE_BLOCK_SIZE: usize = 256;
pub const PREFIX_REVOKED_PERMITS: &str = "revoked_permits";

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
            "Ticker symbol is not in expected format [A-Z]{3,6}",
        ));
    }
    if msg.decimals > 18 {
        return Err(StdError::generic_err("Decimals must not exceed 18"));
    }

    let init_config = msg.config();
    let admin = msg.admin.unwrap_or(info.sender);
    let canon_admin = deps.api.addr_canonicalize(admin.as_str())?;

    let mut total_supply: u128 = 0;
    {
        let initial_balances = msg.initial_balances.unwrap_or_default();
        for balance in initial_balances {
            let balance_address = deps.api.addr_canonicalize(balance.address.as_str())?;
            let amount = balance.amount.u128();
            BalancesStore::save(deps.storage, &balance.address, amount)?;
            if let Some(new_total_supply) = total_supply.checked_add(amount) {
                total_supply = new_total_supply;
            } else {
                return Err(StdError::generic_err(
                    "The sum of all initial balances exceeds the maximum possible total supply",
                ));
            }
            store_mint(
                deps.storage,
                &canon_admin,
                &balance_address,
                balance.amount,
                msg.symbol.clone(),
                Some("Initial Balance".to_string()),
                &env.block,
            )?;
        }
    }

    let prng_seed_hashed = sha_256(&msg.prng_seed.0);

    Constants::save(
        deps.storage,
        &Constants {
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
        },
    )?;
    TotalSupplyStore::save(deps.storage, total_supply)?;
    ContractStatusStore::save(deps.storage, ContractStatusLevel::NormalRun)?;
    let minters = if init_config.mint_enabled() {
        Vec::from([admin])
    } else {
        Vec::new()
    };
    MintersStore::save(deps.storage, minters)?;

    ViewingKey::set_seed(deps.storage, &prng_seed_hashed);
    Ok(Response::default())
}

fn pad_response(response: StdResult<Response>) -> StdResult<Response> {
    response.map(|mut response| {
        response.data = response.data.map(|mut data| {
            space_pad(RESPONSE_BLOCK_SIZE, &mut data.0);
            data
        });
        response
    })
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let contract_status = ContractStatusStore::load(deps.storage)?;

    match contract_status {
        ContractStatusLevel::StopAll | ContractStatusLevel::StopAllButRedeems => {
            let response = match msg {
                ExecuteMsg::SetContractStatus { level, .. } => {
                    set_contract_status(deps, &info, level)
                }
                ExecuteMsg::Redeem { amount, .. }
                    if contract_status == ContractStatusLevel::StopAllButRedeems =>
                {
                    try_redeem(deps, env, &info, amount)
                }
                _ => Err(StdError::generic_err(
                    "This contract is stopped and this action is not allowed",
                )),
            };
            return pad_response(response);
        }
        ContractStatusLevel::NormalRun => {} // If it's a normal run just continue
    }

    let response = match msg {
        // Native
        ExecuteMsg::Deposit { .. } => try_deposit(deps, env, &info),
        ExecuteMsg::Redeem { amount, .. } => try_redeem(deps, env, &info, amount),

        // Base
        ExecuteMsg::Transfer {
            recipient,
            amount,
            memo,
            ..
        } => try_transfer(deps, env, &info, recipient, amount, memo),
        ExecuteMsg::Send {
            recipient,
            recipient_code_hash,
            amount,
            msg,
            memo,
            ..
        } => try_send(
            deps,
            env,
            &info,
            recipient,
            recipient_code_hash,
            amount,
            memo,
            msg,
        ),
        ExecuteMsg::BatchTransfer { actions, .. } => try_batch_transfer(deps, env, &info, actions),
        ExecuteMsg::BatchSend { actions, .. } => try_batch_send(deps, env, &info, actions),
        ExecuteMsg::Burn { amount, memo, .. } => try_burn(deps, env, &info, amount, memo),
        ExecuteMsg::RegisterReceive { code_hash, .. } => {
            try_register_receive(deps, &info, code_hash)
        }
        ExecuteMsg::CreateViewingKey { entropy, .. } => try_create_key(deps, env, &info, entropy),
        ExecuteMsg::SetViewingKey { key, .. } => try_set_key(deps, &info, key),

        // Allowance
        ExecuteMsg::IncreaseAllowance {
            spender,
            amount,
            expiration,
            ..
        } => try_increase_allowance(deps, env, &info, spender, amount, expiration),
        ExecuteMsg::DecreaseAllowance {
            spender,
            amount,
            expiration,
            ..
        } => try_decrease_allowance(deps, env, &info, spender, amount, expiration),
        ExecuteMsg::TransferFrom {
            owner,
            recipient,
            amount,
            memo,
            ..
        } => try_transfer_from(deps, &env, &info, &owner, &recipient, amount, memo),
        ExecuteMsg::SendFrom {
            owner,
            recipient,
            recipient_code_hash,
            amount,
            msg,
            memo,
            ..
        } => try_send_from(
            deps,
            env,
            &info,
            owner,
            recipient,
            recipient_code_hash,
            amount,
            memo,
            msg,
        ),
        ExecuteMsg::BatchTransferFrom { actions, .. } => {
            try_batch_transfer_from(deps, &env, &info, actions)
        }
        ExecuteMsg::BatchSendFrom { actions, .. } => try_batch_send_from(deps, env, &info, actions),
        ExecuteMsg::BurnFrom {
            owner,
            amount,
            memo,
            ..
        } => try_burn_from(deps, &env, &info, &owner, amount, memo),
        ExecuteMsg::BatchBurnFrom { actions, .. } => {
            try_batch_burn_from(deps, &env, &info, actions)
        }

        // Mint
        ExecuteMsg::Mint {
            recipient,
            amount,
            memo,
            ..
        } => try_mint(deps, env, &info, recipient, amount, memo),
        ExecuteMsg::BatchMint { actions, .. } => try_batch_mint(deps, env, &info, actions),

        // Other
        ExecuteMsg::ChangeAdmin { address, .. } => change_admin(deps, &info, address),
        ExecuteMsg::SetContractStatus { level, .. } => set_contract_status(deps, &info, level),
        ExecuteMsg::AddMinters { minters, .. } => add_minters(deps, &info, minters),
        ExecuteMsg::RemoveMinters { minters, .. } => remove_minters(deps, &info, minters),
        ExecuteMsg::SetMinters { minters, .. } => set_minters(deps, &info, minters),
        ExecuteMsg::RevokePermit { permit_name, .. } => revoke_permit(deps, &info, permit_name),
    };

    pad_response(response)
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::TokenInfo {} => query_token_info(deps.storage),
        QueryMsg::TokenConfig {} => query_token_config(deps.storage),
        QueryMsg::ContractStatus {} => query_contract_status(deps.storage),
        QueryMsg::ExchangeRate {} => query_exchange_rate(deps.storage),
        QueryMsg::Minters { .. } => query_minters(deps),
        QueryMsg::WithPermit { permit, query } => permit_queries(deps, permit, query),
        _ => viewing_keys_queries(deps, msg),
    }
}

fn permit_queries(deps: Deps, permit: Permit, query: QueryWithPermit) -> Result<Binary, StdError> {
    // Validate permit content
    let token_address = Constants::load(deps.storage)?.contract_address;

    let account = Addr::unchecked(validate(
        deps,
        PREFIX_REVOKED_PERMITS,
        &permit,
        token_address.into_string(),
        None,
    )?);

    // Permit validated! We can now execute the query.
    match query {
        QueryWithPermit::Balance {} => {
            if !permit.check_permission(&TokenPermissions::Balance) {
                return Err(StdError::generic_err(format!(
                    "No permission to query balance, got permissions {:?}",
                    permit.params.permissions
                )));
            }

            query_balance(deps, &account)
        }
        QueryWithPermit::TransferHistory { page, page_size } => {
            if !permit.check_permission(&TokenPermissions::History) {
                return Err(StdError::generic_err(format!(
                    "No permission to query history, got permissions {:?}",
                    permit.params.permissions
                )));
            }

            query_transfers(deps, &account, page.unwrap_or(0), page_size)
        }
        QueryWithPermit::TransactionHistory { page, page_size } => {
            if !permit.check_permission(&TokenPermissions::History) {
                return Err(StdError::generic_err(format!(
                    "No permission to query history, got permissions {:?}",
                    permit.params.permissions
                )));
            }

            query_transactions(deps, &account, page.unwrap_or(0), page_size)
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

            query_allowance(deps, owner, spender)
        }
    }
}

pub fn viewing_keys_queries(deps: Deps, msg: QueryMsg) -> StdResult<Binary> {
    let (addresses, key) = msg.get_validation_params();

    for address in addresses {
        let result = ViewingKey::check(deps.storage, address.as_str(), key.as_str());
        if result.is_ok() {
            return match msg {
                // Base
                QueryMsg::Balance { address, .. } => query_balance(deps, &address),
                QueryMsg::TransferHistory {
                    address,
                    page,
                    page_size,
                    ..
                } => query_transfers(deps, &address, page.unwrap_or(0), page_size),
                QueryMsg::TransactionHistory {
                    address,
                    page,
                    page_size,
                    ..
                } => query_transactions(deps, &address, page.unwrap_or(0), page_size),
                QueryMsg::Allowance { owner, spender, .. } => query_allowance(deps, owner, spender),
                _ => panic!("This query type does not require authentication"),
            };
        }
    }

    to_binary(&QueryAnswer::ViewingKeyError {
        msg: "Wrong viewing key for this address or viewing key not set".to_string(),
    })
}

fn query_exchange_rate(storage: &dyn Storage) -> StdResult<Binary> {
    let constants = Constants::load(storage)?;

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
        rate: Uint128::new(0),
        denom: String::new(),
    })
}

fn query_token_info(storage: &dyn Storage) -> StdResult<Binary> {
    let constants = Constants::load(storage)?;

    let total_supply = if constants.total_supply_is_public {
        Some(Uint128::new(TotalSupplyStore::load(storage)?))
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

fn query_token_config(storage: &dyn Storage) -> StdResult<Binary> {
    let constants = Constants::load(storage)?;

    to_binary(&QueryAnswer::TokenConfig {
        public_total_supply: constants.total_supply_is_public,
        deposit_enabled: constants.deposit_is_enabled,
        redeem_enabled: constants.redeem_is_enabled,
        mint_enabled: constants.mint_is_enabled,
        burn_enabled: constants.burn_is_enabled,
    })
}

fn query_contract_status(storage: &dyn Storage) -> StdResult<Binary> {
    let contract_status = ContractStatusStore::load(storage)?;

    to_binary(&QueryAnswer::ContractStatus {
        status: contract_status,
    })
}

pub fn query_transfers(deps: Deps, account: &Addr, page: u32, page_size: u32) -> StdResult<Binary> {
    let address = deps.api.addr_canonicalize(account.as_str())?;
    let (txs, total) =
        StoredLegacyTransfer::get_transfers(deps.api, deps.storage, &address, page, page_size)?;

    let result = QueryAnswer::TransferHistory {
        txs,
        total: Some(total),
    };
    to_binary(&result)
}

pub fn query_transactions(
    deps: Deps,
    account: &Addr,
    page: u32,
    page_size: u32,
) -> StdResult<Binary> {
    let address = deps.api.addr_canonicalize(account.as_str())?;
    let (txs, total) = StoredRichTx::get_txs(deps.api, deps.storage, &address, page, page_size)?;

    let result = QueryAnswer::TransactionHistory {
        txs,
        total: Some(total),
    };
    to_binary(&result)
}

pub fn query_balance(deps: Deps, account: &Addr) -> StdResult<Binary> {
    let amount = Uint128::new(BalancesStore::load(deps.storage, account));
    let response = QueryAnswer::Balance { amount };
    to_binary(&response)
}

fn query_minters(deps: Deps) -> StdResult<Binary> {
    let minters = MintersStore::load(deps.storage)?;

    let response = QueryAnswer::Minters { minters };
    to_binary(&response)
}

fn change_admin(deps: DepsMut, info: &MessageInfo, address: Addr) -> StdResult<Response> {
    let mut constants = Constants::load(deps.storage)?;
    check_if_admin(&constants.admin, &info.sender)?;

    constants.admin = address;
    Constants::save(deps.storage, &constants)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::ChangeAdmin { status: Success })?))
}

fn try_mint_impl(
    deps: &mut DepsMut,
    minter: &Addr,
    recipient: &Addr,
    amount: Uint128,
    denom: String,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let raw_amount = amount.u128();

    let mut account_balance = BalancesStore::load(deps.storage, recipient);

    if let Some(new_balance) = account_balance.checked_add(raw_amount) {
        account_balance = new_balance;
    } else {
        // This error literally can not happen, since the account's funds are a subset
        // of the total supply, both are stored as u128, and we check for overflow of
        // the total supply just a couple lines before.
        // Still, writing this to cover all overflows.
        return Err(StdError::generic_err(
            "This mint attempt would increase the account's balance above the supported maximum",
        ));
    }

    BalancesStore::save(deps.storage, recipient, account_balance)?;

    let recipient = deps.api.addr_canonicalize(recipient.as_str())?;
    let minter = deps.api.addr_canonicalize(minter.as_str())?;

    store_mint(
        deps.storage,
        &minter,
        &recipient,
        amount,
        denom,
        memo,
        block,
    )?;

    Ok(())
}

fn try_mint(
    mut deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    recipient: Addr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;

    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    let minters = MintersStore::load(deps.storage)?;
    if !minters.contains(&info.sender) {
        return Err(StdError::generic_err(
            "Minting is allowed to minter accounts only",
        ));
    }

    let mut total_supply = TotalSupplyStore::load(deps.storage)?;
    if let Some(new_total_supply) = total_supply.checked_add(amount.u128()) {
        total_supply = new_total_supply;
    } else {
        return Err(StdError::generic_err(
            "This mint attempt would increase the total supply above the supported maximum",
        ));
    }
    TotalSupplyStore::save(deps.storage, total_supply)?;

    try_mint_impl(
        &mut deps,
        &info.sender,
        &recipient,
        amount,
        constants.symbol,
        memo,
        &env.block,
    )?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::Mint { status: Success })?))
}

fn try_batch_mint(
    mut deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    actions: Vec<batch::MintAction>,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;

    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    let minters = MintersStore::load(deps.storage)?;
    if !minters.contains(&info.sender) {
        return Err(StdError::generic_err(
            "Minting is allowed to minter accounts only",
        ));
    }

    let mut total_supply = TotalSupplyStore::load(deps.storage)?;

    // Quick loop to check that the total of amounts is valid
    for action in &actions {
        if let Some(new_total_supply) = total_supply.checked_add(action.amount.u128()) {
            total_supply = new_total_supply;
        } else {
            return Err(StdError::generic_err(
                format!("This mint attempt would increase the total supply above the supported maximum: {:?}", action),
            ));
        }
    }

    TotalSupplyStore::save(deps.storage, total_supply)?;

    for action in actions {
        try_mint_impl(
            &mut deps,
            &info.sender,
            &action.recipient,
            action.amount,
            constants.symbol.clone(),
            action.memo,
            &env.block,
        )?;
    }

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::BatchMint { status: Success })?))
}

pub fn try_set_key(deps: DepsMut, info: &MessageInfo, key: String) -> StdResult<Response> {
    ViewingKey::set(deps.storage, info.sender.as_str(), key.as_str());
    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetViewingKey {
            status: Success,
        })?),
    )
}

pub fn try_create_key(
    deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    entropy: String,
) -> StdResult<Response> {
    let key = ViewingKey::create(
        deps.storage,
        info,
        &env,
        info.sender.as_str(),
        (&entropy).as_ref(),
    );

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::CreateViewingKey {
            key: ViewingKeyObj(key),
        })?),
    )
}

fn set_contract_status(
    deps: DepsMut,
    info: &MessageInfo,
    status_level: ContractStatusLevel,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    check_if_admin(&constants.admin, &info.sender)?;

    ContractStatusStore::save(deps.storage, status_level)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetContractStatus {
            status: Success,
        })?),
    )
}

pub fn query_allowance(deps: Deps, owner: Addr, spender: Addr) -> StdResult<Binary> {
    let allowance = AllowancesStore::load(deps.storage, &owner, &spender);

    let response = QueryAnswer::Allowance {
        owner,
        spender,
        allowance: Uint128::new(allowance.amount),
        expiration: allowance.expiration,
    };
    to_binary(&response)
}

fn try_deposit(deps: DepsMut, env: Env, info: &MessageInfo) -> StdResult<Response> {
    let mut amount = Uint128::zero();

    for coin in &info.funds {
        if coin.denom == "uscrt" {
            amount = coin.amount
        } else {
            return Err(StdError::generic_err(
                "Tried to deposit an unsupported token",
            ));
        }
    }

    if amount.is_zero() {
        return Err(StdError::generic_err("No funds were sent to be deposited"));
    }

    let raw_amount = amount.u128();

    let constants = Constants::load(deps.storage)?;
    if !constants.deposit_is_enabled {
        return Err(StdError::generic_err(
            "Deposit functionality is not enabled for this token.",
        ));
    }

    let total_supply = TotalSupplyStore::load(deps.storage)?;
    if let Some(total_supply) = total_supply.checked_add(raw_amount) {
        TotalSupplyStore::save(deps.storage, total_supply)?;
    } else {
        return Err(StdError::generic_err(
            "This deposit would overflow the currency's total supply",
        ));
    }

    let sender_address = deps.api.addr_canonicalize(info.sender.as_str())?;

    let account_balance = BalancesStore::load(deps.storage, &info.sender);
    if let Some(account_balance) = account_balance.checked_add(raw_amount) {
        BalancesStore::save(deps.storage, &info.sender, account_balance)?;
    } else {
        return Err(StdError::generic_err(
            "This deposit would overflow your balance",
        ));
    }

    store_deposit(
        deps.storage,
        &sender_address,
        amount,
        "uscrt".to_string(),
        &env.block,
    )?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::Deposit { status: Success })?))
}

fn try_redeem(deps: DepsMut, env: Env, info: &MessageInfo, amount: Uint128) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    if !constants.redeem_is_enabled {
        return Err(StdError::generic_err(
            "Redeem functionality is not enabled for this token.",
        ));
    }

    let sender_address = deps.api.addr_canonicalize(info.sender.as_str())?;
    let amount_raw = amount.u128();

    let account_balance = BalancesStore::load(deps.storage, &info.sender);
    if let Some(account_balance) = account_balance.checked_sub(amount_raw) {
        BalancesStore::save(deps.storage, &info.sender, account_balance)?;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds to redeem: balance={}, required={}",
            account_balance, amount_raw
        )));
    }

    let total_supply = TotalSupplyStore::load(deps.storage)?;
    if let Some(total_supply) = total_supply.checked_sub(amount_raw) {
        TotalSupplyStore::save(deps.storage, total_supply)?;
    } else {
        return Err(StdError::generic_err(
            "You are trying to redeem more tokens than what is available in the total supply",
        ));
    }

    let token_reserve = deps
        .querier
        .query_balance(&env.contract.address, "uscrt")?
        .amount;
    if amount > token_reserve {
        return Err(StdError::generic_err(
            "You are trying to redeem for more SCRT than the token has in its deposit reserve.",
        ));
    }

    let withdrawal_coins: Vec<Coin> = vec![Coin {
        denom: "uscrt".to_string(),
        amount,
    }];

    store_redeem(
        deps.storage,
        &sender_address,
        amount,
        constants.symbol,
        &env.block,
    )?;

    let message = CosmosMsg::Bank(BankMsg::Send {
        to_address: info.sender.clone().into_string(),
        amount: withdrawal_coins,
    });
    let data = to_binary(&ExecuteAnswer::Redeem { status: Success })?;
    let res = Response::new().add_message(message).set_data(data);
    Ok(res)
}

fn try_transfer_impl(
    deps: &mut DepsMut,
    sender: &Addr,
    recipient: &Addr,
    amount: Uint128,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    perform_transfer(deps.storage, sender, recipient, amount.u128())?;

    let symbol = Constants::load(deps.storage)?.symbol;

    let sender = deps.api.addr_canonicalize(sender.as_str())?;
    let recipient = deps.api.addr_canonicalize(recipient.as_str())?;
    store_transfer(
        deps.storage,
        &sender,
        &sender,
        &recipient,
        amount,
        symbol,
        memo,
        block,
    )?;

    Ok(())
}

fn try_transfer(
    mut deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    recipient: Addr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<Response> {
    try_transfer_impl(
        &mut deps,
        &info.sender,
        &recipient,
        amount,
        memo,
        &env.block,
    )?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::Transfer { status: Success })?))
}

fn try_batch_transfer(
    mut deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    actions: Vec<batch::TransferAction>,
) -> StdResult<Response> {
    for action in actions {
        try_transfer_impl(
            &mut deps,
            &info.sender,
            &action.recipient,
            action.amount,
            action.memo,
            &env.block,
        )?;
    }

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::BatchTransfer {
            status: Success,
        })?),
    )
}

#[allow(clippy::too_many_arguments)]
fn try_add_receiver_api_callback(
    storage: &dyn Storage,
    messages: &mut Vec<CosmosMsg>,
    recipient: Addr,
    recipient_code_hash: Option<String>,
    msg: Option<Binary>,
    sender: Addr,
    from: Addr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<()> {
    if let Some(receiver_hash) = recipient_code_hash {
        let receiver_msg = Snip20ReceiveMsg::new(sender, from, amount, memo, msg);
        let callback_msg = receiver_msg.into_cosmos_msg(receiver_hash, recipient)?;

        messages.push(callback_msg);
        return Ok(());
    }

    let receiver_hash = get_receiver_hash(storage, &recipient);
    if let Some(receiver_hash) = receiver_hash {
        let receiver_hash = receiver_hash?;
        let receiver_msg = Snip20ReceiveMsg::new(sender, from, amount, memo, msg);
        let callback_msg = receiver_msg.into_cosmos_msg(receiver_hash, recipient)?;

        messages.push(callback_msg);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn try_send_impl(
    deps: &mut DepsMut,
    messages: &mut Vec<CosmosMsg>,
    sender: Addr,
    recipient: Addr,
    recipient_code_hash: Option<String>,
    amount: Uint128,
    memo: Option<String>,
    msg: Option<Binary>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    try_transfer_impl(deps, &sender, &recipient, amount, memo.clone(), block)?;

    try_add_receiver_api_callback(
        deps.storage,
        messages,
        recipient,
        recipient_code_hash,
        msg,
        sender.clone(),
        sender,
        amount,
        memo,
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn try_send(
    mut deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    recipient: Addr,
    recipient_code_hash: Option<String>,
    amount: Uint128,
    memo: Option<String>,
    msg: Option<Binary>,
) -> StdResult<Response> {
    let mut messages = vec![];
    try_send_impl(
        &mut deps,
        &mut messages,
        info.sender.clone(),
        recipient,
        recipient_code_hash,
        amount,
        memo,
        msg,
        &env.block,
    )?;

    Ok(Response::new()
        .add_messages(messages)
        .set_data(to_binary(&ExecuteAnswer::Send { status: Success })?))
}

fn try_batch_send(
    mut deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    actions: Vec<batch::SendAction>,
) -> StdResult<Response> {
    let mut messages = vec![];
    for action in actions {
        try_send_impl(
            &mut deps,
            &mut messages,
            info.sender.clone(),
            action.recipient,
            action.recipient_code_hash,
            action.amount,
            action.memo,
            action.msg,
            &env.block,
        )?;
    }

    Ok(Response::new()
        .add_messages(messages)
        .set_data(to_binary(&ExecuteAnswer::BatchSend { status: Success })?))
}

fn try_register_receive(
    deps: DepsMut,
    info: &MessageInfo,
    code_hash: String,
) -> StdResult<Response> {
    set_receiver_hash(deps.storage, &info.sender, code_hash);

    let data = to_binary(&ExecuteAnswer::RegisterReceive { status: Success })?;
    Ok(Response::new()
        .add_attribute("register_status", "success")
        .set_data(data))
}

fn insufficient_allowance(allowance: u128, required: u128) -> StdError {
    StdError::generic_err(format!(
        "insufficient allowance: allowance={}, required={}",
        allowance, required
    ))
}

fn use_allowance(
    storage: &mut dyn Storage,
    env: &Env,
    owner: &Addr,
    spender: &Addr,
    amount: u128,
) -> StdResult<()> {
    let mut allowance = AllowancesStore::load(storage, owner, spender);

    if allowance.is_expired_at(&env.block) {
        return Err(insufficient_allowance(0, amount));
    }
    if let Some(new_allowance) = allowance.amount.checked_sub(amount) {
        allowance.amount = new_allowance;
    } else {
        return Err(insufficient_allowance(allowance.amount, amount));
    }

    AllowancesStore::save(storage, owner, spender, &allowance)?;

    Ok(())
}

fn try_transfer_from_impl(
    deps: &mut DepsMut,
    env: &Env,
    spender: &Addr,
    owner: &Addr,
    recipient: &Addr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<()> {
    let raw_amount = amount.u128();

    use_allowance(deps.storage, env, owner, spender, raw_amount)?;

    perform_transfer(deps.storage, owner, recipient, raw_amount)?;

    let symbol = Constants::load(deps.storage)?.symbol;

    let owner = deps.api.addr_canonicalize(owner.as_str())?;
    let spender = deps.api.addr_canonicalize(spender.as_str())?;
    let recipient = deps.api.addr_canonicalize(recipient.as_str())?;
    store_transfer(
        deps.storage,
        &owner,
        &spender,
        &recipient,
        amount,
        symbol,
        memo,
        &env.block,
    )?;

    Ok(())
}

fn try_transfer_from(
    mut deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    owner: &Addr,
    recipient: &Addr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<Response> {
    try_transfer_from_impl(&mut deps, env, &info.sender, owner, recipient, amount, memo)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::TransferFrom { status: Success })?))
}

fn try_batch_transfer_from(
    mut deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    actions: Vec<batch::TransferFromAction>,
) -> StdResult<Response> {
    for action in actions {
        try_transfer_from_impl(
            &mut deps,
            env,
            &info.sender,
            &action.owner,
            &action.recipient,
            action.amount,
            action.memo,
        )?;
    }

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::BatchTransferFrom {
            status: Success,
        })?),
    )
}

#[allow(clippy::too_many_arguments)]
fn try_send_from_impl(
    deps: &mut DepsMut,
    env: Env,
    info: &MessageInfo,
    messages: &mut Vec<CosmosMsg>,
    spender: Addr, // redundant but more efficient
    owner: Addr,
    recipient: Addr,
    recipient_code_hash: Option<String>,
    amount: Uint128,
    memo: Option<String>,
    msg: Option<Binary>,
) -> StdResult<()> {
    try_transfer_from_impl(
        deps,
        &env,
        &spender,
        &owner,
        &recipient,
        amount,
        memo.clone(),
    )?;

    try_add_receiver_api_callback(
        deps.storage,
        messages,
        recipient,
        recipient_code_hash,
        msg,
        info.sender.clone(),
        owner,
        amount,
        memo,
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn try_send_from(
    mut deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    owner: Addr,
    recipient: Addr,
    recipient_code_hash: Option<String>,
    amount: Uint128,
    memo: Option<String>,
    msg: Option<Binary>,
) -> StdResult<Response> {
    let mut messages = vec![];
    try_send_from_impl(
        &mut deps,
        env,
        info,
        &mut messages,
        info.sender.clone(),
        owner,
        recipient,
        recipient_code_hash,
        amount,
        memo,
        msg,
    )?;

    Ok(Response::new()
        .add_messages(messages)
        .set_data(to_binary(&ExecuteAnswer::SendFrom { status: Success })?))
}

fn try_batch_send_from(
    mut deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    actions: Vec<batch::SendFromAction>,
) -> StdResult<Response> {
    let mut messages = vec![];

    for action in actions {
        try_send_from_impl(
            &mut deps,
            env.clone(),
            info,
            &mut messages,
            info.sender.clone(),
            action.owner,
            action.recipient,
            action.recipient_code_hash,
            action.amount,
            action.memo,
            action.msg,
        )?;
    }

    Ok(Response::new()
        .add_messages(messages)
        .set_data(to_binary(&ExecuteAnswer::BatchSendFrom {
            status: Success,
        })?))
}

fn try_burn_from(
    deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    owner: &Addr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    if !constants.burn_is_enabled {
        return Err(StdError::generic_err(
            "Burn functionality is not enabled for this token.",
        ));
    }

    let raw_amount = amount.u128();
    use_allowance(deps.storage, env, owner, &info.sender, raw_amount)?;

    // subtract from owner account
    let mut account_balance = BalancesStore::load(deps.storage, owner);
    if let Some(new_balance) = account_balance.checked_sub(raw_amount) {
        account_balance = new_balance;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds to burn: balance={}, required={}",
            account_balance, raw_amount
        )));
    }
    BalancesStore::save(deps.storage, owner, account_balance)?;

    let spender = deps.api.addr_canonicalize(info.sender.as_str())?;
    let owner = deps.api.addr_canonicalize(owner.as_str())?;

    // remove from supply
    let mut total_supply = TotalSupplyStore::load(deps.storage)?;

    if let Some(new_total_supply) = total_supply.checked_sub(raw_amount) {
        total_supply = new_total_supply;
    } else {
        return Err(StdError::generic_err(
            "You're trying to burn more than is available in the total supply",
        ));
    }
    TotalSupplyStore::save(deps.storage, total_supply)?;

    store_burn(
        deps.storage,
        &owner,
        &spender,
        amount,
        constants.symbol,
        memo,
        &env.block,
    )?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::BurnFrom { status: Success })?))
}

fn try_batch_burn_from(
    deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    actions: Vec<batch::BurnFromAction>,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    if !constants.burn_is_enabled {
        return Err(StdError::generic_err(
            "Burn functionality is not enabled for this token.",
        ));
    }

    let spender = info.sender.clone();

    let mut total_supply = TotalSupplyStore::load(deps.storage)?;

    for action in actions {
        let owner = action.owner.clone();
        let amount = action.amount.u128();
        use_allowance(deps.storage, env, &owner, &spender, amount)?;

        // subtract from owner account
        let mut account_balance = BalancesStore::load(deps.storage, &owner);

        if let Some(new_balance) = account_balance.checked_sub(amount) {
            account_balance = new_balance;
        } else {
            return Err(StdError::generic_err(format!(
                "insufficient funds to burn: balance={}, required={}",
                account_balance, amount
            )));
        }
        BalancesStore::save(deps.storage, &owner, account_balance)?;

        // remove from supply
        if let Some(new_total_supply) = total_supply.checked_sub(amount) {
            total_supply = new_total_supply;
        } else {
            return Err(StdError::generic_err(format!(
                "You're trying to burn more than is available in the total supply: {:?}",
                action
            )));
        }

        let owner = deps.api.addr_canonicalize(owner.as_str())?;
        let spender = deps.api.addr_canonicalize(spender.as_str())?;
        store_burn(
            deps.storage,
            &owner,
            &spender,
            action.amount,
            constants.symbol.clone(),
            action.memo,
            &env.block,
        )?;
    }

    TotalSupplyStore::save(deps.storage, total_supply)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::BatchBurnFrom {
            status: Success,
        })?),
    )
}

fn try_increase_allowance(
    deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    spender: Addr,
    amount: Uint128,
    expiration: Option<u64>,
) -> StdResult<Response> {
    let mut allowance = AllowancesStore::load(deps.storage, &info.sender, &spender);

    // If the previous allowance has expired, reset the allowance.
    // Without this users can take advantage of an expired allowance given to
    // them long ago.
    if allowance.is_expired_at(&env.block) {
        allowance.amount = amount.u128();
        allowance.expiration = None;
    } else {
        allowance.amount = allowance.amount.saturating_add(amount.u128());
    }

    if expiration.is_some() {
        allowance.expiration = expiration;
    }
    let new_amount = allowance.amount;
    AllowancesStore::save(deps.storage, &info.sender, &spender, &allowance)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::IncreaseAllowance {
            owner: info.sender.clone(),
            spender,
            allowance: Uint128::from(new_amount),
        })?),
    )
}

fn try_decrease_allowance(
    deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    spender: Addr,
    amount: Uint128,
    expiration: Option<u64>,
) -> StdResult<Response> {
    let mut allowance = AllowancesStore::load(deps.storage, &info.sender, &spender);

    // If the previous allowance has expired, reset the allowance.
    // Without this users can take advantage of an expired allowance given to
    // them long ago.
    if allowance.is_expired_at(&env.block) {
        allowance.amount = 0;
        allowance.expiration = None;
    } else {
        allowance.amount = allowance.amount.saturating_sub(amount.u128());
    }

    if expiration.is_some() {
        allowance.expiration = expiration;
    }
    let new_amount = allowance.amount;
    AllowancesStore::save(deps.storage, &info.sender, &spender, &allowance)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::DecreaseAllowance {
            owner: info.sender.clone(),
            spender,
            allowance: Uint128::from(new_amount),
        })?),
    )
}

fn add_minters(
    deps: DepsMut,
    info: &MessageInfo,
    minters_to_add: Vec<Addr>,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    check_if_admin(&constants.admin, &info.sender)?;

    MintersStore::add_minters(deps.storage, minters_to_add)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::AddMinters { status: Success })?))
}

fn remove_minters(
    deps: DepsMut,
    info: &MessageInfo,
    minters_to_remove: Vec<Addr>,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    check_if_admin(&constants.admin, &info.sender)?;

    MintersStore::remove_minters(deps.storage, minters_to_remove)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::RemoveMinters {
            status: Success,
        })?),
    )
}

fn set_minters(
    deps: DepsMut,
    info: &MessageInfo,
    minters_to_set: Vec<Addr>,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    check_if_admin(&constants.admin, &info.sender)?;

    MintersStore::save(deps.storage, minters_to_set)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::SetMinters { status: Success })?))
}

/// Burn tokens
///
/// Remove `amount` tokens from the system irreversibly, from signer account
///
/// @param amount the amount of money to burn
fn try_burn(
    deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<Response> {
    let constants = Constants::load(deps.storage)?;
    if !constants.burn_is_enabled {
        return Err(StdError::generic_err(
            "Burn functionality is not enabled for this token.",
        ));
    }

    let sender_address = deps.api.addr_canonicalize(info.sender.as_str())?;
    let raw_amount = amount.u128();

    let mut account_balance = BalancesStore::load(deps.storage, &info.sender);

    if let Some(new_account_balance) = account_balance.checked_sub(raw_amount) {
        account_balance = new_account_balance;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds to burn: balance={}, required={}",
            account_balance, raw_amount
        )));
    }

    BalancesStore::save(deps.storage, &info.sender, account_balance)?;

    let mut total_supply = TotalSupplyStore::load(deps.storage)?;
    if let Some(new_total_supply) = total_supply.checked_sub(raw_amount) {
        total_supply = new_total_supply;
    } else {
        return Err(StdError::generic_err(
            "You're trying to burn more than is available in the total supply",
        ));
    }
    TotalSupplyStore::save(deps.storage, total_supply)?;

    store_burn(
        deps.storage,
        &sender_address,
        &sender_address,
        amount,
        constants.symbol,
        memo,
        &env.block,
    )?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::Burn { status: Success })?))
}

fn perform_transfer(
    store: &mut dyn Storage,
    from: &Addr,
    to: &Addr,
    amount: u128,
) -> StdResult<()> {
    let mut from_balance = BalancesStore::load(store, from);

    if let Some(new_from_balance) = from_balance.checked_sub(amount) {
        from_balance = new_from_balance;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds: balance={}, required={}",
            from_balance, amount
        )));
    }
    BalancesStore::save(store, from, from_balance)?;

    let mut to_balance = BalancesStore::load(store, to);
    to_balance = to_balance.checked_add(amount).ok_or_else(|| {
        StdError::generic_err("This tx will literally make them too rich. Try transferring less")
    })?;
    BalancesStore::save(store, to, to_balance)?;

    Ok(())
}

fn revoke_permit(deps: DepsMut, info: &MessageInfo, permit_name: String) -> StdResult<Response> {
    RevokedPermits::revoke_permit(
        deps.storage,
        PREFIX_REVOKED_PERMITS,
        info.sender.as_str(),
        &permit_name,
    );

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::RevokePermit { status: Success })?))
}

fn check_if_admin(config_admin: &Addr, account: &Addr) -> StdResult<()> {
    if config_admin != account {
        return Err(StdError::generic_err(
            "This is an admin command. Admin commands can only be run from admin address",
        ));
    }

    Ok(())
}

fn is_valid_name(name: &str) -> bool {
    let len = name.len();
    (3..=30).contains(&len)
}

fn is_valid_symbol(symbol: &str) -> bool {
    let len = symbol.len();
    let len_is_valid = (3..=6).contains(&len);

    len_is_valid && symbol.bytes().all(|byte| (b'A'..=b'Z').contains(&byte))
}

// pub fn migrate(
//     _deps: DepsMut,
//     _env: Env,
//     _msg: MigrateMsg,
// ) -> StdResult<MigrateResponse> {
//     Ok(MigrateResponse::default())
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::ResponseStatus;
    use crate::msg::{InitConfig, InitialBalance};
    use crate::viewing_key_obj::ViewingKeyObj;
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{
        from_binary, BlockInfo, ContractInfo, MessageInfo, OwnedDeps, QueryResponse, ReplyOn,
        SubMsg, Timestamp, TransactionInfo, WasmMsg,
    };
    use std::any::Any;
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
            admin: Some(Addr::unchecked("admin".to_string())),
            symbol: "SECSEC".to_string(),
            decimals: 8,
            initial_balances: Some(initial_balances),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: None,
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
            admin: Some(Addr::unchecked("admin".to_string())),
            symbol: "SECSEC".to_string(),
            decimals: 8,
            initial_balances: Some(initial_balances),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
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

    // Init tests

    #[test]
    fn test_init_sanity() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("lebron".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert_eq!(init_result.unwrap(), Response::default());

        let constants = Constants::load(&deps.storage).unwrap();
        assert_eq!(TotalSupplyStore::load(&deps.storage).unwrap(), 5000);
        assert_eq!(
            ContractStatusStore::load(&deps.storage).unwrap(),
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
                address: Addr::unchecked("lebron".to_string()),
                amount: Uint128::new(5000),
            }],
            true,
            true,
            true,
            true,
            0,
        );
        assert_eq!(init_result.unwrap(), Response::default());

        let constants = Constants::load(&deps.storage).unwrap();
        assert_eq!(TotalSupplyStore::load(&deps.storage).unwrap(), 5000);
        assert_eq!(
            ContractStatusStore::load(&deps.storage).unwrap(),
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
    fn test_total_supply_overflow() {
        let (init_result, _deps) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("lebron".to_string()),
            amount: Uint128::new(u128::max_value()),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result, _deps) = init_helper(vec![
            InitialBalance {
                address: Addr::unchecked("lebron".to_string()),
                amount: Uint128::new(u128::max_value()),
            },
            InitialBalance {
                address: Addr::unchecked("giannis".to_string()),
                amount: Uint128::new(1),
            },
        ]);
        let error = extract_error_msg(init_result);
        assert_eq!(
            error,
            "The sum of all initial balances exceeds the maximum possible total supply"
        );
    }

    // Handle tests

    #[test]
    fn test_handle_transfer() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(1000),
            memo: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let bob_addr = Addr::unchecked("bob".to_string());
        let alice_addr = Addr::unchecked("alice".to_string());

        assert_eq!(5000 - 1000, BalancesStore::load(&deps.storage, &bob_addr));
        assert_eq!(1000, BalancesStore::load(&deps.storage, &alice_addr));

        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(10000),
            memo: None,
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
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::RegisterReceive {
            code_hash: "this_is_a_hash_of_a_code".to_string(),
            padding: None,
        };
        let info = mock_info("contract", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let handle_msg = ExecuteMsg::Send {
            recipient: Addr::unchecked("contract".to_string()),
            recipient_code_hash: None,
            amount: Uint128::new(100),
            memo: Some("my memo".to_string()),
            padding: None,
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
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::RegisterReceive {
            code_hash: "this_is_a_hash_of_a_code".to_string(),
            padding: None,
        };
        let info = mock_info("contract", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let hash = get_receiver_hash(&deps.storage, &Addr::unchecked("contract".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(hash, "this_is_a_hash_of_a_code".to_string());
    }

    #[test]
    fn test_handle_create_viewing_key() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::CreateViewingKey {
            entropy: "".to_string(),
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
            address: Addr::unchecked("bob".to_string()),
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
        let actual_vk = ViewingKeyObj("x".to_string().repeat(VIEWING_KEY_SIZE));
        let handle_msg = ExecuteMsg::SetViewingKey {
            key: actual_vk.0.clone(),
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
        // let bob_canonical = deps.as_mut().api.addr_canonicalize("bob").unwrap();

        let result = ViewingKey::check(&deps.storage, "bob", actual_vk.as_str());
        assert!(result.is_ok());

        // let saved_vk = read_viewing_key(&deps.storage, &bob_canonical).unwrap();
        // assert!(actual_vk.check_viewing_key(&saved_vk));
    }

    #[test]
    fn test_handle_transfer_from() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Transfer before allowance
        let handle_msg = ExecuteMsg::TransferFrom {
            owner: Addr::unchecked("bob".to_string()),
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(2500),
            memo: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Transfer more than allowance
        let handle_msg = ExecuteMsg::IncreaseAllowance {
            spender: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(2000),
            padding: None,
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
            owner: Addr::unchecked("bob".to_string()),
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(2500),
            memo: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Transfer after allowance expired
        let handle_msg = ExecuteMsg::TransferFrom {
            owner: Addr::unchecked("bob".to_string()),
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(2000),
            memo: None,
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
                },
                transaction: Some(TransactionInfo { index: 3 }),
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
            owner: Addr::unchecked("bob".to_string()),
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(2000),
            memo: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let bob_canonical = Addr::unchecked("bob".to_string());
        let alice_canonical = Addr::unchecked("alice".to_string());

        let bob_balance = BalancesStore::load(&deps.storage, &bob_canonical);
        let alice_balance = BalancesStore::load(&deps.storage, &alice_canonical);
        assert_eq!(bob_balance, 5000 - 2000);
        assert_eq!(alice_balance, 2000);
        let total_supply = TotalSupplyStore::load(&deps.storage).unwrap();
        assert_eq!(total_supply, 5000);

        // Second send more than allowance
        let handle_msg = ExecuteMsg::TransferFrom {
            owner: Addr::unchecked("bob".to_string()),
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(1),
            memo: None,
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
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Send before allowance
        let handle_msg = ExecuteMsg::SendFrom {
            owner: Addr::unchecked("bob".to_string()),
            recipient: Addr::unchecked("alice".to_string()),
            recipient_code_hash: None,
            amount: Uint128::new(2500),
            memo: None,
            msg: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Send more than allowance
        let handle_msg = ExecuteMsg::IncreaseAllowance {
            spender: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(2000),
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
            owner: Addr::unchecked("bob".to_string()),
            recipient: Addr::unchecked("alice".to_string()),
            recipient_code_hash: None,
            amount: Uint128::new(2500),
            memo: None,
            msg: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Sanity check
        let handle_msg = ExecuteMsg::RegisterReceive {
            code_hash: "lolz".to_string(),
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
            owner: Addr::unchecked("bob".to_string()),
            recipient: Addr::unchecked("contract".to_string()),
            recipient_code_hash: None,
            amount: Uint128::new(2000),
            memo: Some("my memo".to_string()),
            msg: Some(send_msg),
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
            &snip20_msg
                .into_cosmos_submsg(
                    "lolz".to_string(),
                    Addr::unchecked("contract".to_string()),
                    0
                )
                .unwrap()
        ));
        let bob_canonical = Addr::unchecked("bob".to_string());
        let contract_canonical = Addr::unchecked("contract".to_string());
        let bob_balance = BalancesStore::load(&deps.storage, &bob_canonical);
        let contract_balance = BalancesStore::load(&deps.storage, &contract_canonical);
        assert_eq!(bob_balance, 5000 - 2000);
        assert_eq!(contract_balance, 2000);
        let total_supply = TotalSupplyStore::load(&deps.storage).unwrap();
        assert_eq!(total_supply, 5000);

        // Second send more than allowance
        let handle_msg = ExecuteMsg::SendFrom {
            owner: Addr::unchecked("bob".to_string()),
            recipient: Addr::unchecked("alice".to_string()),
            recipient_code_hash: None,
            amount: Uint128::new(1),
            memo: None,
            msg: None,
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
                address: Addr::unchecked("bob".to_string()),
                amount: Uint128::new(10000),
            }],
            false,
            false,
            false,
            true,
            0,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(10000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when burn disabled
        let handle_msg = ExecuteMsg::BurnFrom {
            owner: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(2500),
            memo: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Burn functionality is not enabled for this token."));

        // Burn before allowance
        let handle_msg = ExecuteMsg::BurnFrom {
            owner: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(2500),
            memo: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Burn more than allowance
        let handle_msg = ExecuteMsg::IncreaseAllowance {
            spender: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(2000),
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
        let handle_msg = ExecuteMsg::BurnFrom {
            owner: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(2500),
            memo: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Sanity check
        let handle_msg = ExecuteMsg::BurnFrom {
            owner: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(2000),
            memo: None,
            padding: None,
        };
        let info = mock_info("alice", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let bob_canonical = Addr::unchecked("bob".to_string());
        let bob_balance = BalancesStore::load(&deps.storage, &bob_canonical);
        assert_eq!(bob_balance, 10000 - 2000);
        let total_supply = TotalSupplyStore::load(&deps.storage).unwrap();
        assert_eq!(total_supply, 10000 - 2000);

        // Second burn more than allowance
        let handle_msg = ExecuteMsg::BurnFrom {
            owner: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(1),
            memo: None,
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
                    address: Addr::unchecked("bob".to_string()),
                    amount: Uint128::new(10000),
                },
                InitialBalance {
                    address: Addr::unchecked("jerry".to_string()),
                    amount: Uint128::new(10000),
                },
                InitialBalance {
                    address: Addr::unchecked("mike".to_string()),
                    amount: Uint128::new(10000),
                },
            ],
            false,
            false,
            false,
            true,
            0,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("bob".to_string()),
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
                owner: Addr::unchecked(name.to_string()),
                amount: Uint128::new(2500),
                memo: None,
            })
            .collect();
        let handle_msg = ExecuteMsg::BatchBurnFrom {
            actions,
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
                spender: Addr::unchecked("alice".to_string()),
                amount: Uint128::new(allowance_size),
                padding: None,
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
                owner: Addr::unchecked(name.to_string()),
                amount: Uint128::new(2500),
                memo: None,
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
                owner: Addr::unchecked(name.to_string()),
                amount: Uint128::new(*amount),
                memo: None,
            })
            .collect();

        let handle_msg = ExecuteMsg::BatchBurnFrom {
            actions,
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
            let name_canon = Addr::unchecked(name.to_string());
            let balance = BalancesStore::load(&deps.storage, &name_canon);
            assert_eq!(balance, 10000 - amount);
        }
        let total_supply = TotalSupplyStore::load(&deps.storage).unwrap();
        assert_eq!(total_supply, 10000 * 3 - (200 + 300 + 400));

        // Burn the rest of the allowance
        let actions: Vec<_> = [("bob", 200_u128), ("jerry", 300), ("mike", 400)]
            .iter()
            .map(|(name, amount)| batch::BurnFromAction {
                owner: Addr::unchecked(name.to_string()),
                amount: Uint128::new(allowance_size - *amount),
                memo: None,
            })
            .collect();

        let handle_msg = ExecuteMsg::BatchBurnFrom {
            actions,
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
            let name_canon = Addr::unchecked(name.to_string());
            let balance = BalancesStore::load(&deps.storage, &name_canon);
            assert_eq!(balance, 10000 - allowance_size);
        }
        let total_supply = TotalSupplyStore::load(&deps.storage).unwrap();
        assert_eq!(total_supply, 3 * (10000 - allowance_size));

        // Second burn more than allowance
        let actions: Vec<_> = ["bob", "jerry", "mike"]
            .iter()
            .map(|name| batch::BurnFromAction {
                owner: Addr::unchecked(name.to_string()),
                amount: Uint128::new(1),
                memo: None,
            })
            .collect();
        let handle_msg = ExecuteMsg::BatchBurnFrom {
            actions,
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
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::DecreaseAllowance {
            spender: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(2000),
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
            spender: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(2000),
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

        let handle_msg = ExecuteMsg::DecreaseAllowance {
            spender: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(50),
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
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::IncreaseAllowance {
            spender: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(2000),
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
            spender: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(2000),
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
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::ChangeAdmin {
            address: Addr::unchecked("bob".to_string()),
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let admin = Constants::load(&deps.storage).unwrap().admin;
        assert_eq!(admin, Addr::unchecked("bob".to_string()));
    }

    #[test]
    fn test_handle_set_contract_status() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("admin".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatusLevel::StopAll,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let contract_status = ContractStatusStore::load(&deps.storage).unwrap();
        assert!(matches!(
            contract_status,
            ContractStatusLevel::StopAll { .. }
        ));
    }

    #[test]
    fn test_handle_redeem() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: Addr::unchecked("butler".to_string()),
                amount: Uint128::new(5000),
            }],
            false,
            true,
            false,
            false,
            1000,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result_no_reserve, mut deps_no_reserve) = init_helper_with_config(
            vec![InitialBalance {
                address: Addr::unchecked("butler".to_string()),
                amount: Uint128::new(5000),
            }],
            false,
            true,
            false,
            false,
            0,
        );
        assert!(
            init_result_no_reserve.is_ok(),
            "Init failed: {}",
            init_result_no_reserve.err().unwrap()
        );

        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("butler".to_string()),
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
            padding: None,
        };
        let info = mock_info("butler", &[]);

        let handle_result = execute(deps_no_reserve.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains(
            "You are trying to redeem for more SCRT than the token has in its deposit reserve."
        ));

        let handle_msg = ExecuteMsg::Redeem {
            amount: Uint128::new(1000),
            denom: None,
            padding: None,
        };
        let info = mock_info("butler", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let canonical = Addr::unchecked("butler".to_string());
        assert_eq!(BalancesStore::load(&deps.storage, &canonical), 4000)
    }

    #[test]
    fn test_handle_deposit() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: Addr::unchecked("lebron".to_string()),
                amount: Uint128::new(5000),
            }],
            true,
            false,
            false,
            false,
            0,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("lebron".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when deposit disabled
        let handle_msg = ExecuteMsg::Deposit { padding: None };
        let info = mock_info(
            "lebron",
            &[Coin {
                denom: "uscrt".to_string(),
                amount: Uint128::new(1000),
            }],
        );

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Deposit functionality is not enabled for this token."));

        let handle_msg = ExecuteMsg::Deposit { padding: None };

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

        let canonical = Addr::unchecked("lebron".to_string());
        assert_eq!(BalancesStore::load(&deps.storage, &canonical), 6000)
    }

    #[test]
    fn test_handle_burn() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: Addr::unchecked("lebron".to_string()),
                amount: Uint128::new(5000),
            }],
            false,
            false,
            false,
            true,
            0,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("lebron".to_string()),
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
            padding: None,
        };
        let info = mock_info("lebron", &[]);

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Burn functionality is not enabled for this token."));

        let supply = TotalSupplyStore::load(&deps.storage).unwrap();
        let burn_amount: u128 = 100;
        let handle_msg = ExecuteMsg::Burn {
            amount: Uint128::new(burn_amount),
            memo: None,
            padding: None,
        };
        let info = mock_info("lebron", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let new_supply = TotalSupplyStore::load(&deps.storage).unwrap();
        assert_eq!(new_supply, supply - burn_amount);
    }

    #[test]
    fn test_handle_mint() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: Addr::unchecked("lebron".to_string()),
                amount: Uint128::new(5000),
            }],
            false,
            false,
            true,
            false,
            0,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("lebron".to_string()),
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
            recipient: Addr::unchecked("lebron".to_string()),
            amount: Uint128::new(mint_amount),
            memo: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Mint functionality is not enabled for this token"));

        let supply = TotalSupplyStore::load(&deps.storage).unwrap();
        let mint_amount: u128 = 100;
        let handle_msg = ExecuteMsg::Mint {
            recipient: Addr::unchecked("lebron".to_string()),
            amount: Uint128::new(mint_amount),
            memo: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let new_supply = TotalSupplyStore::load(&deps.storage).unwrap();
        assert_eq!(new_supply, supply + mint_amount);
    }

    #[test]
    fn test_handle_admin_commands() {
        let admin_err = "Admin commands can only be run from admin address".to_string();
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: Addr::unchecked("lebron".to_string()),
                amount: Uint128::new(5000),
            }],
            false,
            false,
            true,
            false,
            0,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let pause_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatusLevel::StopAllButRedeems,
            padding: None,
        };
        let info = mock_info("not_admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, pause_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));

        let mint_msg = ExecuteMsg::AddMinters {
            minters: vec![Addr::unchecked("not_admin".to_string())],
            padding: None,
        };
        let info = mock_info("not_admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, mint_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));

        let mint_msg = ExecuteMsg::RemoveMinters {
            minters: vec![Addr::unchecked("admin".to_string())],
            padding: None,
        };
        let info = mock_info("not_admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, mint_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));

        let mint_msg = ExecuteMsg::SetMinters {
            minters: vec![Addr::unchecked("not_admin".to_string())],
            padding: None,
        };
        let info = mock_info("not_admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, mint_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));

        let change_admin_msg = ExecuteMsg::ChangeAdmin {
            address: Addr::unchecked("not_admin".to_string()),
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
                address: Addr::unchecked("lebron".to_string()),
                amount: Uint128::new(5000),
            }],
            false,
            true,
            false,
            false,
            5000,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let pause_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatusLevel::StopAllButRedeems,
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
            recipient: Addr::unchecked("account".to_string()),
            amount: Uint128::new(123),
            memo: None,
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
            denom: None,
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
            address: Addr::unchecked("lebron".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let pause_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatusLevel::StopAll,
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
            recipient: Addr::unchecked("account".to_string()),
            amount: Uint128::new(123),
            memo: None,
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
            denom: None,
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
                address: Addr::unchecked("bob".to_string()),
                amount: Uint128::new(5000),
            }],
            false,
            false,
            true,
            false,
            0,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // try when mint disabled
        let handle_msg = ExecuteMsg::SetMinters {
            minters: vec![Addr::unchecked("bob".to_string())],
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Mint functionality is not enabled for this token"));

        let handle_msg = ExecuteMsg::SetMinters {
            minters: vec![Addr::unchecked("bob".to_string())],
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Admin commands can only be run from admin address"));

        let handle_msg = ExecuteMsg::SetMinters {
            minters: vec![Addr::unchecked("bob".to_string())],
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Mint {
            recipient: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(100),
            memo: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Mint {
            recipient: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(100),
            memo: None,
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
                address: Addr::unchecked("bob".to_string()),
                amount: Uint128::new(5000),
            }],
            false,
            false,
            true,
            false,
            0,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // try when mint disabled
        let handle_msg = ExecuteMsg::AddMinters {
            minters: vec![Addr::unchecked("bob".to_string())],
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Mint functionality is not enabled for this token"));

        let handle_msg = ExecuteMsg::AddMinters {
            minters: vec![Addr::unchecked("bob".to_string())],
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Admin commands can only be run from admin address"));

        let handle_msg = ExecuteMsg::AddMinters {
            minters: vec![Addr::unchecked("bob".to_string())],
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Mint {
            recipient: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(100),
            memo: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Mint {
            recipient: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(100),
            memo: None,
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
                address: Addr::unchecked("bob".to_string()),
                amount: Uint128::new(5000),
            }],
            false,
            false,
            true,
            false,
            0,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let (init_result_for_failure, mut deps_for_failure) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // try when mint disabled
        let handle_msg = ExecuteMsg::RemoveMinters {
            minters: vec![Addr::unchecked("bob".to_string())],
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps_for_failure.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Mint functionality is not enabled for this token"));

        let handle_msg = ExecuteMsg::RemoveMinters {
            minters: vec![Addr::unchecked("admin".to_string())],
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Admin commands can only be run from admin address"));

        let handle_msg = ExecuteMsg::RemoveMinters {
            minters: vec![Addr::unchecked("admin".to_string())],
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Mint {
            recipient: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(100),
            memo: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("allowed to minter accounts only"));

        let handle_msg = ExecuteMsg::Mint {
            recipient: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(100),
            memo: None,
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("allowed to minter accounts only"));

        // Removing another extra time to ensure nothing funky happens
        let handle_msg = ExecuteMsg::RemoveMinters {
            minters: vec![Addr::unchecked("admin".to_string())],
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Mint {
            recipient: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(100),
            memo: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("allowed to minter accounts only"));

        let handle_msg = ExecuteMsg::Mint {
            recipient: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(100),
            memo: None,
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
            address: Addr::unchecked("giannis".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let no_vk_yet_query_msg = QueryMsg::Balance {
            address: Addr::unchecked("giannis".to_string()),
            key: "no_vk_yet".to_string(),
        };
        let query_result = query(deps.as_ref(), mock_env(), no_vk_yet_query_msg);
        let error = extract_error_msg(query_result);
        assert_eq!(
            error,
            "Wrong viewing key for this address or viewing key not set".to_string()
        );

        let create_vk_msg = ExecuteMsg::CreateViewingKey {
            entropy: "34".to_string(),
            padding: None,
        };
        let info = mock_info("giannis", &[]);
        let handle_response = execute(deps.as_mut(), mock_env(), info, create_vk_msg).unwrap();
        let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
            ExecuteAnswer::CreateViewingKey { key } => key,
            _ => panic!("Unexpected result from handle"),
        };

        let query_balance_msg = QueryMsg::Balance {
            address: Addr::unchecked("giannis".to_string()),
            key: vk.0,
        };

        let query_response = query(deps.as_ref(), mock_env(), query_balance_msg).unwrap();
        let balance = match from_binary(&query_response).unwrap() {
            QueryAnswer::Balance { amount } => amount,
            _ => panic!("Unexpected result from query"),
        };
        assert_eq!(balance, Uint128::new(5000));

        let wrong_vk_query_msg = QueryMsg::Balance {
            address: Addr::unchecked("giannis".to_string()),
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
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: Addr::unchecked("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
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
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: Addr::unchecked("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
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
            } => {
                assert_eq!(public_total_supply, true);
                assert_eq!(deposit_enabled, false);
                assert_eq!(redeem_enabled, false);
                assert_eq!(mint_enabled, true);
                assert_eq!(burn_enabled, false);
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
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: Addr::unchecked("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
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
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: Addr::unchecked("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
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
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: Addr::unchecked("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
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
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: Addr::unchecked("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: None,
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
            address: Addr::unchecked("giannis".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::IncreaseAllowance {
            spender: Addr::unchecked("lebron".to_string()),
            amount: Uint128::new(2000),
            padding: None,
            expiration: None,
        };
        let info = mock_info("giannis", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let vk1 = ViewingKeyObj("key1".to_string());
        let vk2 = ViewingKeyObj("key2".to_string());

        let query_msg = QueryMsg::Allowance {
            owner: Addr::unchecked("giannis".to_string()),
            spender: Addr::unchecked("lebron".to_string()),
            key: vk1.0.clone(),
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
            key: vk1.0.clone(),
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
            key: vk2.0.clone(),
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
            owner: Addr::unchecked("giannis".to_string()),
            spender: Addr::unchecked("lebron".to_string()),
            key: vk1.0.clone(),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let allowance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Allowance { allowance, .. } => allowance,
            _ => panic!("Unexpected"),
        };
        assert_eq!(allowance, Uint128::new(2000));

        let query_msg = QueryMsg::Allowance {
            owner: Addr::unchecked("giannis".to_string()),
            spender: Addr::unchecked("lebron".to_string()),
            key: vk2.0.clone(),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let allowance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Allowance { allowance, .. } => allowance,
            _ => panic!("Unexpected"),
        };
        assert_eq!(allowance, Uint128::new(2000));

        let query_msg = QueryMsg::Allowance {
            owner: Addr::unchecked("lebron".to_string()),
            spender: Addr::unchecked("giannis".to_string()),
            key: vk2.0.clone(),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let allowance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Allowance { allowance, .. } => allowance,
            _ => panic!("Unexpected"),
        };
        assert_eq!(allowance, Uint128::new(0));
    }

    #[test]
    fn test_query_balance() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::SetViewingKey {
            key: "key".to_string(),
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
            address: Addr::unchecked("bob".to_string()),
            key: "wrong_key".to_string(),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key"));

        let query_msg = QueryMsg::Balance {
            address: Addr::unchecked("bob".to_string()),
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
    fn test_query_transfer_history() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(1000),
            memo: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("banana".to_string()),
            amount: Uint128::new(500),
            memo: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("mango".to_string()),
            amount: Uint128::new(2500),
            memo: None,
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let query_msg = QueryMsg::TransferHistory {
            address: Addr::unchecked("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 0,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        // let a: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        // println!("{:?}", a);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert!(transfers.is_empty());

        let query_msg = QueryMsg::TransferHistory {
            address: Addr::unchecked("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 10,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 3);

        let query_msg = QueryMsg::TransferHistory {
            address: Addr::unchecked("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 2,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 2);

        let query_msg = QueryMsg::TransferHistory {
            address: Addr::unchecked("bob".to_string()),
            key: "key".to_string(),
            page: Some(1),
            page_size: 2,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 1);
    }

    #[test]
    fn test_query_transaction_history() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: Addr::unchecked("bob".to_string()),
                amount: Uint128::new(10000),
            }],
            true,
            true,
            true,
            true,
            1000,
        );
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = ExecuteMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Burn {
            amount: Uint128::new(1),
            memo: Some("my burn message".to_string()),
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
            denom: None,
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
            recipient: Addr::unchecked("bob".to_string()),
            amount: Uint128::new(100),
            memo: Some("my mint message".to_string()),
            padding: None,
        };
        let info = mock_info("admin", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = ExecuteMsg::Deposit { padding: None };
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
            recipient: Addr::unchecked("alice".to_string()),
            amount: Uint128::new(1000),
            memo: Some("my transfer message #1".to_string()),
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("banana".to_string()),
            amount: Uint128::new(500),
            memo: Some("my transfer message #2".to_string()),
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let handle_msg = ExecuteMsg::Transfer {
            recipient: Addr::unchecked("mango".to_string()),
            amount: Uint128::new(2500),
            memo: Some("my transfer message #3".to_string()),
            padding: None,
        };
        let info = mock_info("bob", &[]);

        let handle_result = execute(deps.as_mut(), mock_env(), info, handle_msg);

        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let query_msg = QueryMsg::TransferHistory {
            address: Addr::unchecked("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 10,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 3);

        let query_msg = QueryMsg::TransactionHistory {
            address: Addr::unchecked("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 10,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransactionHistory { txs, .. } => txs,
            other => panic!("Unexpected: {:?}", other),
        };

        use crate::transaction_history::{RichTx, TxAction};
        let expected_transfers = [
            RichTx {
                id: 8,
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
            RichTx {
                id: 7,
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
            RichTx {
                id: 6,
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
            RichTx {
                id: 5,
                action: TxAction::Deposit {},
                coins: Coin {
                    denom: "uscrt".to_string(),
                    amount: Uint128::new(1000),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            RichTx {
                id: 4,
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
            RichTx {
                id: 3,
                action: TxAction::Redeem {},
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128::new(1000),
                },
                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
            RichTx {
                id: 2,
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
            RichTx {
                id: 1,
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
