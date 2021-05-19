/// This contract implements SNIP-20 standard:
/// https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md
use cosmwasm_std::{
    log, to_binary, Api, BankMsg, Binary, CanonicalAddr, Coin, CosmosMsg, Env, Extern,
    HandleResponse, HumanAddr, InitResponse, Querier, QueryResult, ReadonlyStorage, StdError,
    StdResult, Storage, Uint128,
};

use crate::msg::{
    space_pad, ContractStatusLevel, HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg,
    ResponseStatus::Success,
};
use crate::rand::sha_256;
use crate::receiver::Snip20ReceiveMsg;
use crate::state::{
    get_receiver_hash, get_transfers, read_allowance, read_viewing_key, set_receiver_hash,
    store_transfer, write_allowance, write_viewing_key, Balances, Config, Constants,
    ReadonlyBalances, ReadonlyConfig,
};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

/// We make sure that responses from `handle` are padded to a multiple of this size.
pub const RESPONSE_BLOCK_SIZE: usize = 256;

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let init_config = msg.config();
    let mut total_supply: u128 = 0;
    {
        let mut balances = Balances::from_storage(&mut deps.storage);
        let initial_balances = msg.initial_balances.unwrap_or_default();
        for balance in initial_balances {
            let balance_address = deps.api.canonical_address(&balance.address)?;
            let amount = balance.amount.u128();
            balances.set_account_balance(&balance_address, amount);
            if let Some(new_total_supply) = total_supply.checked_add(amount) {
                total_supply = new_total_supply;
            } else {
                return Err(StdError::generic_err(
                    "The sum of all initial balances exceeds the maximum possible total supply",
                ));
            }
        }
    }

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

    let admin = msg.admin.unwrap_or(env.message.sender);

    let prng_seed_hashed = sha_256(&msg.prng_seed.0);

    let mut config = Config::from_storage(&mut deps.storage);
    config.set_constants(&Constants {
        name: msg.name,
        symbol: msg.symbol,
        decimals: msg.decimals,
        admin: admin.clone(),
        prng_seed: prng_seed_hashed.to_vec(),
        total_supply_is_public: init_config.public_total_supply(),
        deposit_is_enabled: init_config.deposit_enabled(),
        redeem_is_enabled: init_config.redeem_enabled(),
        mint_is_enabled: init_config.mint_enabled(),
        burn_is_enabled: init_config.burn_enabled(),
    })?;
    config.set_total_supply(total_supply);
    config.set_contract_status(ContractStatusLevel::NormalRun);
    let minters = if init_config.mint_enabled() {
        Vec::from([admin])
    } else {
        Vec::new()
    };
    config.set_minters(minters)?;

    Ok(InitResponse::default())
}

fn pad_response(response: StdResult<HandleResponse>) -> StdResult<HandleResponse> {
    response.map(|mut response| {
        response.data = response.data.map(|mut data| {
            space_pad(RESPONSE_BLOCK_SIZE, &mut data.0);
            data
        });
        response
    })
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    let contract_status = ReadonlyConfig::from_storage(&deps.storage).contract_status();

    match contract_status {
        ContractStatusLevel::StopAll | ContractStatusLevel::StopAllButRedeems => {
            let response = match msg {
                HandleMsg::SetContractStatus { level, .. } => set_contract_status(deps, env, level),
                HandleMsg::Redeem { amount, .. }
                    if contract_status == ContractStatusLevel::StopAllButRedeems =>
                {
                    try_redeem(deps, env, amount)
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
        HandleMsg::Deposit { .. } => try_deposit(deps, env),
        HandleMsg::Redeem { amount, .. } => try_redeem(deps, env, amount),

        // Base
        HandleMsg::Transfer {
            recipient, amount, ..
        } => try_transfer(deps, env, &recipient, amount),
        HandleMsg::Send {
            recipient,
            amount,
            msg,
            ..
        } => try_send(deps, env, &recipient, amount, msg),
        HandleMsg::Burn { amount, .. } => try_burn(deps, env, amount),
        HandleMsg::RegisterReceive { code_hash, .. } => try_register_receive(deps, env, code_hash),
        HandleMsg::CreateViewingKey { entropy, .. } => try_create_key(deps, env, entropy),
        HandleMsg::SetViewingKey { key, .. } => try_set_key(deps, env, key),

        // Allowance
        HandleMsg::IncreaseAllowance {
            spender,
            amount,
            expiration,
            ..
        } => try_increase_allowance(deps, env, spender, amount, expiration),
        HandleMsg::DecreaseAllowance {
            spender,
            amount,
            expiration,
            ..
        } => try_decrease_allowance(deps, env, spender, amount, expiration),
        HandleMsg::TransferFrom {
            owner,
            recipient,
            amount,
            ..
        } => try_transfer_from(deps, env, &owner, &recipient, amount),
        HandleMsg::SendFrom {
            owner,
            recipient,
            amount,
            msg,
            ..
        } => try_send_from(deps, env, &owner, &recipient, amount, msg),
        HandleMsg::BurnFrom { owner, amount, .. } => try_burn_from(deps, env, &owner, amount),

        // Mint
        HandleMsg::Mint {
            recipient, amount, ..
        } => try_mint(deps, env, recipient, amount),

        // Other
        HandleMsg::ChangeAdmin { address, .. } => change_admin(deps, env, address),
        HandleMsg::SetContractStatus { level, .. } => set_contract_status(deps, env, level),
        HandleMsg::AddMinters { minters, .. } => add_minters(deps, env, minters),
        HandleMsg::RemoveMinters { minters, .. } => remove_minters(deps, env, minters),
        HandleMsg::SetMinters { minters, .. } => set_minters(deps, env, minters),
    };

    pad_response(response)
}

pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    match msg {
        QueryMsg::TokenInfo {} => query_token_info(&deps.storage),
        QueryMsg::TokenConfig {} => query_token_config(&deps.storage),
        QueryMsg::ExchangeRate {} => query_exchange_rate(&deps.storage),
        QueryMsg::Minters { .. } => query_minters(deps),
        _ => authenticated_queries(deps, msg),
    }
}

pub fn authenticated_queries<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> QueryResult {
    let (addresses, key) = msg.get_validation_params();

    for address in addresses {
        let canonical_addr = deps.api.canonical_address(address)?;

        let expected_key = read_viewing_key(&deps.storage, &canonical_addr);

        if expected_key.is_none() {
            // Checking the key will take significant time. We don't want to exit immediately if it isn't set
            // in a way which will allow to time the command and determine if a viewing key doesn't exist
            key.check_viewing_key(&[0u8; VIEWING_KEY_SIZE]);
        } else if key.check_viewing_key(expected_key.unwrap().as_slice()) {
            return match msg {
                // Base
                QueryMsg::Balance { address, .. } => query_balance(&deps, &address),
                QueryMsg::TransferHistory {
                    address,
                    page,
                    page_size,
                    ..
                } => query_transactions(&deps, &address, page.unwrap_or(0), page_size),
                QueryMsg::Allowance { owner, spender, .. } => {
                    try_check_allowance(deps, owner, spender)
                }
                _ => panic!("This query type does not require authentication"),
            };
        }
    }

    Ok(to_binary(&QueryAnswer::ViewingKeyError {
        msg: "Wrong viewing key for this address or viewing key not set".to_string(),
    })?)
}

fn query_exchange_rate<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config = ReadonlyConfig::from_storage(storage);
    let constants = config.constants()?;

    if constants.deposit_is_enabled || constants.redeem_is_enabled {
        let rate: Uint128;
        let denom: String;
        // if token has more decimals than SCRT, you get magnitudes of SCRT per token
        if constants.decimals >= 6 {
            rate = Uint128(10u128.pow(constants.decimals as u32 - 6));
            denom = "SCRT".to_string();
        // if token has less decimals, you get magnitudes token for SCRT
        } else {
            rate = Uint128(10u128.pow(6 - constants.decimals as u32));
            denom = constants.symbol;
        }
        return to_binary(&QueryAnswer::ExchangeRate { rate, denom });
    }
    to_binary(&QueryAnswer::ExchangeRate {
        rate: Uint128(0),
        denom: String::new(),
    })
}

fn query_token_info<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config = ReadonlyConfig::from_storage(storage);
    let constants = config.constants()?;

    let total_supply = if constants.total_supply_is_public {
        Some(Uint128(config.total_supply()))
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

fn query_token_config<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config = ReadonlyConfig::from_storage(storage);
    let constants = config.constants()?;

    to_binary(&QueryAnswer::TokenConfig {
        public_total_supply: constants.total_supply_is_public,
        deposit_enabled: constants.deposit_is_enabled,
        redeem_enabled: constants.redeem_is_enabled,
        mint_enabled: constants.mint_is_enabled,
        burn_enabled: constants.burn_is_enabled,
    })
}

pub fn query_transactions<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    account: &HumanAddr,
    page: u32,
    page_size: u32,
) -> StdResult<Binary> {
    let address = deps.api.canonical_address(account).unwrap();
    let (txs, total) = get_transfers(&deps.api, &deps.storage, &address, page, page_size)?;

    let result = QueryAnswer::TransferHistory { txs, total: Some(total) };
    to_binary(&result)
}

pub fn query_balance<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    account: &HumanAddr,
) -> StdResult<Binary> {
    let address = deps.api.canonical_address(account)?;

    let amount = Uint128(ReadonlyBalances::from_storage(&deps.storage).account_amount(&address));
    let response = QueryAnswer::Balance { amount };
    to_binary(&response)
}

fn query_minters<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<Binary> {
    let minters = ReadonlyConfig::from_storage(&deps.storage).minters();

    let response = QueryAnswer::Minters { minters };
    to_binary(&response)
}

fn change_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: HumanAddr,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);

    check_if_admin(&config, &env.message.sender)?;

    let mut consts = config.constants()?;
    consts.admin = address;
    config.set_constants(&consts)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ChangeAdmin { status: Success })?),
    })
}

fn try_mint<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: HumanAddr,
    amount: Uint128,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);
    let constants = config.constants()?;
    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    let minters = config.minters();
    if !minters.contains(&env.message.sender) {
        return Err(StdError::generic_err(
            "Minting is allowed to minter accounts only",
        ));
    }

    let amount = amount.u128();

    let mut total_supply = config.total_supply();
    if let Some(new_total_supply) = total_supply.checked_add(amount) {
        total_supply = new_total_supply;
    } else {
        return Err(StdError::generic_err(
            "This mint attempt would increase the total supply above the supported maximum",
        ));
    }
    config.set_total_supply(total_supply);

    let receipient_account = &deps.api.canonical_address(&address)?;

    let mut balances = Balances::from_storage(&mut deps.storage);

    let mut account_balance = balances.balance(receipient_account);

    if let Some(new_balance) = account_balance.checked_add(amount) {
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

    balances.set_account_balance(receipient_account, account_balance);

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Mint { status: Success })?),
    };

    Ok(res)
}

pub fn try_set_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    key: String,
) -> StdResult<HandleResponse> {
    let vk = ViewingKey(key);

    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    write_viewing_key(&mut deps.storage, &message_sender, &vk);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetViewingKey { status: Success })?),
    })
}

pub fn try_create_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String,
) -> StdResult<HandleResponse> {
    let constants = ReadonlyConfig::from_storage(&deps.storage).constants()?;
    let prng_seed = constants.prng_seed;

    let key = ViewingKey::new(&env, &prng_seed, (&entropy).as_ref());

    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    write_viewing_key(&mut deps.storage, &message_sender, &key);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::CreateViewingKey { key })?),
    })
}

fn set_contract_status<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    status_level: ContractStatusLevel,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);

    check_if_admin(&config, &env.message.sender)?;

    config.set_contract_status(status_level);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetContractStatus {
            status: Success,
        })?),
    })
}

pub fn try_check_allowance<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    owner: HumanAddr,
    spender: HumanAddr,
) -> StdResult<Binary> {
    let owner_address = deps.api.canonical_address(&owner)?;
    let spender_address = deps.api.canonical_address(&spender)?;

    let allowance = read_allowance(&deps.storage, &owner_address, &spender_address)?;

    let response = QueryAnswer::Allowance {
        owner,
        spender,
        allowance: Uint128(allowance.amount),
        expiration: allowance.expiration,
    };
    to_binary(&response)
}

fn try_deposit<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let mut amount = Uint128::zero();

    for coin in &env.message.sent_funds {
        if coin.denom == "uscrt" {
            amount = coin.amount
        }
    }

    if amount.is_zero() {
        return Err(StdError::generic_err("No funds were sent to be deposited"));
    }

    let amount = amount.u128();

    let mut config = Config::from_storage(&mut deps.storage);
    let constants = config.constants()?;
    if !constants.deposit_is_enabled {
        return Err(StdError::generic_err(
            "Deposit functionality is not enabled for this token.",
        ));
    }
    let total_supply = config.total_supply();
    if let Some(total_supply) = total_supply.checked_add(amount) {
        config.set_total_supply(total_supply);
    } else {
        return Err(StdError::generic_err(
            "This deposit would overflow the currency's total supply",
        ));
    }

    let sender_address = deps.api.canonical_address(&env.message.sender)?;

    let mut balances = Balances::from_storage(&mut deps.storage);
    let account_balance = balances.balance(&sender_address);
    if let Some(account_balance) = account_balance.checked_add(amount) {
        balances.set_account_balance(&sender_address, account_balance);
    } else {
        return Err(StdError::generic_err(
            "This deposit would overflow your balance",
        ));
    }

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Deposit { status: Success })?),
    };

    Ok(res)
}

fn try_redeem<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    amount: Uint128,
) -> StdResult<HandleResponse> {
    let config = ReadonlyConfig::from_storage(&deps.storage);
    let constants = config.constants()?;
    if !constants.redeem_is_enabled {
        return Err(StdError::generic_err(
            "Redeem functionality is not enabled for this token.",
        ));
    }

    let sender_address = deps.api.canonical_address(&env.message.sender)?;
    let amount_raw = amount.u128();

    let mut balances = Balances::from_storage(&mut deps.storage);
    let account_balance = balances.balance(&sender_address);

    if let Some(account_balance) = account_balance.checked_sub(amount_raw) {
        balances.set_account_balance(&sender_address, account_balance);
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds to redeem: balance={}, required={}",
            account_balance, amount_raw
        )));
    }

    let mut config = Config::from_storage(&mut deps.storage);
    let total_supply = config.total_supply();
    if let Some(total_supply) = total_supply.checked_sub(amount_raw) {
        config.set_total_supply(total_supply);
    } else {
        return Err(StdError::generic_err(
            "You are tyring to redeem more tokens than what is available in the total supply",
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

    let res = HandleResponse {
        messages: vec![CosmosMsg::Bank(BankMsg::Send {
            from_address: env.contract.address,
            to_address: env.message.sender,
            amount: withdrawal_coins,
        })],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Redeem { status: Success })?),
    };

    Ok(res)
}

fn try_transfer_impl<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    recipient: &HumanAddr,
    amount: Uint128,
) -> StdResult<()> {
    let sender_address = deps.api.canonical_address(&env.message.sender)?;
    let recipient_address = deps.api.canonical_address(recipient)?;

    perform_transfer(
        &mut deps.storage,
        &sender_address,
        &recipient_address,
        amount.u128(),
    )?;

    let symbol = Config::from_storage(&mut deps.storage).constants()?.symbol;

    store_transfer(
        &mut deps.storage,
        &sender_address,
        &sender_address,
        &recipient_address,
        amount,
        symbol,
        env.block
    )?;

    Ok(())
}

fn try_transfer<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    recipient: &HumanAddr,
    amount: Uint128,
) -> StdResult<HandleResponse> {
    try_transfer_impl(deps, env, recipient, amount)?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Transfer { status: Success })?),
    };
    Ok(res)
}

fn try_add_receiver_api_callback<S: ReadonlyStorage>(
    messages: &mut Vec<CosmosMsg>,
    storage: &S,
    recipient: &HumanAddr,
    msg: Option<Binary>,
    sender: HumanAddr,
    from: HumanAddr,
    amount: Uint128,
) -> StdResult<()> {
    let receiver_hash = get_receiver_hash(storage, recipient);
    if let Some(receiver_hash) = receiver_hash {
        let receiver_hash = receiver_hash?;
        let receiver_msg = Snip20ReceiveMsg::new(sender, from, amount, msg);
        let callback_msg = receiver_msg.into_cosmos_msg(receiver_hash, recipient.clone())?;

        messages.push(callback_msg);
    }
    Ok(())
}

fn try_send<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    recipient: &HumanAddr,
    amount: Uint128,
    msg: Option<Binary>,
) -> StdResult<HandleResponse> {
    let sender = env.message.sender.clone();
    try_transfer_impl(deps, env, recipient, amount)?;

    let mut messages = vec![];

    try_add_receiver_api_callback(
        &mut messages,
        &deps.storage,
        recipient,
        msg,
        sender.clone(),
        sender,
        amount,
    )?;

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Send { status: Success })?),
    };
    Ok(res)
}

fn try_register_receive<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    code_hash: String,
) -> StdResult<HandleResponse> {
    set_receiver_hash(&mut deps.storage, &env.message.sender, code_hash);
    let res = HandleResponse {
        messages: vec![],
        log: vec![log("register_status", "success")],
        data: Some(to_binary(&HandleAnswer::RegisterReceive {
            status: Success,
        })?),
    };
    Ok(res)
}

fn insufficient_allowance(allowance: u128, required: u128) -> StdError {
    StdError::generic_err(format!(
        "insufficient allowance: allowance={}, required={}",
        allowance, required
    ))
}

fn try_transfer_from_impl<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    owner: &HumanAddr,
    recipient: &HumanAddr,
    amount: Uint128,
) -> StdResult<()> {
    let spender_address = deps.api.canonical_address(&env.message.sender)?;
    let owner_address = deps.api.canonical_address(owner)?;
    let recipient_address = deps.api.canonical_address(recipient)?;
    let amount_raw = amount.u128();

    let mut allowance = read_allowance(&deps.storage, &owner_address, &spender_address)?;

    if allowance.expiration.map(|ex| ex < env.block.time) == Some(true) {
        allowance.amount = 0;
        write_allowance(
            &mut deps.storage,
            &owner_address,
            &spender_address,
            allowance,
        )?;
        return Err(insufficient_allowance(0, amount_raw));
    }

    if let Some(new_allowance) = allowance.amount.checked_sub(amount_raw) {
        allowance.amount = new_allowance;
    } else {
        return Err(insufficient_allowance(allowance.amount, amount_raw));
    }

    write_allowance(
        &mut deps.storage,
        &owner_address,
        &spender_address,
        allowance,
    )?;
    perform_transfer(
        &mut deps.storage,
        &owner_address,
        &recipient_address,
        amount_raw,
    )?;

    let symbol = Config::from_storage(&mut deps.storage).constants()?.symbol;

    store_transfer(
        &mut deps.storage,
        &owner_address,
        &spender_address,
        &recipient_address,
        amount,
        symbol,
        env.block,
    )?;

    Ok(())
}

fn try_transfer_from<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    owner: &HumanAddr,
    recipient: &HumanAddr,
    amount: Uint128,
) -> StdResult<HandleResponse> {
    try_transfer_from_impl(deps, env, owner, recipient, amount)?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::TransferFrom { status: Success })?),
    };
    Ok(res)
}

fn try_send_from<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    owner: &HumanAddr,
    recipient: &HumanAddr,
    amount: Uint128,
    msg: Option<Binary>,
) -> StdResult<HandleResponse> {
    let sender = env.message.sender.clone();
    try_transfer_from_impl(deps, env, owner, recipient, amount)?;

    let mut messages = vec![];

    try_add_receiver_api_callback(
        &mut messages,
        &deps.storage,
        recipient,
        msg,
        sender,
        owner.clone(),
        amount,
    )?;

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SendFrom { status: Success })?),
    };
    Ok(res)
}

fn try_burn_from<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    owner: &HumanAddr,
    amount: Uint128,
) -> StdResult<HandleResponse> {
    let config = ReadonlyConfig::from_storage(&deps.storage);
    let constants = config.constants()?;
    if !constants.burn_is_enabled {
        return Err(StdError::generic_err(
            "Burn functionality is not enabled for this token.",
        ));
    }

    let spender_address = deps.api.canonical_address(&env.message.sender)?;
    let owner_address = deps.api.canonical_address(owner)?;
    let amount = amount.u128();

    let mut allowance = read_allowance(&deps.storage, &owner_address, &spender_address)?;

    if allowance.expiration.map(|ex| ex < env.block.time) == Some(true) {
        allowance.amount = 0;
        write_allowance(
            &mut deps.storage,
            &owner_address,
            &spender_address,
            allowance,
        )?;
        return Err(insufficient_allowance(0, amount));
    }

    if let Some(new_allowance) = allowance.amount.checked_sub(amount) {
        allowance.amount = new_allowance;
    } else {
        return Err(insufficient_allowance(allowance.amount, amount));
    }

    write_allowance(
        &mut deps.storage,
        &owner_address,
        &spender_address,
        allowance,
    )?;

    // subtract from owner account
    let mut balances = Balances::from_storage(&mut deps.storage);
    let mut account_balance = balances.balance(&owner_address);

    if let Some(new_balance) = account_balance.checked_sub(amount) {
        account_balance = new_balance;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds to burn: balance={}, required={}",
            account_balance, amount
        )));
    }
    balances.set_account_balance(&owner_address, account_balance);

    // remove from supply
    let mut config = Config::from_storage(&mut deps.storage);
    let mut total_supply = config.total_supply();
    if let Some(new_total_supply) = total_supply.checked_sub(amount) {
        total_supply = new_total_supply;
    } else {
        return Err(StdError::generic_err(
            "You're trying to burn more than is available in the total supply",
        ));
    }
    config.set_total_supply(total_supply);

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BurnFrom { status: Success })?),
    };

    Ok(res)
}

fn try_increase_allowance<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    spender: HumanAddr,
    amount: Uint128,
    expiration: Option<u64>,
) -> StdResult<HandleResponse> {
    let owner_address = deps.api.canonical_address(&env.message.sender)?;
    let spender_address = deps.api.canonical_address(&spender)?;

    let mut allowance = read_allowance(&deps.storage, &owner_address, &spender_address)?;
    allowance.amount = allowance.amount.saturating_add(amount.u128());
    if expiration.is_some() {
        allowance.expiration = expiration;
    }
    let new_amount = allowance.amount;
    write_allowance(
        &mut deps.storage,
        &owner_address,
        &spender_address,
        allowance,
    )?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::IncreaseAllowance {
            owner: env.message.sender,
            spender,
            allowance: Uint128(new_amount),
        })?),
    };
    Ok(res)
}

fn try_decrease_allowance<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    spender: HumanAddr,
    amount: Uint128,
    expiration: Option<u64>,
) -> StdResult<HandleResponse> {
    let owner_address = deps.api.canonical_address(&env.message.sender)?;
    let spender_address = deps.api.canonical_address(&spender)?;

    let mut allowance = read_allowance(&deps.storage, &owner_address, &spender_address)?;
    allowance.amount = allowance.amount.saturating_sub(amount.u128());
    if expiration.is_some() {
        allowance.expiration = expiration;
    }
    let new_amount = allowance.amount;
    write_allowance(
        &mut deps.storage,
        &owner_address,
        &spender_address,
        allowance,
    )?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::DecreaseAllowance {
            owner: env.message.sender,
            spender,
            allowance: Uint128(new_amount),
        })?),
    };
    Ok(res)
}

fn add_minters<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    minters_to_add: Vec<HumanAddr>,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);
    let constants = config.constants()?;
    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    check_if_admin(&config, &env.message.sender)?;

    config.add_minters(minters_to_add)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AddMinters { status: Success })?),
    })
}

fn remove_minters<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    minters_to_remove: Vec<HumanAddr>,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);
    let constants = config.constants()?;
    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    check_if_admin(&config, &env.message.sender)?;

    config.remove_minters(minters_to_remove)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RemoveMinters { status: Success })?),
    })
}

fn set_minters<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    minters_to_set: Vec<HumanAddr>,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);
    let constants = config.constants()?;
    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    check_if_admin(&config, &env.message.sender)?;

    config.set_minters(minters_to_set)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetMinters { status: Success })?),
    })
}

/// Burn tokens
///
/// Remove `amount` tokens from the system irreversibly, from signer account
///
/// @param amount the amount of money to burn
fn try_burn<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    amount: Uint128,
) -> StdResult<HandleResponse> {
    let config = ReadonlyConfig::from_storage(&deps.storage);
    let constants = config.constants()?;
    if !constants.burn_is_enabled {
        return Err(StdError::generic_err(
            "Burn functionality is not enabled for this token.",
        ));
    }

    let sender_address = deps.api.canonical_address(&env.message.sender)?;
    let amount = amount.u128();

    let mut balances = Balances::from_storage(&mut deps.storage);
    let mut account_balance = balances.balance(&sender_address);

    if let Some(new_account_balance) = account_balance.checked_sub(amount) {
        account_balance = new_account_balance;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds to burn: balance={}, required={}",
            account_balance, amount
        )));
    }

    balances.set_account_balance(&sender_address, account_balance);

    let mut config = Config::from_storage(&mut deps.storage);
    let mut total_supply = config.total_supply();
    if let Some(new_total_supply) = total_supply.checked_sub(amount) {
        total_supply = new_total_supply;
    } else {
        return Err(StdError::generic_err(
            "You're trying to burn more than is available in the total supply",
        ));
    }
    config.set_total_supply(total_supply);

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Burn { status: Success })?),
    };

    Ok(res)
}

fn perform_transfer<T: Storage>(
    store: &mut T,
    from: &CanonicalAddr,
    to: &CanonicalAddr,
    amount: u128,
) -> StdResult<()> {
    let mut balances = Balances::from_storage(store);

    let mut from_balance = balances.balance(from);
    if let Some(new_from_balance) = from_balance.checked_sub(amount) {
        from_balance = new_from_balance;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds: balance={}, required={}",
            from_balance, amount
        )));
    }
    balances.set_account_balance(from, from_balance);

    let mut to_balance = balances.balance(to);
    to_balance = to_balance.checked_add(amount).ok_or_else(|| {
        StdError::generic_err("This tx will literally make them too rich. Try transferring less")
    })?;
    balances.set_account_balance(to, to_balance);

    Ok(())
}

fn is_admin<S: Storage>(config: &Config<S>, account: &HumanAddr) -> StdResult<bool> {
    let consts = config.constants()?;
    if &consts.admin != account {
        return Ok(false);
    }

    Ok(true)
}

fn check_if_admin<S: Storage>(config: &Config<S>, account: &HumanAddr) -> StdResult<()> {
    if !is_admin(config, account)? {
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

// pub fn migrate<S: Storage, A: Api, Q: Querier>(
//     _deps: &mut Extern<S, A, Q>,
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
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{from_binary, BlockInfo, ContractInfo, MessageInfo, QueryResponse, WasmMsg};
    use std::any::Any;

    // Helper functions

    fn init_helper(
        initial_balances: Vec<InitialBalance>,
    ) -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);

        let init_msg = InitMsg {
            name: "sec-sec".to_string(),
            admin: Some(HumanAddr("admin".to_string())),
            symbol: "SECSEC".to_string(),
            decimals: 8,
            initial_balances: Some(initial_balances),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: None,
        };

        (init(&mut deps, env, init_msg), deps)
    }

    fn init_helper_with_config(
        initial_balances: Vec<InitialBalance>,
        enable_deposit: bool,
        enable_redeem: bool,
        enable_mint: bool,
        enable_burn: bool,
        contract_bal: u128,
    ) -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(
            20,
            &[Coin {
                denom: "uscrt".to_string(),
                amount: Uint128(contract_bal),
            }],
        );

        let env = mock_env("instantiator", &[]);
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
        let init_msg = InitMsg {
            name: "sec-sec".to_string(),
            admin: Some(HumanAddr("admin".to_string())),
            symbol: "SECSEC".to_string(),
            decimals: 8,
            initial_balances: Some(initial_balances),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };

        (init(&mut deps, env, init_msg), deps)
    }

    /// Will return a ViewingKey only for the first account in `initial_balances`
    fn _auth_query_helper(
        initial_balances: Vec<InitialBalance>,
    ) -> (ViewingKey, Extern<MockStorage, MockApi, MockQuerier>) {
        let (init_result, mut deps) = init_helper(initial_balances.clone());
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let account = initial_balances[0].address.clone();
        let create_vk_msg = HandleMsg::CreateViewingKey {
            entropy: "42".to_string(),
            padding: None,
        };
        let handle_response = handle(&mut deps, mock_env(account.0, &[]), create_vk_msg).unwrap();
        let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
            HandleAnswer::CreateViewingKey { key } => key,
            _ => panic!("Unexpected result from handle"),
        };

        (vk, deps)
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

    fn ensure_success(handle_result: HandleResponse) -> bool {
        let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

        match handle_result {
            HandleAnswer::Deposit { status }
            | HandleAnswer::Redeem { status }
            | HandleAnswer::Transfer { status }
            | HandleAnswer::Send { status }
            | HandleAnswer::Burn { status }
            | HandleAnswer::RegisterReceive { status }
            | HandleAnswer::SetViewingKey { status }
            | HandleAnswer::TransferFrom { status }
            | HandleAnswer::SendFrom { status }
            | HandleAnswer::BurnFrom { status }
            | HandleAnswer::Mint { status }
            | HandleAnswer::ChangeAdmin { status }
            | HandleAnswer::SetContractStatus { status }
            | HandleAnswer::SetMinters { status }
            | HandleAnswer::AddMinters { status }
            | HandleAnswer::RemoveMinters { status } => {
                matches!(status, ResponseStatus::Success { .. })
            }
            _ => panic!("HandleAnswer not supported for success extraction"),
        }
    }

    // Init tests

    #[test]
    fn test_init_sanity() {
        let (init_result, deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("lebron".to_string()),
            amount: Uint128(5000),
        }]);
        assert_eq!(init_result.unwrap(), InitResponse::default());

        let config = ReadonlyConfig::from_storage(&deps.storage);
        let constants = config.constants().unwrap();
        assert_eq!(config.total_supply(), 5000);
        assert_eq!(config.contract_status(), ContractStatusLevel::NormalRun);
        assert_eq!(constants.name, "sec-sec".to_string());
        assert_eq!(constants.admin, HumanAddr("admin".to_string()));
        assert_eq!(constants.symbol, "SECSEC".to_string());
        assert_eq!(constants.decimals, 8);
        assert_eq!(
            constants.prng_seed,
            sha_256("lolz fun yay".to_owned().as_bytes())
        );
        assert_eq!(constants.total_supply_is_public, false);
    }

    #[test]
    fn test_init_with_config_sanity() {
        let (init_result, deps) = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("lebron".to_string()),
                amount: Uint128(5000),
            }],
            true,
            true,
            true,
            true,
            0,
        );
        assert_eq!(init_result.unwrap(), InitResponse::default());

        let config = ReadonlyConfig::from_storage(&deps.storage);
        let constants = config.constants().unwrap();
        assert_eq!(config.total_supply(), 5000);
        assert_eq!(config.contract_status(), ContractStatusLevel::NormalRun);
        assert_eq!(constants.name, "sec-sec".to_string());
        assert_eq!(constants.admin, HumanAddr("admin".to_string()));
        assert_eq!(constants.symbol, "SECSEC".to_string());
        assert_eq!(constants.decimals, 8);
        assert_eq!(
            constants.prng_seed,
            sha_256("lolz fun yay".to_owned().as_bytes())
        );
        assert_eq!(constants.total_supply_is_public, false);
        assert_eq!(constants.deposit_is_enabled, true);
        assert_eq!(constants.redeem_is_enabled, true);
        assert_eq!(constants.mint_is_enabled, true);
        assert_eq!(constants.burn_is_enabled, true);
    }

    #[test]
    fn test_total_supply_overflow() {
        let (init_result, _deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("lebron".to_string()),
            amount: Uint128(u128::max_value()),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let (init_result, _deps) = init_helper(vec![
            InitialBalance {
                address: HumanAddr("lebron".to_string()),
                amount: Uint128(u128::max_value()),
            },
            InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: Uint128(1),
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
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::Transfer {
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(1000),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let alice_canonical = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let balances = ReadonlyBalances::from_storage(&deps.storage);
        assert_eq!(5000 - 1000, balances.account_amount(&bob_canonical));
        assert_eq!(1000, balances.account_amount(&alice_canonical));

        let handle_msg = HandleMsg::Transfer {
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(10000),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient funds"));
    }

    #[test]
    fn test_handle_send() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::RegisterReceive {
            code_hash: "this_is_a_hash_of_a_code".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("contract", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let handle_msg = HandleMsg::Send {
            recipient: HumanAddr("contract".to_string()),
            amount: Uint128(100),
            padding: None,
            msg: Some(to_binary("hey hey you you").unwrap()),
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result.clone()));
        assert!(result.messages.contains(&CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: HumanAddr("contract".to_string()),
            callback_code_hash: "this_is_a_hash_of_a_code".to_string(),
            msg: Snip20ReceiveMsg::new(
                HumanAddr("bob".to_string()),
                HumanAddr("bob".to_string()),
                Uint128(100),
                Some(to_binary("hey hey you you").unwrap())
            )
            .into_binary()
            .unwrap(),
            send: vec![]
        })));
    }

    #[test]
    fn test_handle_register_receive() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::RegisterReceive {
            code_hash: "this_is_a_hash_of_a_code".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("contract", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let hash = get_receiver_hash(&deps.storage, &HumanAddr("contract".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(hash, "this_is_a_hash_of_a_code".to_string());
    }

    #[test]
    fn test_handle_create_viewing_key() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let answer: HandleAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();

        let key = match answer {
            HandleAnswer::CreateViewingKey { key } => key,
            _ => panic!("NOPE"),
        };
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let saved_vk = read_viewing_key(&deps.storage, &bob_canonical).unwrap();
        assert!(key.check_viewing_key(saved_vk.as_slice()));
    }

    #[test]
    fn test_handle_set_viewing_key() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Set VK
        let handle_msg = HandleMsg::SetViewingKey {
            key: "hi lol".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
            .unwrap(),
        );

        // Set valid VK
        let actual_vk = ViewingKey("x".to_string().repeat(VIEWING_KEY_SIZE));
        let handle_msg = HandleMsg::SetViewingKey {
            key: actual_vk.0.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey { status: Success }).unwrap(),
        );
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let saved_vk = read_viewing_key(&deps.storage, &bob_canonical).unwrap();
        assert!(actual_vk.check_viewing_key(&saved_vk));
    }

    #[test]
    fn test_handle_transfer_from() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Transfer before allowance
        let handle_msg = HandleMsg::TransferFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(2500),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Transfer more than allowance
        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: Some(1_571_797_420),
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let handle_msg = HandleMsg::TransferFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(2500),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Transfer after allowance expired
        let handle_msg = HandleMsg::TransferFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 12_345,
                    time: 1_571_797_420,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("bob".to_string()),
                    sent_funds: vec![],
                },
                contract: ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Sanity check
        let handle_msg = HandleMsg::TransferFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let alice_canonical = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let bob_balance = crate::state::ReadonlyBalances::from_storage(&deps.storage)
            .account_amount(&bob_canonical);
        let alice_balance = crate::state::ReadonlyBalances::from_storage(&deps.storage)
            .account_amount(&alice_canonical);
        assert_eq!(bob_balance, 5000 - 2000);
        assert_eq!(alice_balance, 2000);
        let total_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        assert_eq!(total_supply, 5000);

        // Second send more than allowance
        let handle_msg = HandleMsg::TransferFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(1),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));
    }

    #[test]
    fn test_handle_send_from() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Send before allowance
        let handle_msg = HandleMsg::SendFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(2500),
            msg: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Send more than allowance
        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let handle_msg = HandleMsg::SendFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(2500),
            msg: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Sanity check
        let handle_msg = HandleMsg::RegisterReceive {
            code_hash: "lolz".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("contract", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let send_msg = Binary::from(r#"{ "some_msg": { "some_key": "some_val" } }"#.as_bytes());
        let snip20_msg = Snip20ReceiveMsg::new(
            HumanAddr("alice".to_string()),
            HumanAddr("bob".to_string()),
            Uint128(2000),
            Some(send_msg.clone()),
        );
        let handle_msg = HandleMsg::SendFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("contract".to_string()),
            amount: Uint128(2000),
            msg: Some(send_msg),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        assert!(handle_result.unwrap().messages.contains(
            &snip20_msg
                .into_cosmos_msg("lolz".to_string(), HumanAddr("contract".to_string()))
                .unwrap()
        ));
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let contract_canonical = deps
            .api
            .canonical_address(&HumanAddr("contract".to_string()))
            .unwrap();
        let bob_balance = crate::state::ReadonlyBalances::from_storage(&deps.storage)
            .account_amount(&bob_canonical);
        let contract_balance = crate::state::ReadonlyBalances::from_storage(&deps.storage)
            .account_amount(&contract_canonical);
        assert_eq!(bob_balance, 5000 - 2000);
        assert_eq!(contract_balance, 2000);
        let total_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        assert_eq!(total_supply, 5000);

        // Second send more than allowance
        let handle_msg = HandleMsg::SendFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(1),
            msg: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));
    }

    #[test]
    fn test_handle_burn_from() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("bob".to_string()),
                amount: Uint128(10000),
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
            address: HumanAddr("bob".to_string()),
            amount: Uint128(10000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when burn disabled
        let handle_msg = HandleMsg::BurnFrom {
            owner: HumanAddr("bob".to_string()),
            amount: Uint128(2500),
            padding: None,
        };
        let handle_result = handle(&mut deps_for_failure, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Burn functionality is not enabled for this token."));

        // Burn before allowance
        let handle_msg = HandleMsg::BurnFrom {
            owner: HumanAddr("bob".to_string()),
            amount: Uint128(2500),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Burn more than allowance
        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let handle_msg = HandleMsg::BurnFrom {
            owner: HumanAddr("bob".to_string()),
            amount: Uint128(2500),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Sanity check
        let handle_msg = HandleMsg::BurnFrom {
            owner: HumanAddr("bob".to_string()),
            amount: Uint128(2000),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let bob_balance = crate::state::ReadonlyBalances::from_storage(&deps.storage)
            .account_amount(&bob_canonical);
        assert_eq!(bob_balance, 10000 - 2000);
        let total_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        assert_eq!(total_supply, 10000 - 2000);

        // Second burn more than allowance
        let handle_msg = HandleMsg::BurnFrom {
            owner: HumanAddr("bob".to_string()),
            amount: Uint128(1),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));
    }

    #[test]
    fn test_handle_decrease_allowance() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::DecreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let alice_canonical = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();

        let allowance = read_allowance(&deps.storage, &bob_canonical, &alice_canonical).unwrap();
        assert_eq!(
            allowance,
            crate::state::Allowance {
                amount: 0,
                expiration: None
            }
        );

        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let handle_msg = HandleMsg::DecreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(50),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let allowance = read_allowance(&deps.storage, &bob_canonical, &alice_canonical).unwrap();
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
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let alice_canonical = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();

        let allowance = read_allowance(&deps.storage, &bob_canonical, &alice_canonical).unwrap();
        assert_eq!(
            allowance,
            crate::state::Allowance {
                amount: 2000,
                expiration: None
            }
        );

        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let allowance = read_allowance(&deps.storage, &bob_canonical, &alice_canonical).unwrap();
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
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::ChangeAdmin {
            address: HumanAddr("bob".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let admin = ReadonlyConfig::from_storage(&deps.storage)
            .constants()
            .unwrap()
            .admin;
        assert_eq!(admin, HumanAddr("bob".to_string()));
    }

    #[test]
    fn test_handle_set_contract_status() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("admin".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::SetContractStatus {
            level: ContractStatusLevel::StopAll,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let contract_status = ReadonlyConfig::from_storage(&deps.storage).contract_status();
        assert!(matches!(
            contract_status,
            ContractStatusLevel::StopAll { .. }
        ));
    }

    #[test]
    fn test_handle_redeem() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("butler".to_string()),
                amount: Uint128(5000),
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
                address: HumanAddr("butler".to_string()),
                amount: Uint128(5000),
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
            address: HumanAddr("butler".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when redeem disabled
        let handle_msg = HandleMsg::Redeem {
            amount: Uint128(1000),
            denom: None,
            padding: None,
        };
        let handle_result = handle(&mut deps_for_failure, mock_env("butler", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Redeem functionality is not enabled for this token."));

        // try to redeem when contract has 0 balance
        let handle_msg = HandleMsg::Redeem {
            amount: Uint128(1000),
            denom: None,
            padding: None,
        };
        let handle_result = handle(&mut deps_no_reserve, mock_env("butler", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains(
            "You are trying to redeem for more SCRT than the token has in its deposit reserve."
        ));

        let handle_msg = HandleMsg::Redeem {
            amount: Uint128(1000),
            denom: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("butler", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let balances = ReadonlyBalances::from_storage(&deps.storage);
        let canonical = deps
            .api
            .canonical_address(&HumanAddr("butler".to_string()))
            .unwrap();
        assert_eq!(balances.account_amount(&canonical), 4000)
    }

    #[test]
    fn test_handle_deposit() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("lebron".to_string()),
                amount: Uint128(5000),
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
            address: HumanAddr("lebron".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when deposit disabled
        let handle_msg = HandleMsg::Deposit { padding: None };
        let handle_result = handle(
            &mut deps_for_failure,
            mock_env(
                "lebron",
                &[Coin {
                    denom: "uscrt".to_string(),
                    amount: Uint128(1000),
                }],
            ),
            handle_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Deposit functionality is not enabled for this token."));

        let handle_msg = HandleMsg::Deposit { padding: None };
        let handle_result = handle(
            &mut deps,
            mock_env(
                "lebron",
                &[Coin {
                    denom: "uscrt".to_string(),
                    amount: Uint128(1000),
                }],
            ),
            handle_msg,
        );
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let balances = ReadonlyBalances::from_storage(&deps.storage);
        let canonical = deps
            .api
            .canonical_address(&HumanAddr("lebron".to_string()))
            .unwrap();
        assert_eq!(balances.account_amount(&canonical), 6000)
    }

    #[test]
    fn test_handle_burn() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("lebron".to_string()),
                amount: Uint128(5000),
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
            address: HumanAddr("lebron".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when burn disabled
        let handle_msg = HandleMsg::Burn {
            amount: Uint128(100),
            padding: None,
        };
        let handle_result = handle(&mut deps_for_failure, mock_env("lebron", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Burn functionality is not enabled for this token."));

        let supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        let burn_amount: u128 = 100;
        let handle_msg = HandleMsg::Burn {
            amount: Uint128(burn_amount),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("lebron", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let new_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        assert_eq!(new_supply, supply - burn_amount);
    }

    #[test]
    fn test_handle_mint() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("lebron".to_string()),
                amount: Uint128(5000),
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
            address: HumanAddr("lebron".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // try to mint when mint is disabled
        let mint_amount: u128 = 100;
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("lebron".to_string()),
            amount: Uint128(mint_amount),
            padding: None,
        };
        let handle_result = handle(&mut deps_for_failure, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Mint functionality is not enabled for this token"));

        let supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        let mint_amount: u128 = 100;
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("lebron".to_string()),
            amount: Uint128(mint_amount),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let new_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        assert_eq!(new_supply, supply + mint_amount);
    }

    #[test]
    fn test_handle_admin_commands() {
        let admin_err = "Admin commands can only be run from admin address".to_string();
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("lebron".to_string()),
                amount: Uint128(5000),
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

        let pause_msg = HandleMsg::SetContractStatus {
            level: ContractStatusLevel::StopAllButRedeems,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("not_admin", &[]), pause_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));

        let mint_msg = HandleMsg::AddMinters {
            minters: vec![HumanAddr("not_admin".to_string())],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("not_admin", &[]), mint_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));

        let mint_msg = HandleMsg::RemoveMinters {
            minters: vec![HumanAddr("admin".to_string())],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("not_admin", &[]), mint_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));

        let mint_msg = HandleMsg::SetMinters {
            minters: vec![HumanAddr("not_admin".to_string())],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("not_admin", &[]), mint_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));

        let change_admin_msg = HandleMsg::ChangeAdmin {
            address: HumanAddr("not_admin".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("not_admin", &[]), change_admin_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains(&admin_err.clone()));
    }

    #[test]
    fn test_handle_pause_with_withdrawals() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("lebron".to_string()),
                amount: Uint128(5000),
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

        let pause_msg = HandleMsg::SetContractStatus {
            level: ContractStatusLevel::StopAllButRedeems,
            padding: None,
        };

        let handle_result = handle(&mut deps, mock_env("admin", &[]), pause_msg);
        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let send_msg = HandleMsg::Transfer {
            recipient: HumanAddr("account".to_string()),
            amount: Uint128(123),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), send_msg);
        let error = extract_error_msg(handle_result);
        assert_eq!(
            error,
            "This contract is stopped and this action is not allowed".to_string()
        );

        let withdraw_msg = HandleMsg::Redeem {
            amount: Uint128(5000),
            denom: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("lebron", &[]), withdraw_msg);
        assert!(
            handle_result.is_ok(),
            "Withdraw failed: {}",
            handle_result.err().unwrap()
        );
    }

    #[test]
    fn test_handle_pause_all() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("lebron".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let pause_msg = HandleMsg::SetContractStatus {
            level: ContractStatusLevel::StopAll,
            padding: None,
        };

        let handle_result = handle(&mut deps, mock_env("admin", &[]), pause_msg);
        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let send_msg = HandleMsg::Transfer {
            recipient: HumanAddr("account".to_string()),
            amount: Uint128(123),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), send_msg);
        let error = extract_error_msg(handle_result);
        assert_eq!(
            error,
            "This contract is stopped and this action is not allowed".to_string()
        );

        let withdraw_msg = HandleMsg::Redeem {
            amount: Uint128(5000),
            denom: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("lebron", &[]), withdraw_msg);
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
                address: HumanAddr("bob".to_string()),
                amount: Uint128(5000),
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
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // try when mint disabled
        let handle_msg = HandleMsg::SetMinters {
            minters: vec![HumanAddr("bob".to_string())],
            padding: None,
        };
        let handle_result = handle(&mut deps_for_failure, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Mint functionality is not enabled for this token"));

        let handle_msg = HandleMsg::SetMinters {
            minters: vec![HumanAddr("bob".to_string())],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Admin commands can only be run from admin address"));

        let handle_msg = HandleMsg::SetMinters {
            minters: vec![HumanAddr("bob".to_string())],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(100),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(100),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("allowed to minter accounts only"));
    }

    #[test]
    fn test_handle_add_minters() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("bob".to_string()),
                amount: Uint128(5000),
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
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // try when mint disabled
        let handle_msg = HandleMsg::AddMinters {
            minters: vec![HumanAddr("bob".to_string())],
            padding: None,
        };
        let handle_result = handle(&mut deps_for_failure, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Mint functionality is not enabled for this token"));

        let handle_msg = HandleMsg::AddMinters {
            minters: vec![HumanAddr("bob".to_string())],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Admin commands can only be run from admin address"));

        let handle_msg = HandleMsg::AddMinters {
            minters: vec![HumanAddr("bob".to_string())],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(100),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(100),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(ensure_success(handle_result.unwrap()));
    }

    #[test]
    fn test_handle_remove_minters() {
        let (init_result, mut deps) = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("bob".to_string()),
                amount: Uint128(5000),
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
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // try when mint disabled
        let handle_msg = HandleMsg::RemoveMinters {
            minters: vec![HumanAddr("bob".to_string())],
            padding: None,
        };
        let handle_result = handle(&mut deps_for_failure, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Mint functionality is not enabled for this token"));

        let handle_msg = HandleMsg::RemoveMinters {
            minters: vec![HumanAddr("admin".to_string())],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Admin commands can only be run from admin address"));

        let handle_msg = HandleMsg::RemoveMinters {
            minters: vec![HumanAddr("admin".to_string())],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(100),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("allowed to minter accounts only"));

        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(100),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("allowed to minter accounts only"));

        // Removing another extra time to ensure nothing funky happens
        let handle_msg = HandleMsg::RemoveMinters {
            minters: vec![HumanAddr("admin".to_string())],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(100),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("allowed to minter accounts only"));

        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(100),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("allowed to minter accounts only"));
    }

    // Query tests

    #[test]
    fn test_authenticated_queries() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("giannis".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let no_vk_yet_query_msg = QueryMsg::Balance {
            address: HumanAddr("giannis".to_string()),
            key: "no_vk_yet".to_string(),
        };
        let query_result = query(&deps, no_vk_yet_query_msg);
        let error = extract_error_msg(query_result);
        assert_eq!(
            error,
            "Wrong viewing key for this address or viewing key not set".to_string()
        );

        let create_vk_msg = HandleMsg::CreateViewingKey {
            entropy: "34".to_string(),
            padding: None,
        };
        let handle_response = handle(&mut deps, mock_env("giannis", &[]), create_vk_msg).unwrap();
        let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
            HandleAnswer::CreateViewingKey { key } => key,
            _ => panic!("Unexpected result from handle"),
        };

        let query_balance_msg = QueryMsg::Balance {
            address: HumanAddr("giannis".to_string()),
            key: vk.0,
        };

        let query_response = query(&deps, query_balance_msg).unwrap();
        let balance = match from_binary(&query_response).unwrap() {
            QueryAnswer::Balance { amount } => amount,
            _ => panic!("Unexpected result from query"),
        };
        assert_eq!(balance, Uint128(5000));

        let wrong_vk_query_msg = QueryMsg::Balance {
            address: HumanAddr("giannis".to_string()),
            key: "wrong_vk".to_string(),
        };
        let query_result = query(&deps, wrong_vk_query_msg);
        let error = extract_error_msg(query_result);
        assert_eq!(
            error,
            "Wrong viewing key for this address or viewing key not set".to_string()
        );
    }

    #[test]
    fn test_query_token_info() {
        let init_name = "sec-sec".to_string();
        let init_admin = HumanAddr("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 8;
        let init_config: InitConfig = from_binary(&Binary::from(
            r#"{ "public_total_supply": true }"#.as_bytes(),
        ))
        .unwrap();
        let init_supply = Uint128(5000);

        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);
        let init_msg = InitMsg {
            name: init_name.clone(),
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::TokenInfo {};
        let query_result = query(&deps, query_msg);
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
                assert_eq!(total_supply, Some(Uint128(5000)));
            }
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn test_query_token_config() {
        let init_name = "sec-sec".to_string();
        let init_admin = HumanAddr("admin".to_string());
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

        let init_supply = Uint128(5000);

        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);
        let init_msg = InitMsg {
            name: init_name.clone(),
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::TokenConfig {};
        let query_result = query(&deps, query_msg);
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
        let init_admin = HumanAddr("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 8;

        let init_supply = Uint128(5000);

        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);
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
        let init_msg = InitMsg {
            name: init_name.clone(),
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::ExchangeRate {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ExchangeRate { rate, denom } => {
                assert_eq!(rate, Uint128(100));
                assert_eq!(denom, "SCRT");
            }
            _ => panic!("unexpected"),
        }

        // test same number of decimals as SCRT
        let init_name = "sec-sec".to_string();
        let init_admin = HumanAddr("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 6;

        let init_supply = Uint128(5000);

        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);
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
        let init_msg = InitMsg {
            name: init_name.clone(),
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::ExchangeRate {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ExchangeRate { rate, denom } => {
                assert_eq!(rate, Uint128(1));
                assert_eq!(denom, "SCRT");
            }
            _ => panic!("unexpected"),
        }

        // test less decimal places than SCRT
        let init_name = "sec-sec".to_string();
        let init_admin = HumanAddr("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 3;

        let init_supply = Uint128(5000);

        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);
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
        let init_msg = InitMsg {
            name: init_name.clone(),
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::ExchangeRate {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ExchangeRate { rate, denom } => {
                assert_eq!(rate, Uint128(1000));
                assert_eq!(denom, "SECSEC");
            }
            _ => panic!("unexpected"),
        }

        // test depost/redeem not enabled
        let init_name = "sec-sec".to_string();
        let init_admin = HumanAddr("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 3;

        let init_supply = Uint128(5000);

        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);
        let init_msg = InitMsg {
            name: init_name.clone(),
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: None,
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::ExchangeRate {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ExchangeRate { rate, denom } => {
                assert_eq!(rate, Uint128(0));
                assert_eq!(denom, String::new());
            }
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn test_query_allowance() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("giannis".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("lebron".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("giannis", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let vk1 = ViewingKey("key1".to_string());
        let vk2 = ViewingKey("key2".to_string());

        let query_msg = QueryMsg::Allowance {
            owner: HumanAddr("giannis".to_string()),
            spender: HumanAddr("lebron".to_string()),
            key: vk1.0.clone(),
        };
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Query failed: {}",
            query_result.err().unwrap()
        );
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key"));

        let handle_msg = HandleMsg::SetViewingKey {
            key: vk1.0.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("lebron", &[]), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
            .unwrap(),
        );

        let handle_msg = HandleMsg::SetViewingKey {
            key: vk2.0.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("giannis", &[]), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
            .unwrap(),
        );

        let query_msg = QueryMsg::Allowance {
            owner: HumanAddr("giannis".to_string()),
            spender: HumanAddr("lebron".to_string()),
            key: vk1.0.clone(),
        };
        let query_result = query(&deps, query_msg);
        let allowance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Allowance { allowance, .. } => allowance,
            _ => panic!("Unexpected"),
        };
        assert_eq!(allowance, Uint128(2000));

        let query_msg = QueryMsg::Allowance {
            owner: HumanAddr("giannis".to_string()),
            spender: HumanAddr("lebron".to_string()),
            key: vk2.0.clone(),
        };
        let query_result = query(&deps, query_msg);
        let allowance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Allowance { allowance, .. } => allowance,
            _ => panic!("Unexpected"),
        };
        assert_eq!(allowance, Uint128(2000));

        let query_msg = QueryMsg::Allowance {
            owner: HumanAddr("lebron".to_string()),
            spender: HumanAddr("giannis".to_string()),
            key: vk2.0.clone(),
        };
        let query_result = query(&deps, query_msg);
        let allowance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Allowance { allowance, .. } => allowance,
            _ => panic!("Unexpected"),
        };
        assert_eq!(allowance, Uint128(0));
    }

    #[test]
    fn test_query_balance() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
            .unwrap(),
        );

        let query_msg = QueryMsg::Balance {
            address: HumanAddr("bob".to_string()),
            key: "wrong_key".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key"));

        let query_msg = QueryMsg::Balance {
            address: HumanAddr("bob".to_string()),
            key: "key".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let balance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Balance { amount } => amount,
            _ => panic!("Unexpected"),
        };
        assert_eq!(balance, Uint128(5000));
    }

    #[test]
    fn test_query_transfer_history() {
        let (init_result, mut deps) = init_helper(vec![InitialBalance {
            address: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
        }]);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = HandleMsg::Transfer {
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(1000),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let handle_msg = HandleMsg::Transfer {
            recipient: HumanAddr("banana".to_string()),
            amount: Uint128(500),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let handle_msg = HandleMsg::Transfer {
            recipient: HumanAddr("mango".to_string()),
            amount: Uint128(2500),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let query_msg = QueryMsg::TransferHistory {
            address: HumanAddr("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 0,
        };
        let query_result = query(&deps, query_msg);
        // let a: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        // println!("{:?}", a);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, total } => txs,
            _ => panic!("Unexpected"),
        };
        assert!(transfers.is_empty());

        let query_msg = QueryMsg::TransferHistory {
            address: HumanAddr("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 10,
        };
        let query_result = query(&deps, query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, total } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 3);

        let query_msg = QueryMsg::TransferHistory {
            address: HumanAddr("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 2,
        };
        let query_result = query(&deps, query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, total } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 2);
    }
}
