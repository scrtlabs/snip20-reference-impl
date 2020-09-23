use crate::msg::{HandleMsg, InitMsg, QueryMsg};
use crate::state::{
    get_transfers, read_allowance, read_viewing_key, store_transfer, write_allowance,
    write_viewing_key, Balances, Config, Constants, ReadonlyBalances, ReadonlyConfig,
};
use crate::utils::ConstLenStr;
use crate::viewing_key::{ViewingKey, VIEWING_KEY_LENGTH};
use cosmwasm_std::{
    log, Api, BankMsg, Binary, CanonicalAddr, Coin, CosmosMsg, Decimal, Env, Extern,
    HandleResponse, HumanAddr, InitResponse, Querier, QueryResult, StdError, StdResult, Storage,
    Uint128,
};

pub const PREFIX_ALLOWANCES: &[u8] = b"allowances";
pub const PREFIX_VIEW_KEY: &[u8] = b"viewingkey";
pub const KEY_CONSTANTS: &[u8] = b"constants";
pub const KEY_TOTAL_SUPPLY: &[u8] = b"total_supply";
pub const VK_PRNG_SEED: &[u8] = b"yo";

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let mut total_supply: u128 = 0;
    {
        let mut balances = Balances::from_storage(&mut deps.storage);
        for balance in msg.initial_balances {
            let balance_address = deps.api.canonical_address(&balance.address)?;
            let amount = balance.amount.u128();
            balances.set_account_balance(&balance_address, amount);
            total_supply += amount;
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

    let mut config = Config::from_storage(&mut deps.storage);
    config.set_constants(&Constants {
        name: msg.name,
        symbol: msg.symbol,
        decimals: msg.decimals,
    })?;
    config.set_total_supply(total_supply);

    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    match msg {
        HandleMsg::Withdraw { amount } => try_withdraw(deps, env, amount),
        HandleMsg::Deposit {} => try_deposit(deps, env),
        HandleMsg::Balance {} => try_balance(deps, env),
        HandleMsg::Allowance { spender } => try_check_allowance(deps, env, spender),
        HandleMsg::Approve { spender, amount } => try_approve(deps, env, &spender, amount),
        HandleMsg::Transfer { recipient, amount } => try_transfer(deps, env, &recipient, amount),
        HandleMsg::TransferFrom {
            owner,
            recipient,
            amount,
        } => try_transfer_from(deps, env, &owner, &recipient, amount),
        HandleMsg::Burn { amount } => try_burn(deps, env, amount),
        HandleMsg::CreateViewingKey { entropy } => try_create_key(deps, env, entropy),
        HandleMsg::SetViewingKey { key } => try_set_key(deps, env, key),
    }
}

pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    let (address, key) = msg.get_validation_params();

    let canonical_addr = deps.api.canonical_address(address)?;

    let expected_key = read_viewing_key(&deps.storage, &canonical_addr);

    if expected_key.is_none() {
        // Checking the key will take significant time. We don't want to exit immediately if it isn't set
        // in a way which will allow to time the command and determine if a viewing key doesn't exist
        key.check_viewing_key(&[0u8; 24]);
        return Ok(Binary(
            b"Wrong viewing key for this address or viewing key not set".to_vec(),
        ));
    }

    if !key.check_viewing_key(expected_key.unwrap().as_slice()) {
        return Ok(Binary(
            b"Wrong viewing key for this address or viewing key not set".to_vec(),
        ));
    }

    match msg {
        QueryMsg::Balance { address, .. } => query_balance(&deps, &address),
        QueryMsg::Transfers { address, .. } => query_transactions(&deps, &address),
        _ => unimplemented!(),
    }
}

pub fn query_transactions<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    account: &HumanAddr,
) -> StdResult<Binary> {
    let address = deps.api.canonical_address(account).unwrap();
    let address = get_transfers(&deps.storage, &address)?;

    Ok(Binary(format!("{:?}", address).into_bytes().to_vec()))
}

pub fn query_balance<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    account: &HumanAddr,
) -> StdResult<Binary> {
    let address = deps.api.canonical_address(account)?;

    Ok(Binary(Vec::from(get_balance(deps, &address)?)))
}

pub fn try_set_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    key: String,
) -> StdResult<HandleResponse> {
    let vk = ViewingKey(key);

    if !vk.is_valid() {
        return Ok(HandleResponse {
            messages: vec![],
            log: vec![
                log("result", "failed!"),
                log(
                    "viewing key",
                    format!(
                        "viewing key must be a string exactly {} characters!",
                        VIEWING_KEY_LENGTH
                    ),
                ),
            ],
            data: None,
        });
    }

    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    write_viewing_key(&mut deps.storage, &message_sender, &vk)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![
            log("result", "success"),
            log("viewing key", format!("{}", vk)),
        ],
        data: None,
    })
}

pub fn try_create_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String,
) -> StdResult<HandleResponse> {
    let vk = ViewingKey::new(&env, VK_PRNG_SEED, (&entropy).as_ref());

    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    write_viewing_key(&mut deps.storage, &message_sender, &vk)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![log("viewing key", format!("{}", vk))],
        data: None,
    })
}

pub fn try_check_allowance<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    spender: HumanAddr,
) -> StdResult<HandleResponse> {
    let sender_address = deps.api.canonical_address(&env.message.sender)?;
    let allowance = read_allowance(
        &deps.storage,
        &sender_address,
        &deps.api.canonical_address(&spender)?,
    );

    if let Err(_e) = allowance {
        Ok(HandleResponse {
            messages: vec![],
            log: vec![
                log("action", "check_allowance"),
                log("account", env.message.sender.0),
                log("spender", &spender.as_str()),
                log("amount", ConstLenStr("0".to_string())),
            ],
            data: None,
        })
    } else {
        Ok(HandleResponse {
            messages: vec![],
            log: vec![
                log("action", "check_allowance"),
                log("account", env.message.sender.0),
                log("spender", &spender.as_str()),
                log("amount", ConstLenStr(allowance.unwrap().to_string())),
            ],
            data: None,
        })
    }
}

pub fn try_balance<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let sender_address = deps.api.canonical_address(&env.message.sender)?;
    let account_balance = get_balance(deps, &sender_address);

    if let Err(_e) = account_balance {
        Ok(HandleResponse {
            messages: vec![],
            log: vec![
                log("action", "balance"),
                log("account", env.message.sender.0),
                log("amount", ConstLenStr("0".to_string())),
            ],
            data: None,
        })
    } else {
        Ok(HandleResponse {
            messages: vec![],
            log: vec![
                log("action", "balance"),
                log("account", env.message.sender.0),
                log("amount", ConstLenStr(account_balance.unwrap())),
            ],
            data: None,
        })
    }
}

fn get_balance<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    account: &CanonicalAddr,
) -> StdResult<String> {
    let account_balance = ReadonlyBalances::from_storage(&deps.storage).account_amount(account);

    let consts = ReadonlyConfig::from_storage(&deps.storage).constants()?;

    Ok(to_display_token(
        account_balance,
        &consts.symbol,
        consts.decimals,
    ))
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
        return Err(StdError::generic_err("Lol send some funds dude"));
    }

    let amount = amount.u128();

    let sender_address = deps.api.canonical_address(&env.message.sender)?;

    let mut balances = Balances::from_storage(&mut deps.storage);
    let mut account_balance = balances.account_amount(&sender_address);
    account_balance += amount;
    balances.set_account_balance(&sender_address, account_balance);

    let mut config = Config::from_storage(&mut deps.storage);
    let mut total_supply = config.total_supply();
    total_supply += amount;
    config.set_total_supply(total_supply);

    let res = HandleResponse {
        messages: vec![],
        log: vec![
            log("action", "deposit"),
            log("account", env.message.sender.0),
            log("amount", &amount.to_string()),
        ],
        data: None,
    };

    Ok(res)
}

fn try_withdraw<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    amount: Uint128,
) -> StdResult<HandleResponse> {
    let sender_address = deps.api.canonical_address(&env.message.sender)?;
    let amount_raw = amount.u128();

    let mut balances = Balances::from_storage(&mut deps.storage);
    let mut account_balance = balances.account_amount(&sender_address);

    if account_balance < amount_raw {
        return Err(StdError::generic_err(format!(
            "insufficient funds to burn: balance={}, required={}",
            account_balance, amount_raw
        )));
    }
    account_balance -= amount_raw;

    balances.set_account_balance(&sender_address, account_balance);

    let mut config = Config::from_storage(&mut deps.storage);
    let mut total_supply = config.total_supply();
    total_supply -= amount_raw;
    config.set_total_supply(total_supply);

    let withdrawl_coins: Vec<Coin> = vec![Coin {
        denom: "uscrt".to_string(),
        amount,
    }];

    let res = HandleResponse {
        messages: vec![CosmosMsg::Bank(BankMsg::Send {
            from_address: env.contract.address,
            to_address: env.message.sender.clone(),
            amount: withdrawl_coins,
        })],
        log: vec![
            log("action", "withdraw"),
            log("account", env.message.sender.0),
            log("amount", &amount.to_string()),
        ],
        data: None,
    };

    Ok(res)
}

fn try_transfer<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    recipient: &HumanAddr,
    amount: Uint128,
) -> StdResult<HandleResponse> {
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
        &deps.api,
        &mut deps.storage,
        &sender_address,
        &recipient_address,
        amount,
        symbol,
    );

    let res = HandleResponse {
        messages: vec![],
        log: vec![
            log("action", "transfer"),
            log("sender", env.message.sender.0),
            log("recipient", recipient.as_str()),
        ],
        data: None,
    };
    Ok(res)
}

fn try_transfer_from<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    owner: &HumanAddr,
    recipient: &HumanAddr,
    amount: Uint128,
) -> StdResult<HandleResponse> {
    let spender_address = deps.api.canonical_address(&env.message.sender)?;
    let owner_address = deps.api.canonical_address(owner)?;
    let recipient_address = deps.api.canonical_address(recipient)?;
    let amount_raw = amount.u128();

    let mut allowance = read_allowance(&deps.storage, &owner_address, &spender_address)?;
    if allowance < amount_raw {
        return Err(StdError::generic_err(format!(
            "Insufficient allowance: allowance={}, required={}",
            allowance, amount_raw
        )));
    }
    allowance -= amount_raw;
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
        &deps.api,
        &mut deps.storage,
        &owner_address,
        &recipient_address,
        amount,
        symbol,
    );

    let res = HandleResponse {
        messages: vec![],
        log: vec![
            log("action", "transfer_from"),
            log("spender", env.message.sender.0),
            log("sender", owner.as_str()),
            log("recipient", recipient.as_str()),
        ],
        data: None,
    };
    Ok(res)
}

fn try_approve<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    spender: &HumanAddr,
    amount: Uint128,
) -> StdResult<HandleResponse> {
    let owner_address = deps.api.canonical_address(&env.message.sender)?;
    let spender_address = deps.api.canonical_address(spender)?;
    write_allowance(
        &mut deps.storage,
        &owner_address,
        &spender_address,
        amount.u128(),
    )?;
    let res = HandleResponse {
        messages: vec![],
        log: vec![
            log("action", "approve"),
            log("owner", env.message.sender.0),
            log("spender", spender.as_str()),
        ],
        data: None,
    };
    Ok(res)
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
    let sender_address = deps.api.canonical_address(&env.message.sender)?;
    let amount = amount.u128();

    let mut balances = Balances::from_storage(&mut deps.storage);
    let mut account_balance = balances.account_amount(&sender_address);

    if account_balance < amount {
        return Err(StdError::generic_err(format!(
            "insufficient funds to burn: balance={}, required={}",
            account_balance, amount
        )));
    }
    account_balance -= amount;

    balances.set_account_balance(&sender_address, account_balance);

    let mut config = Config::from_storage(&mut deps.storage);
    let mut total_supply = config.total_supply();
    total_supply -= amount;
    config.set_total_supply(total_supply);

    let res = HandleResponse {
        messages: vec![],
        log: vec![
            log("action", "burn"),
            log("account", env.message.sender.0),
            log("amount", amount.to_string()),
        ],
        data: None,
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

    let mut from_balance = balances.account_amount(from);
    if from_balance < amount {
        return Err(StdError::generic_err(format!(
            "Insufficient funds: balance={}, required={}",
            from_balance, amount
        )));
    }
    from_balance -= amount;
    balances.set_account_balance(from, from_balance);

    let mut to_balance = balances.account_amount(to);
    to_balance += amount;
    balances.set_account_balance(to, to_balance);

    Ok(())
}

fn is_valid_name(name: &str) -> bool {
    let len = name.len();
    3 <= len && len <= 30
}

fn is_valid_symbol(symbol: &str) -> bool {
    let len = symbol.len();
    let len_is_valid = 3 <= len && len <= 6;

    len_is_valid && symbol.bytes().all(|byte| b'A' <= byte && byte <= b'Z')
}

fn to_display_token(amount: u128, symbol: &str, decimals: u8) -> String {
    let base: u32 = 10;

    let amnt: Decimal = Decimal::from_ratio(amount, (base.pow(decimals.into())) as u64);

    format!("{} {}", amnt, symbol)
}

// pub fn migrate<S: Storage, A: Api, Q: Querier>(
//     _deps: &mut Extern<S, A, Q>,
//     _env: Env,
//     _msg: MigrateMsg,
// ) -> StdResult<MigrateResponse> {
//     Ok(MigrateResponse::default())
// }
