use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

use crate::msg::{AllowanceResponse, BalanceResponse, MigrateMsg,HandleMsg, InitMsg, QueryMsg};
use cosmwasm_std::{log, to_binary, to_vec, Api, Binary, CanonicalAddr, Env, Extern, HandleResponse, HumanAddr, generic_err, InitResponse, MigrateResponse, Querier, ReadonlyStorage, StdResult, Storage, Uint128, CosmosMsg, BankMsg, Coin, Decimal};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, JsonSchema)]
pub struct Constants {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

pub const PREFIX_CONFIG: &[u8] = b"config";
pub const PREFIX_BALANCES: &[u8] = b"balances";
pub const PREFIX_ALLOWANCES: &[u8] = b"allowances";

pub const KEY_CONSTANTS: &[u8] = b"constants";
pub const KEY_TOTAL_SUPPLY: &[u8] = b"total_supply";

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let mut total_supply: u128 = 0;
    {
        // Initial balances
        let mut balances_store = PrefixedStorage::new(PREFIX_BALANCES, &mut deps.storage);
        for row in msg.initial_balances {
            let raw_address = deps.api.canonical_address(&row.address)?;
            let amount_raw = row.amount.u128();
            balances_store.set(raw_address.as_slice(), &amount_raw.to_be_bytes());
            total_supply += amount_raw;
        }
    }

    // Check name, symbol, decimals
    if !is_valid_name(&msg.name) {
        return Err(generic_err(
            "Name is not in the expected format (3-30 UTF-8 bytes)",
        ));
    }
    if !is_valid_symbol(&msg.symbol) {
        return Err(generic_err(
            "Ticker symbol is not in expected format [A-Z]{3,6}",
        ));
    }
    if msg.decimals > 18 {
        return Err(generic_err("Decimals must not exceed 18"));
    }

    let mut config_store = PrefixedStorage::new(PREFIX_CONFIG, &mut deps.storage);
    let constants = bincode2::serialize(&Constants {
        name: msg.name,
        symbol: msg.symbol,
        decimals: msg.decimals,
    }).unwrap();
    config_store.set(KEY_CONSTANTS, &constants);
    config_store.set(KEY_TOTAL_SUPPLY, &total_supply.to_be_bytes());

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
        HandleMsg::Allowance {spender} => try_check_allowance(deps, env, spender),
        HandleMsg::Approve { spender, amount } => try_approve(deps, env, &spender, &amount),
        HandleMsg::Transfer { recipient, amount } => try_transfer(deps, env, &recipient, &amount),
        HandleMsg::TransferFrom {
            owner,
            recipient,
            amount,
        } => try_transfer_from(deps, env, &owner, &recipient, &amount),
        HandleMsg::Burn { amount } => try_burn(deps, env, &amount),
    }
}

pub fn query<S: Storage, A: Api, Q: Querier>(
    _deps: &Extern<S, A, Q>,
    _msg: QueryMsg,
) -> StdResult<Binary> {
    Err(generic_err("Queries are not supported in this contract"))
}


pub fn try_check_allowance<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    spender: HumanAddr) -> StdResult<HandleResponse> {

    let sender_address_raw = &env.message.sender;
    let allownace = read_allowance(&deps.storage, sender_address_raw, &deps.api.canonical_address(&spender)?);

    if let Err(e) = allownace {
        Ok(HandleResponse {
            messages: vec![],
            log: vec![
                log("action", "check_allownace"),
                log(
                    "account",
                    deps.api.human_address(&env.message.sender)?.as_str(),
                ),
                log(
                    "spender",
                    &spender.as_str(),
                ),
                log("amount", "0"),
            ],
            data: None,
        })
    }
    else {
        Ok(HandleResponse {
            messages: vec![],
            log: vec![
                log("action", "check_allownace"),
                log(
                    "account",
                    deps.api.human_address(&env.message.sender)?.as_str(),
                ),
                log(
                    "spender",
                    &spender.as_str(),
                ),
                log("amount", allownace.unwrap()),
            ],
            data: None,
        })
    }
}

pub fn try_balance<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env) -> StdResult<HandleResponse> {

    let sender_address_raw = &env.message.sender;
    let account_balance = read_balance(&deps.storage, sender_address_raw);

    let consts = read_constants(&deps.storage)?;

    if let Err(_e) = account_balance {
        Ok(HandleResponse {
            messages: vec![],
            log: vec![
                log("action", "balance"),
                log(
                    "account",
                    deps.api.human_address(&env.message.sender)?.as_str(),
                ),
                log("amount", "0"),
            ],
            data: None,
        })
    }
    else {

        let printable_token = to_display_token(account_balance.unwrap(), &consts.symbol, consts.decimals);

        Ok(HandleResponse {
            messages: vec![],
            log: vec![
                log("action", "balance"),
                log(
                    "account",
                    deps.api.human_address(&env.message.sender)?.as_str(),
                ),
                log("amount", printable_token),
            ],
            data: None,
        })
    }
}

fn try_deposit<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env) -> StdResult<HandleResponse> {

    let mut amount_raw: Uint128 = Uint128::default();

    for coin in &env.message.sent_funds {
        if coin.denom == "uscrt" {
            amount_raw = coin.amount
        }
    }

    if amount_raw == Uint128::default() {
        return Err(generic_err(format!("Lol send some funds dude")));
    }

    let amount = amount_raw.u128();

    let sender_address_raw = &env.message.sender;

    let mut account_balance = read_balance(&deps.storage, sender_address_raw)?;

    account_balance += amount;

    let mut balances_store = PrefixedStorage::new(PREFIX_BALANCES, &mut deps.storage);
    balances_store.set(sender_address_raw.as_slice(), &account_balance.to_be_bytes());

    let mut config_store = PrefixedStorage::new(PREFIX_CONFIG, &mut deps.storage);
    let data = config_store
        .get(KEY_TOTAL_SUPPLY)
        .expect("no total supply data stored");
    let mut total_supply = bytes_to_u128(&data).unwrap();

    total_supply += amount;

    config_store.set(KEY_TOTAL_SUPPLY, &total_supply.to_be_bytes());

    let res = HandleResponse {
        messages: vec![],
        log: vec![
            log("action", "deposit"),
            log(
                "account",
                deps.api.human_address(&env.message.sender)?.as_str(),
            ),
            log("amount", &amount.to_string()),
        ],
        data: None,
    };

    Ok(res)

}

fn try_withdraw<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    amount: Uint128) -> StdResult<HandleResponse> {
    let owner_address_raw = &env.message.sender;
    let amount_raw = amount.u128();

    let mut account_balance = read_balance(&deps.storage, owner_address_raw)?;

    if account_balance < amount_raw {
        return Err(generic_err(format!(
            "insufficient funds to burn: balance={}, required={}",
            account_balance, amount_raw
        )));
    }
    account_balance -= amount_raw;

    let mut balances_store = PrefixedStorage::new(PREFIX_BALANCES, &mut deps.storage);
    balances_store.set(owner_address_raw.as_slice(), &account_balance.to_be_bytes());

    let mut config_store = PrefixedStorage::new(PREFIX_CONFIG, &mut deps.storage);
    let data = config_store
        .get(KEY_TOTAL_SUPPLY)
        .expect("no total supply data stored");
    let mut total_supply = bytes_to_u128(&data).unwrap();

    total_supply -= amount_raw;

    config_store.set(KEY_TOTAL_SUPPLY, &total_supply.to_be_bytes());

    let contract_addr = deps.api.human_address(&env.contract.address)?;
    let withdrawl_addr = deps.api.human_address(owner_address_raw)?;

    let withdrawl_coins: Vec<Coin> = vec![Coin {denom: "uscrt".to_string(), amount}];


    let res = HandleResponse {
        messages: vec![CosmosMsg::Bank(BankMsg::Send {
            from_address: contract_addr,
            to_address: withdrawl_addr,
            amount: withdrawl_coins,
        })],
        log: vec![
            log("action", "withdraw"),
            log(
                "account",
                deps.api.human_address(&env.message.sender)?.as_str(),
            ),
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
    amount: &Uint128,
) -> StdResult<HandleResponse> {
    let sender_address_raw = &env.message.sender;
    let recipient_address_raw = deps.api.canonical_address(recipient)?;
    let amount_raw = amount.u128();

    perform_transfer(
        &mut deps.storage,
        &sender_address_raw,
        &recipient_address_raw,
        amount_raw,
    )?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![
            log("action", "transfer"),
            log(
                "sender",
                deps.api.human_address(&env.message.sender)?.as_str(),
            ),
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
    amount: &Uint128,
) -> StdResult<HandleResponse> {
    let spender_address_raw = &env.message.sender;
    let owner_address_raw = deps.api.canonical_address(owner)?;
    let recipient_address_raw = deps.api.canonical_address(recipient)?;
    let amount_raw = amount.u128();

    let mut allowance = read_allowance(&deps.storage, &owner_address_raw, &spender_address_raw)?;
    if allowance < amount_raw {
        return Err(generic_err(format!(
            "Insufficient allowance: allowance={}, required={}",
            allowance, amount_raw
        )));
    }
    allowance -= amount_raw;
    write_allowance(
        &mut deps.storage,
        &owner_address_raw,
        &spender_address_raw,
        allowance,
    )?;
    perform_transfer(
        &mut deps.storage,
        &owner_address_raw,
        &recipient_address_raw,
        amount_raw,
    )?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![
            log("action", "transfer_from"),
            log(
                "spender",
                deps.api.human_address(&env.message.sender)?.as_str(),
            ),
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
    amount: &Uint128,
) -> StdResult<HandleResponse> {
    let owner_address_raw = &env.message.sender;
    let spender_address_raw = deps.api.canonical_address(spender)?;
    write_allowance(
        &mut deps.storage,
        &owner_address_raw,
        &spender_address_raw,
        amount.u128(),
    )?;
    let res = HandleResponse {
        messages: vec![],
        log: vec![
            log("action", "approve"),
            log(
                "owner",
                deps.api.human_address(&env.message.sender)?.as_str(),
            ),
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
    amount: &Uint128,
) -> StdResult<HandleResponse> {
    let owner_address_raw = &env.message.sender;
    let amount_raw = amount.u128();

    let mut account_balance = read_balance(&deps.storage, owner_address_raw)?;

    if account_balance < amount_raw {
        return Err(generic_err(format!(
            "insufficient funds to burn: balance={}, required={}",
            account_balance, amount_raw
        )));
    }
    account_balance -= amount_raw;

    let mut balances_store = PrefixedStorage::new(PREFIX_BALANCES, &mut deps.storage);
    balances_store.set(owner_address_raw.as_slice(), &account_balance.to_be_bytes());

    let mut config_store = PrefixedStorage::new(PREFIX_CONFIG, &mut deps.storage);
    let data = config_store
        .get(KEY_TOTAL_SUPPLY)
        .expect("no total supply data stored");
    let mut total_supply = bytes_to_u128(&data).unwrap();

    total_supply -= amount_raw;

    config_store.set(KEY_TOTAL_SUPPLY, &total_supply.to_be_bytes());

    let res = HandleResponse {
        messages: vec![],
        log: vec![
            log("action", "burn"),
            log(
                "account",
                deps.api.human_address(&env.message.sender)?.as_str(),
            ),
            log("amount", &amount.to_string()),
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
    let mut balances_store = PrefixedStorage::new(PREFIX_BALANCES, store);

    let mut from_balance = read_u128(&balances_store, from.as_slice())?;
    if from_balance < amount {
        return Err(generic_err(format!(
            "Insufficient funds: balance={}, required={}",
            from_balance, amount
        )));
    }
    from_balance -= amount;
    balances_store.set(from.as_slice(), &from_balance.to_be_bytes());

    let mut to_balance = read_u128(&balances_store, to.as_slice())?;
    to_balance += amount;
    balances_store.set(to.as_slice(), &to_balance.to_be_bytes());

    Ok(())
}

// Converts 16 bytes value into u128
// Errors if data found that is not 16 bytes
pub fn bytes_to_u128(data: &[u8]) -> StdResult<u128> {
    match data[0..16].try_into() {
        Ok(bytes) => Ok(u128::from_be_bytes(bytes)),
        Err(_) => Err(generic_err(
            "Corrupted data found. 16 byte expected.",
        )),
    }
}

// Reads 16 byte storage value into u128
// Returns zero if key does not exist. Errors if data found that is not 16 bytes
pub fn read_u128<S: ReadonlyStorage>(store: &S, key: &[u8]) -> StdResult<u128> {
    let result = store.get(key);
    match result {
        Some(data) => bytes_to_u128(&data),
        None => Ok(0u128),
    }
}

fn read_balance<S: Storage>(store: &S, owner: &CanonicalAddr) -> StdResult<u128> {
    let balance_store = ReadonlyPrefixedStorage::new(PREFIX_BALANCES, store);
    read_u128(&balance_store, owner.as_slice())
}

fn read_allowance<S: Storage>(
    store: &S,
    owner: &CanonicalAddr,
    spender: &CanonicalAddr,
) -> StdResult<u128> {
    let allowances_store = ReadonlyPrefixedStorage::new(PREFIX_ALLOWANCES, store);
    let owner_store = ReadonlyPrefixedStorage::new(owner.as_slice(), &allowances_store);
    read_u128(&owner_store, spender.as_slice())
}

fn write_allowance<S: Storage>(
    store: &mut S,
    owner: &CanonicalAddr,
    spender: &CanonicalAddr,
    amount: u128,
) -> StdResult<()> {
    let mut allowances_store = PrefixedStorage::new(PREFIX_ALLOWANCES, store);
    let mut owner_store = PrefixedStorage::new(owner.as_slice(), &mut allowances_store);
    owner_store.set(spender.as_slice(), &amount.to_be_bytes());
    Ok(())
}

fn is_valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() < 3 || bytes.len() > 30 {
        return false;
    }
    true
}

fn is_valid_symbol(symbol: &str) -> bool {
    let bytes = symbol.as_bytes();
    if bytes.len() < 3 || bytes.len() > 6 {
        return false;
    }
    for byte in bytes.iter() {
        if *byte < 65 || *byte > 90 {
            return false;
        }
    }
    true
}

fn read_constants<S: Storage>(
    store: &S,
) -> StdResult<Constants> {
    let mut config_store = ReadonlyPrefixedStorage::new(PREFIX_CONFIG, store);
    let consts_bytes = config_store.get(KEY_CONSTANTS).unwrap();

    let consts: Constants = bincode2::deserialize(&consts_bytes).unwrap();

    Ok(consts)
}

fn to_display_token(amount: u128, symbol: &String, decimals: u8) -> String {

    let base: u32 = 10;

    let amnt: Decimal = Decimal::from_ratio(amount, (base.pow(decimals.into())) as u64);

    format!("{} {}", amnt, symbol)
}

pub fn migrate<S: Storage, A: Api, Q: Querier>(
    _deps: &mut Extern<S, A, Q>,
    _env: Env,
    _msg: MigrateMsg,
) -> StdResult<MigrateResponse> {
    Ok(MigrateResponse::default())
}