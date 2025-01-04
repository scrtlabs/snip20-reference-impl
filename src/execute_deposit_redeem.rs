use cosmwasm_std::{
    to_binary, BankMsg, BlockInfo, CanonicalAddr, Coin, CosmosMsg, DepsMut, Env, MessageInfo,
    Response, StdError, StdResult, Storage, Uint128,
};
use secret_toolkit_crypto::ContractPrng;

use crate::dwb::DWB;
use crate::msg::{ExecuteAnswer, ResponseStatus::Success};
use crate::state::{safe_add, CONFIG, TOTAL_SUPPLY};
use crate::transaction_history::{store_deposit_action, store_redeem_action};
#[cfg(feature = "gas_tracking")]
use crate::gas_tracker::GasTracker;

// deposit functions

pub fn try_deposit(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    rng: &mut ContractPrng,
) -> StdResult<Response> {
    let constants = CONFIG.load(deps.storage)?;

    let mut amount = Uint128::zero();

    for coin in &info.funds {
        if constants.supported_denoms.contains(&coin.denom) {
            amount += coin.amount
        } else {
            return Err(StdError::generic_err(format!(
                "Tried to deposit an unsupported coin {}",
                coin.denom
            )));
        }
    }

    if amount.is_zero() {
        return Err(StdError::generic_err("No funds were sent to be deposited"));
    }

    let mut raw_amount = amount.u128();

    if !constants.deposit_is_enabled {
        return Err(StdError::generic_err(
            "Deposit functionality is not enabled.",
        ));
    }

    let mut total_supply = TOTAL_SUPPLY.load(deps.storage)?;
    raw_amount = safe_add(&mut total_supply, raw_amount);
    TOTAL_SUPPLY.save(deps.storage, &total_supply)?;

    let sender_address = deps.api.addr_canonicalize(info.sender.as_str())?;

    #[cfg(feature = "gas_tracking")]
    let mut tracker: GasTracker = GasTracker::new(deps.api);

    perform_deposit(
        deps.storage,
        rng,
        &sender_address,
        raw_amount,
        "uscrt".to_string(),
        &env.block,
        #[cfg(feature = "gas_tracking")]
        &mut tracker,
    )?;

    let resp = Response::new().set_data(to_binary(&ExecuteAnswer::Deposit { status: Success })?);

    #[cfg(feature = "gas_tracking")]
    return Ok(tracker.add_to_response(resp));

    #[cfg(not(feature = "gas_tracking"))]
    Ok(resp)
}

fn perform_deposit(
    store: &mut dyn Storage,
    rng: &mut ContractPrng,
    to: &CanonicalAddr,
    amount: u128,
    denom: String,
    block: &BlockInfo,
    #[cfg(feature = "gas_tracking")] tracker: &mut GasTracker,
) -> StdResult<()> {
    // first store the tx information in the global append list of txs and get the new tx id
    let tx_id = store_deposit_action(store, amount, denom, block)?;

    // load delayed write buffer
    let mut dwb = DWB.load(store)?;

    // add the tx info for the recipient to the buffer
    dwb.add_recipient(
        store,
        rng,
        to,
        tx_id,
        amount,
        #[cfg(feature = "gas_tracking")]
        tracker,
    )?;

    DWB.save(store, &dwb)?;

    Ok(())
}

// redeem functions

pub fn try_redeem(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
    denom: Option<String>,
) -> StdResult<Response> {
    let constants = CONFIG.load(deps.storage)?;
    if !constants.redeem_is_enabled {
        return Err(StdError::generic_err(
            "Redeem functionality is not enabled for this token.",
        ));
    }

    // if denom is none and there is only 1 supported denom then we don't need to check anything
    let withdraw_denom = if denom.is_none() && constants.supported_denoms.len() == 1 {
        constants.supported_denoms.first().unwrap().clone()
    // if denom is specified make sure it's on the list before trying to withdraw with it
    } else if denom.is_some() && constants.supported_denoms.contains(denom.as_ref().unwrap()) {
        denom.unwrap()
    // error handling
    } else if denom.is_none() {
        return Err(StdError::generic_err(
            "Tried to redeem without specifying denom, but multiple coins are supported",
        ));
    } else {
        return Err(StdError::generic_err(
            "Tried to redeem for an unsupported coin",
        ));
    };

    let sender_address = deps.api.addr_canonicalize(info.sender.as_str())?;
    let amount_raw = amount.u128();

    let tx_id = store_redeem_action(deps.storage, amount.u128(), constants.symbol, &env.block)?;

    // load delayed write buffer
    let mut dwb = DWB.load(deps.storage)?;

    #[cfg(feature = "gas_tracking")]
    let mut tracker = GasTracker::new(deps.api);

    // settle the signer's account in buffer
    dwb.settle_sender_or_owner_account(
        deps.storage,
        &sender_address,
        tx_id,
        amount_raw,
        "redeem",
        false,
        #[cfg(feature = "gas_tracking")]
        &mut tracker,
    )?;

    DWB.save(deps.storage, &dwb)?;

    let total_supply = TOTAL_SUPPLY.load(deps.storage)?;
    if let Some(total_supply) = total_supply.checked_sub(amount_raw) {
        TOTAL_SUPPLY.save(deps.storage, &total_supply)?;
    } else {
        return Err(StdError::generic_err(
            "You are trying to redeem more tokens than what is available in the total supply",
        ));
    }

    let token_reserve = deps
        .querier
        .query_balance(&env.contract.address, &withdraw_denom)?
        .amount;
    if amount > token_reserve {
        return Err(StdError::generic_err(format!(
            "You are trying to redeem for more {withdraw_denom} than the contract has in its reserve",
        )));
    }

    let withdrawal_coins: Vec<Coin> = vec![Coin {
        denom: withdraw_denom,
        amount,
    }];

    let message = CosmosMsg::Bank(BankMsg::Send {
        to_address: info.sender.clone().into_string(),
        amount: withdrawal_coins,
    });
    let data = to_binary(&ExecuteAnswer::Redeem { status: Success })?;
    let res = Response::new().add_message(message).set_data(data);
    Ok(res)
}
