use cosmwasm_std::{
    to_binary, Addr, BlockInfo, CanonicalAddr, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult, Storage, Uint128,
};
use secret_toolkit::notification::Notification;
use secret_toolkit_crypto::ContractPrng;

use crate::batch;
use crate::dwb::DWB;
use crate::execute::use_allowance;
use crate::msg::{ExecuteAnswer, ResponseStatus::Success};
use crate::notifications::{
    render_group_notification, MultiRecvdNotification, MultiSpentNotification, RecvdNotification,
    SpentNotification,
};
use crate::state::{
    safe_add, MintersStore, CONFIG, INTERNAL_SECRET_SENSITIVE, NOTIFICATIONS_ENABLED, TOTAL_SUPPLY,
};
use crate::transaction_history::{store_burn_action, store_mint_action};

// mint functions

#[allow(clippy::too_many_arguments)]
pub fn try_mint(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    rng: &mut ContractPrng,
    recipient: String,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<Response> {
    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let recipient = deps.api.addr_validate(recipient.as_str())?;

    let constants = CONFIG.load(deps.storage)?;

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

    let mut total_supply = TOTAL_SUPPLY.load(deps.storage)?;
    let minted_amount = safe_add(&mut total_supply, amount.u128());
    TOTAL_SUPPLY.save(deps.storage, &total_supply)?;

    #[cfg(feature = "gas_tracking")]
    let mut tracker: GasTracker = GasTracker::new(deps.api);

    let memo_len = memo.as_ref().map(|s| s.len()).unwrap_or_default();

    // Note that even when minted_amount is equal to 0 we still want to perform the operations for logic consistency
    try_mint_impl(
        &mut deps,
        rng,
        info.sender,
        recipient.clone(),
        Uint128::new(minted_amount),
        constants.symbol,
        memo,
        &env.block,
        #[cfg(feature = "gas_tracking")]
        &mut tracker,
    )?;

    let mut resp = Response::new().set_data(to_binary(&ExecuteAnswer::Mint { status: Success })?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        let received_notification = Notification::new(
            recipient,
            RecvdNotification {
                amount: minted_amount,
                sender: None,
                memo_len,
                sender_is_owner: true,
            },
        )
        .to_txhash_notification(deps.api, &env, secret, None)?;

        resp = resp.add_attribute_plaintext(
            received_notification.id_plaintext(),
            received_notification.data_plaintext(),
        );
    }

    #[cfg(feature = "gas_tracking")]
    return Ok(resp.add_gas_tracker(tracker));

    #[cfg(not(feature = "gas_tracking"))]
    Ok(resp)
}

pub fn try_batch_mint(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    rng: &mut ContractPrng,
    actions: Vec<batch::MintAction>,
) -> StdResult<Response> {
    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let constants = CONFIG.load(deps.storage)?;

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

    let mut total_supply = TOTAL_SUPPLY.load(deps.storage)?;

    let mut notifications = vec![];
    // Quick loop to check that the total of amounts is valid
    for action in actions {
        let actual_amount = safe_add(&mut total_supply, action.amount.u128());

        let recipient = deps.api.addr_validate(action.recipient.as_str())?;

        #[cfg(feature = "gas_tracking")]
        let mut tracker: GasTracker = GasTracker::new(deps.api);

        notifications.push(Notification::new(
            recipient.clone(),
            RecvdNotification {
                amount: actual_amount,
                sender: None,
                memo_len: action.memo.as_ref().map(|s| s.len()).unwrap_or_default(),
                sender_is_owner: true,
            },
        ));

        try_mint_impl(
            &mut deps,
            rng,
            info.sender.clone(),
            recipient,
            Uint128::new(actual_amount),
            constants.symbol.clone(),
            action.memo,
            &env.block,
            #[cfg(feature = "gas_tracking")]
            &mut tracker,
        )?;
    }

    TOTAL_SUPPLY.save(deps.storage, &total_supply)?;

    let mut resp =
        Response::new().set_data(to_binary(&ExecuteAnswer::BatchMint { status: Success })?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        resp = render_group_notification(
            deps.api,
            MultiRecvdNotification(notifications),
            &env.transaction.unwrap().hash,
            env.block.random.unwrap(),
            secret,
            resp,
        )?;
    }

    Ok(resp)
}

#[allow(clippy::too_many_arguments)]
fn try_mint_impl(
    deps: &mut DepsMut,
    rng: &mut ContractPrng,
    minter: Addr,
    recipient: Addr,
    amount: Uint128,
    denom: String,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
    #[cfg(feature = "gas_tracking")] tracker: &mut GasTracker,
) -> StdResult<()> {
    let raw_amount = amount.u128();
    let raw_recipient = deps.api.addr_canonicalize(recipient.as_str())?;
    let raw_minter = deps.api.addr_canonicalize(minter.as_str())?;

    perform_mint(
        deps.storage,
        rng,
        &raw_minter,
        &raw_recipient,
        raw_amount,
        denom,
        memo,
        block,
        #[cfg(feature = "gas_tracking")]
        tracker,
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn perform_mint(
    store: &mut dyn Storage,
    rng: &mut ContractPrng,
    minter: &CanonicalAddr,
    to: &CanonicalAddr,
    amount: u128,
    denom: String,
    memo: Option<String>,
    block: &BlockInfo,
    #[cfg(feature = "gas_tracking")] tracker: &mut GasTracker,
) -> StdResult<()> {
    // first store the tx information in the global append list of txs and get the new tx id
    let tx_id = store_mint_action(store, minter, to, amount, denom, memo, block)?;

    // load delayed write buffer
    let mut dwb = DWB.load(store)?;

    // sender and owner are different
    if minter != to {
        // settle the sender's account too
        dwb.settle_sender_or_owner_account(
            store,
            minter,
            tx_id,
            0,
            "mint",
            false,
            #[cfg(feature = "gas_tracking")]
            tracker,
        )?;
    }

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

// burn functions

/// Burn tokens
///
/// Remove `amount` tokens from the system irreversibly, from signer account
///
/// @param amount the amount of money to burn
pub fn try_burn(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<Response> {
    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let constants = CONFIG.load(deps.storage)?;
    if !constants.burn_is_enabled {
        return Err(StdError::generic_err(
            "Burn functionality is not enabled for this token.",
        ));
    }

    let raw_amount = amount.u128();
    let raw_burn_address = deps.api.addr_canonicalize(info.sender.as_str())?;

    let memo_len = memo.as_ref().map(|s| s.len()).unwrap_or_default();

    let tx_id = store_burn_action(
        deps.storage,
        raw_burn_address.clone(),
        raw_burn_address.clone(),
        raw_amount,
        constants.symbol,
        memo,
        &env.block,
    )?;

    // load delayed write buffer
    let mut dwb = DWB.load(deps.storage)?;

    #[cfg(feature = "gas_tracking")]
    let mut tracker = GasTracker::new(deps.api);

    // settle the signer's account in buffer
    let owner_balance = dwb.settle_sender_or_owner_account(
        deps.storage,
        &raw_burn_address,
        tx_id,
        raw_amount,
        "burn",
        false,
        #[cfg(feature = "gas_tracking")]
        &mut tracker,
    )?;

    DWB.save(deps.storage, &dwb)?;

    let mut total_supply = TOTAL_SUPPLY.load(deps.storage)?;
    if let Some(new_total_supply) = total_supply.checked_sub(raw_amount) {
        total_supply = new_total_supply;
    } else {
        return Err(StdError::generic_err(
            "You're trying to burn more than is available in the total supply",
        ));
    }
    TOTAL_SUPPLY.save(deps.storage, &total_supply)?;

    let mut resp = Response::new().set_data(to_binary(&ExecuteAnswer::Burn { status: Success })?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        let spent_notification = Notification::new(
            info.sender,
            SpentNotification {
                amount: raw_amount,
                actions: 1,
                recipient: None,
                balance: owner_balance,
                memo_len,
            },
        )
        .to_txhash_notification(deps.api, &env, secret, None)?;

        resp = resp.add_attribute_plaintext(
            spent_notification.id_plaintext(),
            spent_notification.data_plaintext(),
        );
    }

    Ok(resp)
}

#[allow(clippy::too_many_arguments)]
pub fn try_burn_from(
    deps: DepsMut,
    env: &Env,
    info: MessageInfo,
    owner: String,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<Response> {
    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let owner = deps.api.addr_validate(owner.as_str())?;
    let raw_owner = deps.api.addr_canonicalize(owner.as_str())?;
    let constants = CONFIG.load(deps.storage)?;
    if !constants.burn_is_enabled {
        return Err(StdError::generic_err(
            "Burn functionality is not enabled for this token.",
        ));
    }

    let raw_amount = amount.u128();
    use_allowance(deps.storage, env, &owner, &info.sender, raw_amount)?;
    let raw_burner = deps.api.addr_canonicalize(info.sender.as_str())?;

    let memo_len = memo.as_ref().map(|s| s.len()).unwrap_or_default();

    // store the event
    let tx_id = store_burn_action(
        deps.storage,
        raw_owner.clone(),
        raw_burner.clone(),
        raw_amount,
        constants.symbol,
        memo,
        &env.block,
    )?;

    // load delayed write buffer
    let mut dwb = DWB.load(deps.storage)?;

    #[cfg(feature = "gas_tracking")]
    let mut tracker = GasTracker::new(deps.api);

    // settle the owner's account in buffer
    let owner_balance = dwb.settle_sender_or_owner_account(
        deps.storage,
        &raw_owner,
        tx_id,
        raw_amount,
        "burn",
        raw_burner == raw_owner,
        #[cfg(feature = "gas_tracking")]
        &mut tracker,
    )?;

    // sender and owner are different
    if raw_burner != raw_owner {
        // also settle sender's account
        dwb.settle_sender_or_owner_account(
            deps.storage,
            &raw_burner,
            tx_id,
            0,
            "burn",
            false,
            #[cfg(feature = "gas_tracking")]
            &mut tracker,
        )?;
    }

    DWB.save(deps.storage, &dwb)?;

    // remove from supply
    let mut total_supply = TOTAL_SUPPLY.load(deps.storage)?;

    if let Some(new_total_supply) = total_supply.checked_sub(raw_amount) {
        total_supply = new_total_supply;
    } else {
        return Err(StdError::generic_err(
            "You're trying to burn more than is available in the total supply",
        ));
    }

    TOTAL_SUPPLY.save(deps.storage, &total_supply)?;

    let mut resp =
        Response::new().set_data(to_binary(&ExecuteAnswer::BurnFrom { status: Success })?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        let spent_notification = Notification::new(
            owner,
            SpentNotification {
                amount: raw_amount,
                actions: 1,
                recipient: None,
                balance: owner_balance,
                memo_len,
            },
        )
        .to_txhash_notification(deps.api, env, secret, None)?;

        resp = resp.add_attribute_plaintext(
            spent_notification.id_plaintext(),
            spent_notification.data_plaintext(),
        );
    }

    Ok(resp)
}

pub fn try_batch_burn_from(
    deps: DepsMut,
    env: &Env,
    info: MessageInfo,
    actions: Vec<batch::BurnFromAction>,
) -> StdResult<Response> {
    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let constants = CONFIG.load(deps.storage)?;
    if !constants.burn_is_enabled {
        return Err(StdError::generic_err(
            "Burn functionality is not enabled for this token.",
        ));
    }

    let raw_spender = deps.api.addr_canonicalize(info.sender.as_str())?;
    let mut total_supply = TOTAL_SUPPLY.load(deps.storage)?;
    let mut spent_notifications = vec![];

    for action in actions {
        let owner = deps.api.addr_validate(action.owner.as_str())?;
        let raw_owner = deps.api.addr_canonicalize(owner.as_str())?;
        let amount = action.amount.u128();
        use_allowance(deps.storage, env, &owner, &info.sender, amount)?;

        let tx_id = store_burn_action(
            deps.storage,
            raw_owner.clone(),
            raw_spender.clone(),
            amount,
            constants.symbol.clone(),
            action.memo.clone(),
            &env.block,
        )?;

        // load delayed write buffer
        let mut dwb = DWB.load(deps.storage)?;

        #[cfg(feature = "gas_tracking")]
        let mut tracker = GasTracker::new(deps.api);

        // settle the owner's account in buffer
        let owner_balance = dwb.settle_sender_or_owner_account(
            deps.storage,
            &raw_owner,
            tx_id,
            amount,
            "burn",
            raw_spender == raw_owner,
            #[cfg(feature = "gas_tracking")]
            &mut tracker,
        )?;

        // sender and owner are different
        if raw_spender != raw_owner {
            // also settle the sender's account
            dwb.settle_sender_or_owner_account(
                deps.storage,
                &raw_spender,
                tx_id,
                0,
                "burn",
                false,
                #[cfg(feature = "gas_tracking")]
                &mut tracker,
            )?;
        }

        DWB.save(deps.storage, &dwb)?;

        // remove from supply
        if let Some(new_total_supply) = total_supply.checked_sub(amount) {
            total_supply = new_total_supply;
        } else {
            return Err(StdError::generic_err(format!(
                "You're trying to burn more than is available in the total supply: {action:?}",
            )));
        }

        spent_notifications.push(Notification::new(
            info.sender.clone(),
            SpentNotification {
                amount,
                actions: 1,
                recipient: None,
                balance: owner_balance,
                memo_len: action.memo.as_ref().map(|s| s.len()).unwrap_or_default(),
            },
        ));
    }

    TOTAL_SUPPLY.save(deps.storage, &total_supply)?;

    let mut resp = Response::new().set_data(to_binary(&ExecuteAnswer::BatchBurnFrom {
        status: Success,
    })?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        resp = render_group_notification(
            deps.api,
            MultiSpentNotification(spent_notifications),
            &env.transaction.clone().unwrap().hash,
            env.block.random.clone().unwrap(),
            secret,
            resp,
        )?;
    }

    Ok(resp)
}
