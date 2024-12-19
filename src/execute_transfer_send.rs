use cosmwasm_std::{to_binary, Addr, Binary, BlockInfo, CanonicalAddr, CosmosMsg, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Storage, Uint128};
use secret_toolkit::notification::Notification;
use secret_toolkit_crypto::ContractPrng;

use crate::batch;
use crate::dwb::DWB;
use crate::execute::use_allowance;
use crate::msg::{ExecuteAnswer, ResponseStatus::Success};
use crate::notifications::{render_group_notification, MultiRecvdNotification, MultiSpentNotification, RecvdNotification, SpentNotification};
use crate::receiver::Snip20ReceiveMsg;
use crate::state::{ReceiverHashStore, CONFIG, INTERNAL_SECRET_SENSITIVE, NOTIFICATIONS_ENABLED};
use crate::strings::SEND_TO_CONTRACT_ERR_MSG;
use crate::transaction_history::store_transfer_action;

// transfer functions

#[allow(clippy::too_many_arguments)]
pub fn try_transfer(
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

    let recipient: Addr = deps.api.addr_validate(recipient.as_str())?;

    let symbol = CONFIG.load(deps.storage)?.symbol;

    // make sure the sender is not accidentally sending tokens to the contract address
    if recipient == env.contract.address {
        return Err(StdError::generic_err(SEND_TO_CONTRACT_ERR_MSG));
    }

    #[cfg(feature = "gas_tracking")]
    let mut tracker: GasTracker = GasTracker::new(deps.api);

    // perform the transfer
    let (
        received_notification,
        spent_notification
    ) = try_transfer_impl(
        &mut deps,
        rng,
        &info.sender,
        &recipient,
        amount,
        symbol,
        memo,
        &env.block,
        #[cfg(feature = "gas_tracking")]
        &mut tracker,
    )?;

    #[cfg(feature = "gas_tracking")]
    let mut group1 = tracker.group("try_transfer.rest");

    let mut resp = Response::new()
        .set_data(to_binary(&ExecuteAnswer::Transfer { status: Success })?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        // render the tokens received notification
        let received_notification = received_notification.to_txhash_notification(
            deps.api,
            &env,
            secret,
            None,
        )?;

        // render the tokens spent notification
        let spent_notification = spent_notification.to_txhash_notification(
            deps.api, 
            &env, 
            secret,
            None,
        )?;
        
        resp = resp.add_attribute_plaintext(
            received_notification.id_plaintext(),
            received_notification.data_plaintext(),
        )
        .add_attribute_plaintext(
            spent_notification.id_plaintext(),
            spent_notification.data_plaintext(),
        );
    }

    #[cfg(feature = "gas_tracking")]
    group1.log("rest");

    #[cfg(feature = "gas_tracking")]
    return Ok(resp.add_gas_tracker(tracker));

    #[cfg(not(feature = "gas_tracking"))]
    Ok(resp)
}

pub fn try_batch_transfer(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    rng: &mut ContractPrng,
    actions: Vec<batch::TransferAction>,
) -> StdResult<Response> {
    let num_actions = actions.len();
    if num_actions == 0 {
        return Ok(Response::new()
            .set_data(to_binary(&ExecuteAnswer::BatchTransfer { status: Success })?)
        );
    }

    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let symbol = CONFIG.load(deps.storage)?.symbol;

    let mut total_memo_len = 0;

    #[cfg(feature = "gas_tracking")]
    let mut tracker: GasTracker = GasTracker::new(deps.api);

    let mut notifications = vec![];
    for action in actions {
        let recipient = deps.api.addr_validate(action.recipient.as_str())?;
      
        // make sure the sender is not accidentally sending tokens to the contract address
        if recipient == env.contract.address {
            return Err(StdError::generic_err(SEND_TO_CONTRACT_ERR_MSG));
        }

        total_memo_len += action.memo.as_ref().map(|s| s.len()).unwrap_or_default();

        let (
            received_notification,
            spent_notification
        ) = try_transfer_impl(
            &mut deps,
            rng,
            &info.sender,
            &recipient,
            action.amount,
            symbol.clone(),
            action.memo,
            &env.block,
            #[cfg(feature = "gas_tracking")]
            &mut tracker,
        )?;

        notifications.push((received_notification, spent_notification));
    }

    let (
        received_notifications,
        spent_notifications
    ): (
        Vec<Notification<RecvdNotification>>,
        Vec<Notification<SpentNotification>>,
    ) = notifications.into_iter().unzip();

    let mut resp = Response::new()
        .set_data(to_binary(&ExecuteAnswer::BatchTransfer { status: Success })?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        resp = render_group_notification(
            deps.api,
            MultiRecvdNotification(received_notifications),
            &env.transaction.clone().unwrap().hash,
            env.block.random.clone().unwrap(),
            secret,
            resp,
        )?;

        let total_amount_spent = spent_notifications
            .iter()
            .fold(0u128, |acc, notification| acc.saturating_add(notification.data.amount));

        let spent_notification = Notification::new (
            info.sender,
            SpentNotification {
                amount: total_amount_spent,
                actions: num_actions as u32,
                recipient: spent_notifications[0].data.recipient.clone(),
                balance: spent_notifications.last().unwrap().data.balance,
                memo_len: total_memo_len,
            }
        )
        .to_txhash_notification(deps.api, &env, secret, None)?;

        resp = resp.add_attribute_plaintext(
            spent_notification.id_plaintext(),
            spent_notification.data_plaintext(),
        );
    }

    #[cfg(feature = "gas_tracking")]
    return Ok(resp.add_gas_tracker(tracker));

    #[cfg(not(feature = "gas_tracking"))]
    Ok(resp)
}

#[allow(clippy::too_many_arguments)]
pub fn try_transfer_from(
    mut deps: DepsMut,
    env: &Env,
    info: MessageInfo,
    rng: &mut ContractPrng,
    owner: String,
    recipient: String,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<Response> {
    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let owner = deps.api.addr_validate(owner.as_str())?;
    let recipient = deps.api.addr_validate(recipient.as_str())?;
    let symbol = CONFIG.load(deps.storage)?.symbol;
    let (
        received_notification,
        spent_notification
    ) = try_transfer_from_impl(
        &mut deps,
        rng,
        env,
        &info.sender,
        &owner,
        &recipient,
        amount,
        symbol,
        memo,
    )?;

    let mut resp = Response::new()
        .set_data(to_binary(&ExecuteAnswer::TransferFrom { status: Success })?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        let received_notification = received_notification.to_txhash_notification(
            deps.api,
            &env,
            secret,
            None,
        )?;

        let spent_notification = spent_notification.to_txhash_notification(
            deps.api, 
            &env, 
            secret, 
            None
        )?;

        resp = resp.add_attribute_plaintext(
            received_notification.id_plaintext(),
            received_notification.data_plaintext(),
        )
        .add_attribute_plaintext(
            spent_notification.id_plaintext(),
            spent_notification.data_plaintext(),
        );
    }

    Ok(resp)
}

pub fn try_batch_transfer_from(
    mut deps: DepsMut,
    env: &Env,
    info: MessageInfo,
    rng: &mut ContractPrng,
    actions: Vec<batch::TransferFromAction>,
) -> StdResult<Response> {
    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let mut notifications = vec![];

    let symbol = CONFIG.load(deps.storage)?.symbol;
    for action in actions {
        let owner = deps.api.addr_validate(action.owner.as_str())?;
        let recipient = deps.api.addr_validate(action.recipient.as_str())?;

        let (
            received_notification,
            spent_notification
        ) = try_transfer_from_impl(
            &mut deps,
            rng,
            env,
            &info.sender,
            &owner,
            &recipient,
            action.amount,
            symbol.clone(),
            action.memo,
        )?;

        notifications.push((received_notification, spent_notification));
    }

    let mut resp = Response::new()
        .set_data(to_binary(&ExecuteAnswer::BatchTransferFrom {status: Success})?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        let (received_notifications, spent_notifications): (
            Vec<Notification<RecvdNotification>>,
            Vec<Notification<SpentNotification>>,
        ) = notifications.into_iter().unzip();

        let tx_hash = env.transaction.clone().unwrap().hash;

        resp = render_group_notification(
            deps.api,
            MultiRecvdNotification(received_notifications),
            &tx_hash,
            env.block.random.clone().unwrap(),
            secret,
            resp,
        )?;
    
        resp = render_group_notification(
            deps.api,
            MultiSpentNotification(spent_notifications),
            &tx_hash,
            env.block.random.clone().unwrap(),
            secret,
            resp,
        )?;
    }

    Ok(resp)
}

// send functions

#[allow(clippy::too_many_arguments)]
pub fn try_send(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    rng: &mut ContractPrng,
    recipient: String,
    recipient_code_hash: Option<String>,
    amount: Uint128,
    memo: Option<String>,
    msg: Option<Binary>,
) -> StdResult<Response> {
    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let recipient = deps.api.addr_validate(recipient.as_str())?;

    let mut messages = vec![];
    let symbol = CONFIG.load(deps.storage)?.symbol;

    // make sure the sender is not accidentally sending tokens to the contract address
    if recipient == env.contract.address {
        return Err(StdError::generic_err(SEND_TO_CONTRACT_ERR_MSG));
    }

    #[cfg(feature = "gas_tracking")]
    let mut tracker: GasTracker = GasTracker::new(deps.api);

    let (
        received_notification,
        spent_notification
    ) = try_send_impl(
        &mut deps,
        rng,
        &mut messages,
        info.sender,
        recipient,
        recipient_code_hash,
        amount,
        symbol,
        memo,
        msg,
        &env.block,
        #[cfg(feature = "gas_tracking")]
        &mut tracker,
    )?;

    let mut resp = Response::new()
        .add_messages(messages)
        .set_data(to_binary(&ExecuteAnswer::Send { status: Success })?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        let received_notification = received_notification.to_txhash_notification(deps.api, &env, secret, None)?;
        let spent_notification = spent_notification.to_txhash_notification(deps.api, &env, secret, None)?;
            
        resp = resp.add_attribute_plaintext(
            received_notification.id_plaintext(),
            received_notification.data_plaintext(),
        )
        .add_attribute_plaintext(
            spent_notification.id_plaintext(),
            spent_notification.data_plaintext(),
        );
    }

    #[cfg(feature = "gas_tracking")]
    return Ok(resp.add_gas_tracker(tracker));

    #[cfg(not(feature = "gas_tracking"))]
    Ok(resp)
}

pub fn try_batch_send(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    rng: &mut ContractPrng,
    actions: Vec<batch::SendAction>,
) -> StdResult<Response> {
    let num_actions = actions.len();
    if num_actions == 0 {
        return Ok(Response::new()
            .set_data(to_binary(&ExecuteAnswer::BatchSend { status: Success })?)
        );
    }

    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let mut messages = vec![];

    let mut notifications = vec![];
    let num_actions: usize = actions.len();

    let symbol = CONFIG.load(deps.storage)?.symbol;

    let mut total_memo_len = 0;

    #[cfg(feature = "gas_tracking")]
    let mut tracker: GasTracker = GasTracker::new(deps.api);

    for action in actions {
        let recipient = deps.api.addr_validate(action.recipient.as_str())?;

        // make sure the sender is not accidentally sending tokens to the contract address
        if recipient == env.contract.address {
            return Err(StdError::generic_err(SEND_TO_CONTRACT_ERR_MSG));
        }

        total_memo_len += action.memo.as_ref().map(|s| s.len()).unwrap_or_default();

        let (
            received_notification,
            spent_notification
        ) = try_send_impl(
            &mut deps,
            rng,
            &mut messages,
            info.sender.clone(),
            recipient,
            action.recipient_code_hash,
            action.amount,
            symbol.clone(),
            action.memo,
            action.msg,
            &env.block,
            #[cfg(feature = "gas_tracking")]
            &mut tracker,
        )?;

        notifications.push((received_notification, spent_notification));
    }

    let mut resp = Response::new()
        .add_messages(messages)
        .set_data(to_binary(&ExecuteAnswer::BatchSend { status: Success })?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        let (received_notifications, spent_notifications): (
            Vec<Notification<RecvdNotification>>,
            Vec<Notification<SpentNotification>>,
        ) = notifications.into_iter().unzip();

        resp = render_group_notification(
            deps.api,
            MultiRecvdNotification(received_notifications),
            &env.transaction.clone().unwrap().hash,
            env.block.random.clone().unwrap(),
            secret,
            resp,
        )?;

        let total_amount_spent = spent_notifications
            .iter()
            .fold(0u128, |acc, notification| acc + notification.data.amount);

        let spent_notification = Notification::new (
            info.sender,
            SpentNotification {
                amount: total_amount_spent,
                actions: num_actions as u32,
                recipient: spent_notifications[0].data.recipient.clone(),
                balance: spent_notifications.last().unwrap().data.balance,
                memo_len: total_memo_len,
            }
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
pub fn try_send_from(
    mut deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    rng: &mut ContractPrng,
    owner: String,
    recipient: String,
    recipient_code_hash: Option<String>,
    amount: Uint128,
    memo: Option<String>,
    msg: Option<Binary>,
) -> StdResult<Response> {
    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let owner = deps.api.addr_validate(owner.as_str())?;
    let recipient = deps.api.addr_validate(recipient.as_str())?;
    let mut messages = vec![];
    let (
        received_notification,
        spent_notification
    ) = try_send_from_impl(
        &mut deps,
        env.clone(),
        info,
        rng,
        &mut messages,
        owner,
        recipient,
        recipient_code_hash,
        amount,
        memo,
        msg,
    )?;

    let mut resp = Response::new()
        .add_messages(messages)
        .set_data(to_binary(&ExecuteAnswer::SendFrom { status: Success })?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        let received_notification = received_notification.to_txhash_notification(deps.api, &env, secret, None,)?;
        let spent_notification = spent_notification.to_txhash_notification(deps.api, &env, secret, None)?;
    
        resp = resp.add_attribute_plaintext(
            received_notification.id_plaintext(),
            received_notification.data_plaintext(),
        )
        .add_attribute_plaintext(
            spent_notification.id_plaintext(),
            spent_notification.data_plaintext(),
        )
    }

    Ok(resp)
}

pub fn try_batch_send_from(
    mut deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    rng: &mut ContractPrng,
    actions: Vec<batch::SendFromAction>,
) -> StdResult<Response> {
    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let mut messages = vec![];
    let mut notifications = vec![];

    for action in actions {
        let owner = deps.api.addr_validate(action.owner.as_str())?;
        let recipient = deps.api.addr_validate(action.recipient.as_str())?;
        let (
            received_notification,
            spent_notification
        ) = try_send_from_impl(
            &mut deps,
            env.clone(),
            info,
            rng,
            &mut messages,
            owner,
            recipient,
            action.recipient_code_hash,
            action.amount,
            action.memo,
            action.msg,
        )?;
        notifications.push((received_notification, spent_notification));
    }

    let mut resp = Response::new()
        .add_messages(messages)
        .set_data(to_binary(&ExecuteAnswer::BatchSendFrom {
            status: Success,
        })?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        let (received_notifications, spent_notifications): (
            Vec<Notification<RecvdNotification>>,
            Vec<Notification<SpentNotification>>,
        ) = notifications.into_iter().unzip();

        let tx_hash = env.transaction.clone().unwrap().hash;

        resp = render_group_notification(
            deps.api,
            MultiRecvdNotification(received_notifications),
            &tx_hash,
            env.block.random.clone().unwrap(),
            secret,
            resp,
        )?;

        resp = render_group_notification(
            deps.api,
            MultiSpentNotification(spent_notifications),
            &tx_hash,
            env.block.random.clone().unwrap(),
            secret,
            resp,
        )?;
    }

    Ok(resp)
}

// helper functions

#[allow(clippy::too_many_arguments)]
fn try_transfer_impl(
    deps: &mut DepsMut,
    rng: &mut ContractPrng,
    owner: &Addr,
    recipient: &Addr,
    amount: Uint128,
    denom: String,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
    #[cfg(feature = "gas_tracking")] tracker: &mut GasTracker,
) -> StdResult<(Notification<RecvdNotification>, Notification<SpentNotification>)> {
    // canonicalize owner and recipient addresses
    let raw_owner = deps.api.addr_canonicalize(owner.as_str())?;
    let raw_recipient = deps.api.addr_canonicalize(recipient.as_str())?;

    // memo length
    let memo_len = memo.as_ref().map(|s| s.len()).unwrap_or_default();

    // create the tokens received notification for recipient
    let received_notification = Notification::new(
        recipient.clone(),
        RecvdNotification {
            amount: amount.u128(),
            sender: Some(owner.clone()),
            memo_len,
            sender_is_owner: true,
        }
    );

    // perform the transfer from owner to recipient
    let owner_balance = perform_transfer(
        deps.storage,
        rng,
        &raw_owner,
        &raw_recipient,
        &raw_owner,
        amount.u128(),
        denom,
        memo.clone(),
        block,
        false,
        #[cfg(feature = "gas_tracking")]
        tracker,
    )?;

    // create the tokens spent notification for owner
    let spent_notification = Notification::new (
        owner.clone(),
        SpentNotification {
            amount: amount.u128(),
            actions: 1,
            recipient: Some(recipient.clone()),
            balance: owner_balance,
            memo_len,
        }
    );

    Ok((received_notification, spent_notification))
}

#[allow(clippy::too_many_arguments)]
fn try_transfer_from_impl(
    deps: &mut DepsMut,
    rng: &mut ContractPrng,
    env: &Env,
    spender: &Addr,
    owner: &Addr,
    recipient: &Addr,
    amount: Uint128,
    denom: String,
    memo: Option<String>,
) -> StdResult<(Notification<RecvdNotification>, Notification<SpentNotification>)> {
    let raw_amount = amount.u128();
    let raw_spender = deps.api.addr_canonicalize(spender.as_str())?;
    let raw_owner = deps.api.addr_canonicalize(owner.as_str())?;
    let raw_recipient = deps.api.addr_canonicalize(recipient.as_str())?;

    use_allowance(deps.storage, env, owner, spender, raw_amount)?;

    // make sure the sender is not accidentally sending tokens to the contract address
    if *recipient == env.contract.address {
        return Err(StdError::generic_err(SEND_TO_CONTRACT_ERR_MSG));
    }

    #[cfg(feature = "gas_tracking")]
    let mut tracker: GasTracker = GasTracker::new(deps.api);

    let memo_len = memo.as_ref().map(|s| s.len()).unwrap_or_default();

    // create tokens received notification for recipient
    let received_notification = Notification::new(
        recipient.clone(),
        RecvdNotification {
            amount: amount.u128(),
            sender: Some(owner.clone()),
            memo_len,
            sender_is_owner: spender == owner,
        }
    );
    
    // perform the transfer from owner to recipient
    let owner_balance = perform_transfer(
        deps.storage,
        rng,
        &raw_owner,
        &raw_recipient,
        &raw_spender,
        raw_amount,
        denom,
        memo,
        &env.block,
        true,
        #[cfg(feature = "gas_tracking")]
        &mut tracker,
    )?;

    // create tokens spent notification for owner
    let spent_notification = Notification::new (
        owner.clone(),
        SpentNotification {
            amount: amount.u128(),
            actions: 1,
            recipient: Some(recipient.clone()),
            balance: owner_balance,
            memo_len,
        }
    );

    Ok((received_notification, spent_notification))
}

#[allow(clippy::too_many_arguments)]
fn try_send_impl(
    deps: &mut DepsMut,
    rng: &mut ContractPrng,
    messages: &mut Vec<CosmosMsg>,
    sender: Addr,
    recipient: Addr,
    recipient_code_hash: Option<String>,
    amount: Uint128,
    denom: String,
    memo: Option<String>,
    msg: Option<Binary>,
    block: &cosmwasm_std::BlockInfo,
    #[cfg(feature = "gas_tracking")] tracker: &mut GasTracker,
) -> StdResult<(Notification<RecvdNotification>, Notification<SpentNotification>)> {
    let (
        received_notification,
        spent_notification
    ) = try_transfer_impl(
        deps,
        rng,
        &sender,
        &recipient,
        amount,
        denom,
        memo.clone(),
        block,
        #[cfg(feature = "gas_tracking")]
        tracker,
    )?;

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

    Ok((received_notification, spent_notification))
}

#[allow(clippy::too_many_arguments)]
fn try_send_from_impl(
    deps: &mut DepsMut,
    env: Env,
    info: &MessageInfo,
    rng: &mut ContractPrng,
    messages: &mut Vec<CosmosMsg>,
    owner: Addr,
    recipient: Addr,
    recipient_code_hash: Option<String>,
    amount: Uint128,
    memo: Option<String>,
    msg: Option<Binary>,
) -> StdResult<(Notification<RecvdNotification>, Notification<SpentNotification>)> {
    let spender = info.sender.clone();
    let symbol = CONFIG.load(deps.storage)?.symbol;
    let (
        received_notification,
        spent_notification
    ) = try_transfer_from_impl(
        deps,
        rng,
        &env,
        &spender,
        &owner,
        &recipient,
        amount,
        symbol,
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

    Ok((received_notification, spent_notification))
}

fn perform_transfer(
    store: &mut dyn Storage,
    rng: &mut ContractPrng,
    from: &CanonicalAddr,
    to: &CanonicalAddr,
    sender: &CanonicalAddr,
    amount: u128,
    denom: String,
    memo: Option<String>,
    block: &BlockInfo,
    is_from_action: bool,
    #[cfg(feature = "gas_tracking")] tracker: &mut GasTracker,
) -> StdResult<u128> {
    #[cfg(feature = "gas_tracking")]
    let mut group1 = tracker.group("perform_transfer.1");

    // first store the tx information in the global append list of txs and get the new tx id
    let tx_id = store_transfer_action(store, from, sender, to, amount, denom, memo, block)?;

    #[cfg(feature = "gas_tracking")]
    group1.log("@store_transfer_action");

    // load delayed write buffer
    let mut dwb = DWB.load(store)?;

    #[cfg(feature = "gas_tracking")]
    group1.log("DWB.load");

    let transfer_str = "transfer";

    // settle the owner's account
    let owner_balance = dwb.settle_sender_or_owner_account(
        store,
        from,
        tx_id,
        amount,
        transfer_str,
        is_from_action && sender == from,
        #[cfg(feature = "gas_tracking")]
        tracker,
    )?;

    // sender and owner are different
    if sender != from {
        // settle the sender's account too
        dwb.settle_sender_or_owner_account(
            store,
            sender,
            tx_id,
            0,
            transfer_str,
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

    #[cfg(feature = "gas_tracking")]
    let mut group2 = tracker.group("perform_transfer.2");

    DWB.save(store, &dwb)?;

    #[cfg(feature = "gas_tracking")]
    group2.log("DWB.save");

    Ok(owner_balance)
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

    let receiver_hash = ReceiverHashStore::may_load(storage, &recipient)?;
    if let Some(receiver_hash) = receiver_hash {
        let receiver_msg = Snip20ReceiveMsg::new(sender, from, amount, memo, msg);
        let callback_msg = receiver_msg.into_cosmos_msg(receiver_hash, recipient)?;

        messages.push(callback_msg);
    }
    Ok(())
}