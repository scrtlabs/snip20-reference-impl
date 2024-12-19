use cosmwasm_std::{to_binary, Addr, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Storage, Uint128};
use secret_toolkit::notification::Notification;
use secret_toolkit::permit::{AllRevokedInterval, RevokedPermits, RevokedPermitsStore};
use secret_toolkit::viewing_key::{ViewingKey, ViewingKeyStore};
use secret_toolkit_crypto::ContractPrng;

use crate::msg::{ExecuteAnswer, ResponseStatus::Success};
use crate::notifications::AllowanceNotification;
use crate::state::{AllowancesStore, ReceiverHashStore, INTERNAL_SECRET_SENSITIVE, NOTIFICATIONS_ENABLED};

// viewing key functions

pub fn try_set_key(deps: DepsMut, info: MessageInfo, key: String) -> StdResult<Response> {
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
    info: MessageInfo,
    entropy: Option<String>,
    rng: &mut ContractPrng,
) -> StdResult<Response> {
    let entropy = [entropy.unwrap_or_default().as_bytes(), &rng.rand_bytes()].concat();

    let key = ViewingKey::create(
        deps.storage,
        &info,
        &env,
        info.sender.as_str(),
        &entropy,
    );

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::CreateViewingKey { key })?))
}

// register receive function

pub fn try_register_receive(
    deps: DepsMut,
    info: MessageInfo,
    code_hash: String,
) -> StdResult<Response> {
    ReceiverHashStore::save(deps.storage, &info.sender, code_hash)?;

    let data = to_binary(&ExecuteAnswer::RegisterReceive { status: Success })?;
    Ok(Response::new()
        .add_attribute("register_status", "success")
        .set_data(data))
}

// allowance functions

fn insufficient_allowance(allowance: u128, required: u128) -> StdError {
    StdError::generic_err(format!(
        "insufficient allowance: allowance={allowance}, required={required}",
    ))
}

pub fn use_allowance(
    storage: &mut dyn Storage,
    env: &Env,
    owner: &Addr,
    spender: &Addr,
    amount: u128,
) -> StdResult<()> {
    let mut allowance = AllowancesStore::load(storage, owner, spender);

    if allowance.is_expired_at(&env.block) || allowance.amount == 0 {
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

pub fn try_increase_allowance(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    spender: String,
    amount: Uint128,
    expiration: Option<u64>,
) -> StdResult<Response> {
    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let spender = deps.api.addr_validate(spender.as_str())?;
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

    let mut resp = Response::new()
        .set_data(to_binary(&ExecuteAnswer::IncreaseAllowance {
            owner: info.sender.clone(),
            spender: spender.clone(),
            allowance: Uint128::from(new_amount),
        })?);

    println!("Got 1 {:?}", resp);
    
    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        let notification = Notification::new (
            spender,
            AllowanceNotification {
                amount: new_amount,
                allower: info.sender,
                expiration,
            }
        )
        .to_txhash_notification(deps.api, &env, secret, None)?;

        resp = resp.add_attribute_plaintext(
            notification.id_plaintext(),
            notification.data_plaintext()
        );

        println!("Got 2 {:?}", resp);

    }

    Ok(resp)  
}

pub fn try_decrease_allowance(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    spender: String,
    amount: Uint128,
    expiration: Option<u64>,
) -> StdResult<Response> {
    let secret = INTERNAL_SECRET_SENSITIVE.load(deps.storage)?;
    let secret = secret.as_slice();

    let spender = deps.api.addr_validate(spender.as_str())?;
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

    let mut resp = Response::new()
        .set_data(to_binary(&ExecuteAnswer::DecreaseAllowance {
            owner: info.sender.clone(),
            spender: spender.clone(),
            allowance: Uint128::from(new_amount),
        })?);

    if NOTIFICATIONS_ENABLED.load(deps.storage)? {
        let notification = Notification::new (
            spender,
            AllowanceNotification {
                amount: new_amount,
                allower: info.sender,
                expiration,
            }
        )
        .to_txhash_notification(deps.api, &env, secret, None)?;

        resp = resp.add_attribute_plaintext(
            notification.id_plaintext(),
            notification.data_plaintext()
        );
    }

    Ok(resp)
}

// SNIP 24, 24.1 permit functions

pub fn revoke_permit(deps: DepsMut, info: MessageInfo, permit_name: String) -> StdResult<Response> {
    RevokedPermits::revoke_permit(
        deps.storage,
        info.sender.as_str(),
        &permit_name,
    );

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::RevokePermit { status: Success })?))
}

pub fn revoke_all_permits(deps: DepsMut, info: MessageInfo, interval: AllRevokedInterval) -> StdResult<Response> {
    let revocation_id = RevokedPermits::revoke_all_permits(
        deps.storage,
        info.sender.as_str(),
        &interval,
    )?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::RevokeAllPermits { 
        status: Success,
        revocation_id: Some(revocation_id.to_string()),
    })?))
}

pub fn delete_permit_revocation(deps: DepsMut, info: MessageInfo, revocation_id: String) -> StdResult<Response> {
    RevokedPermits::delete_revocation(
        deps.storage,
        info.sender.as_str(),
        revocation_id.as_str(),
    )?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::DeletePermitRevocation { 
        status: Success,
    })?))
}





