use cosmwasm_std::{to_binary, Addr, DepsMut, Response, StdError, StdResult};

use crate::msg::ContractStatusLevel;
use crate::msg::{ExecuteAnswer, ResponseStatus::Success};
use crate::state::{Config, MintersStore, CONFIG, CONTRACT_STATUS, NOTIFICATIONS_ENABLED};

// All the functions in this file MUST only be executed after confirming the sender is the admin

pub fn change_admin(deps: DepsMut, constants: &mut Config, address: String) -> StdResult<Response> {
    let address = deps.api.addr_validate(address.as_str())?;

    constants.admin = address;
    CONFIG.save(deps.storage, constants)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::ChangeAdmin { status: Success })?))
}

pub fn add_supported_denoms(
    deps: DepsMut,
    config: &mut Config,
    denoms: Vec<String>,
) -> StdResult<Response> {
    if !config.can_modify_denoms {
        return Err(StdError::generic_err(
            "Cannot modify denoms for this contract",
        ));
    }

    for denom in denoms.iter() {
        if !config.supported_denoms.contains(denom) {
            config.supported_denoms.push(denom.clone());
        }
    }

    CONFIG.save(deps.storage, config)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::AddSupportedDenoms {
            status: Success,
        })?),
    )
}

pub fn remove_supported_denoms(
    deps: DepsMut,
    config: &mut Config,
    denoms: Vec<String>,
) -> StdResult<Response> {
    if !config.can_modify_denoms {
        return Err(StdError::generic_err(
            "Cannot modify denoms for this contract",
        ));
    }

    for denom in denoms.iter() {
        config.supported_denoms.retain(|x| x != denom);
    }

    CONFIG.save(deps.storage, config)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::RemoveSupportedDenoms {
            status: Success,
        })?),
    )
}

pub fn set_contract_status(
    deps: DepsMut,
    status_level: ContractStatusLevel,
) -> StdResult<Response> {
    CONTRACT_STATUS.save(deps.storage, &status_level)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetContractStatus {
            status: Success,
        })?),
    )
}

pub fn add_minters(
    deps: DepsMut,
    constants: &Config,
    minters_to_add: Vec<String>,
) -> StdResult<Response> {
    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    let minters_to_add: Vec<Addr> = minters_to_add
        .iter()
        .map(|minter| deps.api.addr_validate(minter.as_str()).unwrap())
        .collect();
    MintersStore::add_minters(deps.storage, minters_to_add)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::AddMinters { status: Success })?))
}

pub fn remove_minters(
    deps: DepsMut,
    constants: &Config,
    minters_to_remove: Vec<String>,
) -> StdResult<Response> {
    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    let minters_to_remove: StdResult<Vec<Addr>> = minters_to_remove
        .iter()
        .map(|minter| deps.api.addr_validate(minter.as_str()))
        .collect();
    MintersStore::remove_minters(deps.storage, minters_to_remove?)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::RemoveMinters {
            status: Success,
        })?),
    )
}

pub fn set_minters(
    deps: DepsMut,
    constants: &Config,
    minters_to_set: Vec<String>,
) -> StdResult<Response> {
    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    let minters_to_set: Vec<Addr> = minters_to_set
        .iter()
        .map(|minter| deps.api.addr_validate(minter.as_str()).unwrap())
        .collect();
    MintersStore::save(deps.storage, minters_to_set)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::SetMinters { status: Success })?))
}

// SNIP-52 functions

pub fn set_notification_status(deps: DepsMut, enabled: bool) -> StdResult<Response> {
    NOTIFICATIONS_ENABLED.save(deps.storage, &enabled)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetNotificationStatus {
            status: Success,
        })?),
    )
}

// end SNIP-52 functions
