use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{to_binary, Binary, CosmosMsg, HumanAddr, StdResult, Uint128, WasmMsg};

/// Snip20ReceiveMsg should be de/serialized under `Receive()` variant in a HandleMsg
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub struct Snip20ReceiveMsg {
    pub sender: HumanAddr,
    pub amount: Uint128,
    pub msg: Option<Binary>,
}

impl Snip20ReceiveMsg {
    pub fn new(sender: HumanAddr, amount: Uint128, msg: Option<Binary>) -> Self {
        Self {
            sender,
            amount,
            msg,
        }
    }

    /// serializes the message
    pub fn into_binary(self) -> StdResult<Binary> {
        let msg = ReceiverHandleMsg::Receive(self);
        to_binary(&msg)
    }

    /// creates a cosmos_msg sending this struct to the named contract
    pub fn into_cosmos_msg(
        self,
        callback_code_hash: String,
        contract_addr: HumanAddr,
    ) -> StdResult<CosmosMsg> {
        let msg = self.into_binary()?;
        let execute = WasmMsg::Execute {
            msg,
            callback_code_hash,
            contract_addr,
            send: vec![],
        };
        Ok(execute.into())
    }
}

// This is just a helper to properly serialize the above message
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
enum ReceiverHandleMsg {
    Receive(Snip20ReceiveMsg),
}
