pub mod contract;
pub mod msg;
pub mod state;

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::contract;
    use cosmwasm_std::{do_execute, do_instantiate, do_query};

    #[no_mangle]
    extern "C" fn init(env_ptr: u32, info_ptr: u32, msg_ptr: u32) -> u32 {
        do_instantiate(&contract::instantiate, env_ptr, info_ptr, msg_ptr)
    }

    #[no_mangle]
    extern "C" fn handle(env_ptr: u32, info_ptr: u32, msg_ptr: u32) -> u32 {
        do_execute(&contract::execute, env_ptr, info_ptr, msg_ptr)
    }

    #[no_mangle]
    extern "C" fn query(env_ptr: u32, msg_ptr: u32) -> u32 {
        do_query(&contract::query, env_ptr, msg_ptr)
    }

    // Other C externs like cosmwasm_vm_version_1, allocate, deallocate are available
    // automatically because we `use cosmwasm_std`.
}
