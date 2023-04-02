use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, StdError, StdResult, Storage};
use secret_toolkit::serialization::Json;
use secret_toolkit::storage::{Item, Keymap, Keyset};
use secret_toolkit_crypto::SHA256_HASH_SIZE;

use crate::msg::ContractStatusLevel;

pub const KEY_CONFIG: &[u8] = b"config";
pub const KEY_TOTAL_SUPPLY: &[u8] = b"total_supply";
pub const KEY_CONTRACT_STATUS: &[u8] = b"contract_status";
pub const KEY_PRNG: &[u8] = b"prng";
pub const KEY_MINTERS: &[u8] = b"minters";
pub const KEY_TX_COUNT: &[u8] = b"tx-count";

pub const PREFIX_CONFIG: &[u8] = b"config";
pub const PREFIX_BALANCES: &[u8] = b"balances";
pub const PREFIX_ALLOWANCES: &[u8] = b"allowances";
pub const PREFIX_ALLOWED: &[u8] = b"allowed";
pub const PREFIX_VIEW_KEY: &[u8] = b"viewingkey";
pub const PREFIX_RECEIVERS: &[u8] = b"receivers";

// Config

#[derive(Serialize, Debug, Deserialize, Clone, JsonSchema)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Config {
    pub name: String,
    pub admin: Addr,
    pub symbol: String,
    pub decimals: u8,
    // privacy configuration
    pub total_supply_is_public: bool,
    // is deposit enabled
    pub deposit_is_enabled: bool,
    // is redeem enabled
    pub redeem_is_enabled: bool,
    // is mint enabled
    pub mint_is_enabled: bool,
    // is burn enabled
    pub burn_is_enabled: bool,
    // the address of this contract, used to validate query permits
    pub contract_address: Addr,
    // coin denoms that are supported for deposit/redeem
    pub supported_denoms: Vec<String>,
    // can admin add or remove supported denoms
    pub can_modify_denoms: bool,
}

pub static CONFIG: Item<Config> = Item::new(KEY_CONFIG);

pub static TOTAL_SUPPLY: Item<u128> = Item::new(KEY_TOTAL_SUPPLY);

pub static CONTRACT_STATUS: Item<ContractStatusLevel, Json> = Item::new(KEY_CONTRACT_STATUS);

pub static PRNG: Item<[u8; SHA256_HASH_SIZE]> = Item::new(KEY_PRNG);

pub static MINTERS: Item<Vec<Addr>> = Item::new(KEY_MINTERS);

pub static TX_COUNT: Item<u64> = Item::new(KEY_TX_COUNT);

pub struct PrngStore {}
impl PrngStore {
    pub fn load(store: &dyn Storage) -> StdResult<[u8; SHA256_HASH_SIZE]> {
        PRNG.load(store).map_err(|_err| StdError::generic_err(""))
    }

    pub fn save(store: &mut dyn Storage, prng_seed: [u8; SHA256_HASH_SIZE]) -> StdResult<()> {
        PRNG.save(store, &prng_seed)
    }
}

pub struct MintersStore {}
impl MintersStore {
    pub fn load(store: &dyn Storage) -> StdResult<Vec<Addr>> {
        MINTERS
            .load(store)
            .map_err(|_err| StdError::generic_err(""))
    }

    pub fn save(store: &mut dyn Storage, minters_to_set: Vec<Addr>) -> StdResult<()> {
        MINTERS.save(store, &minters_to_set)
    }

    pub fn add_minters(store: &mut dyn Storage, minters_to_add: Vec<Addr>) -> StdResult<()> {
        let mut loaded_minters = MINTERS
            .load(store)
            .map_err(|_err| StdError::not_found("Key not found in storage"))?;

        loaded_minters.extend(minters_to_add);

        MINTERS.save(store, &loaded_minters)
    }

    pub fn remove_minters(store: &mut dyn Storage, minters_to_remove: Vec<Addr>) -> StdResult<()> {
        let mut loaded_minters = MINTERS
            .load(store)
            .map_err(|_err| StdError::generic_err(""))?;

        for minter in minters_to_remove {
            loaded_minters.retain(|x| x != &minter);
        }

        MINTERS.save(store, &loaded_minters)
    }
}

// To avoid balance guessing attacks based on balance overflow we need to perform safe addition and don't expose overflows to the caller.
// Assuming that max of u128 is probably an unreachable balance, we want the addition to be bounded the max of u128
// Currently the logic here is very straight forward yet the existence of the function is mendatory for future changes if needed.
pub fn safe_add(balance: &mut u128, amount: u128) -> u128 {
    // Note that new_amount can be equal to base after this operation.
    // Currently we do nothing maybe on other implementations we will have something to add here
    let prev_balance: u128 = *balance;
    *balance = balance.saturating_add(amount);

    // Won't underflow as the minimal value possible is 0
    *balance - prev_balance
}

pub static BALANCES: Item<u128> = Item::new(PREFIX_BALANCES);
pub struct BalancesStore {}
impl BalancesStore {
    fn save(store: &mut dyn Storage, account: &Addr, amount: u128) -> StdResult<()> {
        let balances = BALANCES.add_suffix(account.as_str().as_bytes());
        balances.save(store, &amount)
    }

    pub fn load(store: &dyn Storage, account: &Addr) -> u128 {
        let balances = BALANCES.add_suffix(account.as_str().as_bytes());
        balances.load(store).unwrap_or_default()
    }

    pub fn update_balance(
        store: &mut dyn Storage,
        account: &Addr,
        amount_to_be_updated: u128,
        should_add: bool,
        operation_name: &str,
        decoys: &Option<Vec<Addr>>,
        account_random_pos: &Option<usize>,
    ) -> StdResult<()> {
        match decoys {
            None => {
                let mut balance = Self::load(store, account);
                balance = match should_add {
                    true => {
                        safe_add(&mut balance, amount_to_be_updated);
                        balance
                    }
                    false => {
                        if let Some(balance) = balance.checked_sub(amount_to_be_updated) {
                            balance
                        } else {
                            return Err(StdError::generic_err(format!(
                                "insufficient funds to {operation_name}: balance={balance}, required={amount_to_be_updated}",
                            )));
                        }
                    }
                };

                Self::save(store, account, balance)
            }
            Some(decoys_vec) => {
                // It should always be set when decoys_vec is set
                let account_pos = account_random_pos.unwrap();

                let mut accounts_to_be_written: Vec<&Addr> = vec![];

                let (first_part, second_part) = decoys_vec.split_at(account_pos);
                accounts_to_be_written.extend(first_part);
                accounts_to_be_written.push(account);
                accounts_to_be_written.extend(second_part);

                // In a case where the account is also a decoy somehow
                let mut was_account_updated = false;

                for acc in accounts_to_be_written.iter() {
                    // Always load account balance to obfuscate the real account
                    // Please note that decoys are not always present in the DB. In this case it is ok beacuse load will return 0.
                    let mut acc_balance = Self::load(store, acc);
                    let mut new_balance = acc_balance;

                    if *acc == account && !was_account_updated {
                        was_account_updated = true;
                        new_balance = match should_add {
                            true => {
                                safe_add(&mut acc_balance, amount_to_be_updated);
                                acc_balance
                            }
                            false => {
                                if let Some(balance) = acc_balance.checked_sub(amount_to_be_updated)
                                {
                                    balance
                                } else {
                                    return Err(StdError::generic_err(format!(
                                        "insufficient funds to {operation_name}: balance={acc_balance}, required={amount_to_be_updated}",
                                    )));
                                }
                            }
                        };
                    }
                    Self::save(store, acc, new_balance)?;
                }

                Ok(())
            }
        }
    }
}

// Allowances

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, Eq, Default, JsonSchema)]
pub struct Allowance {
    pub amount: u128,
    pub expiration: Option<u64>,
}

impl Allowance {
    pub fn is_expired_at(&self, block: &cosmwasm_std::BlockInfo) -> bool {
        match self.expiration {
            Some(time) => block.time.seconds() >= time,
            None => false, // allowance has no expiration
        }
    }
}

pub static ALLOWANCES: Keymap<Addr, Allowance> = Keymap::new(PREFIX_ALLOWANCES);
pub static ALLOWED: Keyset<Addr> = Keyset::new(PREFIX_ALLOWED);
pub struct AllowancesStore {}
impl AllowancesStore {
    pub fn load(store: &dyn Storage, owner: &Addr, spender: &Addr) -> Allowance {
        ALLOWANCES
            .add_suffix(owner.as_bytes())
            .get(store, &spender.clone())
            .unwrap_or_default()
    }

    pub fn save(
        store: &mut dyn Storage,
        owner: &Addr,
        spender: &Addr,
        allowance: &Allowance,
    ) -> StdResult<()> {
        ALLOWED
            .add_suffix(spender.as_bytes())
            .insert(store, owner)?;
        ALLOWANCES
            .add_suffix(owner.as_bytes())
            .insert(store, spender, allowance)
    }

    pub fn all_allowances(
        store: &dyn Storage,
        owner: &Addr,
        page: u32,
        page_size: u32,
    ) -> StdResult<Vec<(Addr, Allowance)>> {
        ALLOWANCES
            .add_suffix(owner.as_bytes())
            .paging(store, page, page_size)
    }

    pub fn num_allowances(store: &dyn Storage, owner: &Addr) -> u32 {
        ALLOWANCES
            .add_suffix(owner.as_bytes())
            .get_len(store)
            .unwrap_or(0)
    }

    pub fn all_allowed(
        store: &dyn Storage,
        spender: &Addr,
        page: u32,
        page_size: u32,
    ) -> StdResult<Vec<(Addr, Allowance)>> {
        let owners = ALLOWED
            .add_suffix(spender.as_bytes())
            .paging(store, page, page_size)?;
        let owners_allowances = owners
            .into_iter()
            .map(|owner| (owner.clone(), AllowancesStore::load(store, &owner, spender)))
            .collect();
        Ok(owners_allowances)
    }

    pub fn num_allowed(store: &dyn Storage, spender: &Addr) -> u32 {
        ALLOWED
            .add_suffix(spender.as_bytes())
            .get_len(store)
            .unwrap_or(0)
    }

    pub fn is_allowed(store: &dyn Storage, owner: &Addr, spender: &Addr) -> bool {
        ALLOWED
            .add_suffix(spender.as_bytes())
            .contains(store, owner)
    }
}

// Receiver Interface
pub static RECEIVER_HASH: Item<String> = Item::new(PREFIX_RECEIVERS);
pub struct ReceiverHashStore {}
impl ReceiverHashStore {
    pub fn may_load(store: &dyn Storage, account: &Addr) -> StdResult<Option<String>> {
        let receiver_hash = RECEIVER_HASH.add_suffix(account.as_str().as_bytes());
        receiver_hash.may_load(store)
    }

    pub fn save(store: &mut dyn Storage, account: &Addr, code_hash: String) -> StdResult<()> {
        let receiver_hash = RECEIVER_HASH.add_suffix(account.as_str().as_bytes());
        receiver_hash.save(store, &code_hash)
    }
}
