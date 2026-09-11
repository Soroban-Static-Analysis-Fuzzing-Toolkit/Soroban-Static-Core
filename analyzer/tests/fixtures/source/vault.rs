use soroban_sdk::{contract, contractimpl, Env, Symbol, Vec};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    /// Persists a caller-supplied collection, then iterates it without a static
    /// bound (SOR-104) while holding a storage handle.
    pub fn process(env: Env, ids: Vec<u32>) {
        env.storage().persistent().set(&Symbol::short("IDS"), &ids);
        for id in ids.iter() {
            let _ = id;
        }
    }
}
