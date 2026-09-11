use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    /// Deliberate unchecked arithmetic, acknowledged inline. SOR-103 must not
    /// fire here.
    pub fn allowed_pay(env: Env, amount: i128, to: Address) {
        // soroban-analyzer: allow(SOR-103)
        let balance = amount + 10;
        let client = token::Client::new(&env, &to);
        client.transfer(&env.current_contract_address(), &to, &balance);
    }

    /// The same pattern without the directive; SOR-103 must fire here.
    pub fn flagged_pay(env: Env, amount: i128, to: Address) {
        let balance = amount + 10;
        let client = token::Client::new(&env, &to);
        client.transfer(&env.current_contract_address(), &to, &balance);
    }
}
