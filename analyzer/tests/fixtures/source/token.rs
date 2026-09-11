use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    /// Transfers tokens after computing a new balance with unchecked
    /// arithmetic on an amount (SOR-103).
    pub fn pay(env: Env, amount: i128, to: Address) {
        let balance = amount + 10;
        let client = token::Client::new(&env, &to);
        client.transfer(&env.current_contract_address(), &to, &balance);
    }
}
