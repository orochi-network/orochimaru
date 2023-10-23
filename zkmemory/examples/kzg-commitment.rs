use zkmemory::base::{UsizeConvertible, U256};
use zkmemory::config::{DefaultConfig, ConfigArgs};
use zkmemory::machine::{RAMMachine, RegisterMachine, StackMachine, StateMachine256};
fn main() {
    let mut sm = StateMachine256::new_custom(DefaultConfig::default(), 1024 as usize);
}