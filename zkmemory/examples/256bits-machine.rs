#![recursion_limit = "256"]

use ethnum::U256;
use rbtree::RBTree;
use std::marker::PhantomData;
use zkmemory::base::{Base, UsizeConvertible};
use zkmemory::{
    impl_register_machine, impl_stack_machine, impl_state_machine,
    machine::{AbstractContext, AbstractInstruction, AbstractMachine},
};

#[derive(Debug)]
pub enum MyInstruction<M, K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    Read(K, V),
    Write(K, V),
    Invalid(PhantomData<M>),
}

/// RAM Machine
#[derive(Debug)]
pub struct StateMachine<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    memory: RBTree<K, V>,
    word_size: K,
    time_log: usize,
    stack_base: K,
    stack_depth: usize,
    stack_ptr: K,
}

impl<M, K, V, const S: usize, const T: usize> AbstractContext<M, K, V> for StateMachine<K, V, S, T>
where
    Self: core::fmt::Debug + Sized,
    K: Base<S>,
    V: Base<T>,
    M: AbstractMachine<K, V>,
{
    fn set_stack_depth(&mut self, stack_depth: usize) {
        todo!()
    }

    fn get_stack_depth(&self) -> usize {
        todo!()
    }

    fn stack_ptr(&self) -> K {
        todo!()
    }

    fn get_time_log(&self) -> usize {
        todo!()
    }

    fn set_time_log(&mut self, time_log: usize) {
        todo!()
    }

    fn apply(&'static mut self, instruction: &<M as AbstractMachine<K, V>>::Instruction) {
        todo!()
    }
}

impl<M, K, V, const S: usize, const T: usize> AbstractInstruction<M, K, V>
    for MyInstruction<M, K, V, S, T>
where
    Self: core::fmt::Debug + Sized,
    K: Base<S>,
    V: Base<T>,
    M: AbstractMachine<K, V>,
{
    fn exec(&self, context: &'static mut <M as AbstractMachine<K, V>>::Context) {
        todo!()
    }
}

impl<K, V, const S: usize, const T: usize> StateMachine<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Create a new RAM machine
    pub fn new() -> Self {
        Self {
            memory: RBTree::new(),
            word_size: K::from_usize(32),
            time_log: 0,
            stack_base: K::from_usize(0),
            stack_depth: 0,
            stack_ptr: K::from_usize(0),
        }
    }
}

impl<K, V, const S: usize, const T: usize> AbstractMachine<K, V> for StateMachine<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    type Context = Self;
    type Instruction = MyInstruction<Self, K, V, S, T>;

    fn context(&mut self) -> &'_ mut Self::Context {
        self
    }

    fn memory(&mut self) -> &'_ mut RBTree<K, V> {
        &mut self.memory
    }

    fn word_size(&self) -> K {
        self.word_size
    }
}

impl_register_machine!(StateMachine);
impl_stack_machine!(StateMachine);
impl_state_machine!(StateMachine);

fn main() {
    let mut a = StateMachine::<U256, U256, 32, 32>::new();
    a.write(U256::from_usize(0), U256::from_usize(123));

    /*
    // Test the state machine of Uint256 values
    let mut sm = StateMachine256::new(DefaultConfig::default());

    let base_address: usize = sm.base_address().to_usize();
    sm.write(
        U256::from_usize(base_address),
        U256::from_be_bytes([1u8; 32]),
    )
    .unwrap();
    sm.write(
        U256::from_usize(base_address + 32),
        U256::from_be_bytes([2u8; 32]),
    )
    .unwrap();

    sm.write(
        U256::from_usize(base_address + 6),
        U256::from_be_bytes([3u8; 32]),
    )
    .unwrap();

    println!("{:?}", sm.read(U256::from_usize(base_address + 7)).unwrap());

    println!("{:?}", sm.read(U256::from_usize(base_address + 0)).unwrap());

    println!(
        "{:?}",
        sm.read(U256::from_usize(base_address + 32)).unwrap()
    );

    sm.push(U256::from_usize(123)).unwrap();

    sm.pop().unwrap();

    let r0 = sm.register(0).unwrap();
    let r1 = sm.register(1).unwrap();

    sm.set(r1, U256::from_be_bytes([9u8; 32])).unwrap();
    sm.mov(r0, r1).unwrap();

    // Check the memory trace
    println!("{:#064x?}", sm);

    let trace = sm.trace();

    println!("{:#064x?}", trace); */
}
