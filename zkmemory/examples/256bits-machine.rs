use ethnum::U256;
use rbtree::RBTree;
use std::marker::PhantomData;
use zkmemory::base::{Base, UsizeConvertible};
use zkmemory::machine::TraceRecord;
use zkmemory::{
    impl_register_machine, impl_stack_machine, impl_state_machine,
    machine::{AbstractContext, AbstractInstruction, AbstractMachine, Register},
};

#[derive(Debug)]
pub enum MyInstruction<M, K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Read from memory
    Read(K, V),
    /// Write to memory
    Write(K, V),
    /// Push to stack
    Push(V),
    /// Pop from stack
    Pop(V),
    /// Move from register to register
    Mov(Register<K>, Register<K>),
    /// Swap value from top stack  to register
    Swap(Register<K>),
    /// Load from memory to register
    Load(Register<K>, K),
    /// Save from register to memory
    Save(K, Register<K>),
    /// Invalid instruction
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
    time_log: u64,

    // Stack
    stack_start: K,
    stack_end: K,
    stack_depth: u64,
    stack_ptr: K,

    // Register
    register_start: K,
    register_end: K,
    r0: Register<K>,
    r1: Register<K>,
    r2: Register<K>,
    r3: Register<K>,
}

impl<M, K, V, const S: usize, const T: usize> AbstractContext<M, K, V> for StateMachine<K, V, S, T>
where
    Self: core::fmt::Debug
        + Sized
        + AbstractMachine<K, V, Context = M::Context, Instruction = M::Instruction>,
    K: Base<S>,
    V: Base<T>,
    M: AbstractMachine<K, V>,
{
    fn set_stack_depth(&mut self, stack_depth: u64) {
        self.stack_depth = stack_depth;
    }

    fn stack_depth(&self) -> u64 {
        self.stack_depth
    }

    fn stack_ptr(&self) -> K {
        self.stack_ptr
    }

    fn time_log(&self) -> u64 {
        self.time_log
    }

    fn set_time_log(&mut self, time_log: u64) {
        self.time_log = time_log;
    }

    fn apply(&mut self, instruction: &mut M::Instruction) {
        instruction.exec(self.context());
    }

    fn set_stack_ptr(&mut self, stack_ptr: K) {
        self.stack_ptr = stack_ptr;
    }

    fn memory(&mut self) -> &'_ mut RBTree<K, V> {
        &mut self.memory
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
    fn exec(&self, context: &mut M::Context) {}
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
            stack_start: K::from_usize(0),
            stack_end: K::from_usize(0),
            stack_depth: 0,
            stack_ptr: K::from_usize(0),
            register_start: K::from_usize(0),
            register_end: K::from_usize(0),
            r0: Register::new(0, K::from_usize(0)),
            r1: Register::new(1, K::from_usize(0)),
            r2: Register::new(2, K::from_usize(0)),
            r3: Register::new(3, K::from_usize(0)),
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
    type TraceRecord = TraceRecord<K, V, S, T>;

    fn context(&mut self) -> &'_ mut Self::Context {
        self
    }

    fn word_size(&self) -> K {
        self.word_size
    }

    fn register_start(&self) -> K {
        self.register_start
    }

    fn ro_context(&self) -> &'_ Self::Context {
        todo!()
    }

    fn track(&mut self, trace: Self::TraceRecord) {
        todo!()
    }

    fn trace(&self) -> &'_ Vec<Self::TraceRecord> {
        todo!()
    }
}

impl_register_machine!(StateMachine);
impl_stack_machine!(StateMachine);
impl_state_machine!(StateMachine);

fn main() {
    let mut a = StateMachine::<U256, U256, 32, 32>::new();
    a.write(U256::from_usize(0), U256::from_usize(123)).unwrap();

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
