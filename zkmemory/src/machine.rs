extern crate alloc;
use crate::{base::Base, error::Error};
use alloc::vec::Vec;
use rbtree::RBTree;

/// Basic Memory Instruction
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryInstruction {
    /// Write to memory
    Write,

    /// Read from memory
    Read,
}

/// Trace record struct of [AbstractTraceRecord]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceRecord<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
{
    time_log: u64,
    stack_depth: u64,
    instruction: MemoryInstruction,
    address: K,
    value: V,
}

impl<K, V, const S: usize, const T: usize> TraceRecord<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    /// Return the tuple representation of the trace record
    pub fn get_tuple(&self) -> (u64, u64, MemoryInstruction, K, V) {
        (
            self.time_log,
            self.stack_depth,
            self.instruction,
            self.address,
            self.value,
        )
    }
}

#[derive(Debug)]
/// Cell interaction enum where K is the address and V is the value
pub enum CellInteraction<K, V> {
    /// Interactive with a single cell
    SingleCell(MemoryInstruction, K, V),

    /// Interactive with 2 cells
    /// Opcode concated(K,V) lo(K,V) hi(K,V)
    DoubleCell(MemoryInstruction, K, V, K, V, K, V),
}

/// Context of machine
pub trait AbstractContext<M, K, V>
where
    K: Ord,
    Self: core::fmt::Debug + Sized,
    M: AbstractMachine<K, V>,
{
    /// Get the memory
    fn memory(&mut self) -> &'_ mut RBTree<K, V>;

    /// Set the stack depth
    fn set_stack_depth(&mut self, stack_depth: u64);

    /// Set the time log
    fn set_time_log(&mut self, time_log: u64);

    /// Set the stack pointer
    fn set_stack_ptr(&mut self, stack_ptr: K);

    /// Get the stack pointer
    fn stack_ptr(&self) -> K;

    /// Get the current stack depth
    fn stack_depth(&self) -> u64;

    /// Get the time log
    fn time_log(&self) -> u64;
}

/// Public trait for all instructions.
pub trait AbstractInstruction<M, K, V>
where
    K: Ord,
    Self: core::fmt::Debug + Sized,
    M: AbstractMachine<K, V>,
{
    /// Execute the instruction on the context
    fn exec(&self, machine: &mut M::Machine);
}

/// Trace record
/// TIME_LOG, STACK_DEPTH, INSTRUCTION, ADDRESS, VALUE,  
pub trait AbstractTraceRecord<K, V>
where
    K: Ord,
    Self: Ord,
{
    /// Create a new trace record
    fn new(
        time_log: u64,
        stack_depth: u64,
        instruction: MemoryInstruction,
        address: K,
        value: V,
    ) -> Self;

    /// Get the time log
    fn time_log(&self) -> u64;

    /// Get the stack depth
    fn stack_depth(&self) -> u64;

    /// Get the address
    fn address(&self) -> K;

    /// Get the value
    fn value(&self) -> V;

    /// Get the instruction
    fn instruction(&self) -> MemoryInstruction;
}

/// The abstract machine that will be implemented by particular machine
pub trait AbstractMachine<K, V>
where
    Self: Sized,
    K: Ord,
{
    /// The type of machine
    type Machine: AbstractMachine<K, V>;

    /// Context of machine
    type Context: AbstractContext<Self, K, V>;

    /// Instruction set
    type Instruction: AbstractInstruction<Self, K, V>;

    /// Trace record
    type TraceRecord: AbstractTraceRecord<K, V>;

    /// Get the context of abstract machine
    fn context(&mut self) -> &'_ mut Self::Context;

    /// Get the read only context of abstract machine
    fn ro_context(&self) -> &'_ Self::Context;

    /// Get the WORD_SIZE of the addresss pace
    fn word_size(&self) -> K;

    /// Get the base address of the address space
    fn register_start(&self) -> K;

    /// Push the trace record to the trace
    fn track(&mut self, trace: Self::TraceRecord);

    /// Get the execution trace
    fn trace(&self) -> Vec<Self::TraceRecord>;

    /// Get the execution trace
    fn exec(&mut self, instruction: &Self::Instruction);

    /// Get the base address of the memory section
    fn base_address(&self) -> K;

    /// Get the range allocated of the memory section
    fn get_memory_address(&self) -> (K, K);

    /// Get the current stack depth of the machine
    fn get_stack_depth(&self) -> u64;

    /// Get max stack depth of the machine
    fn max_stack_depth(&self) -> u64;
}

/// Abstract RAM machine
pub trait AbstractMemoryMachine<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
    Self: AbstractMachine<K, V>,
{
    /// Read from memory
    fn read(&mut self, address: K) -> Result<CellInteraction<K, V>, Error> {
        let remain = address % self.word_size();
        if remain.is_zero() {
            // Read on a cell
            let result = self.dummy_read(address);
            let time_log = self.ro_context().time_log();
            self.track(Self::TraceRecord::new(
                time_log,
                self.ro_context().stack_depth(),
                MemoryInstruction::Read,
                address,
                result,
            ));
            self.context().set_time_log(time_log + 1);

            // Return single cell read
            Ok(CellInteraction::SingleCell(
                MemoryInstruction::Read,
                address,
                result,
            ))
        } else {
            // Get the address of 2 cells
            let (addr_lo, addr_hi) = self.compute_address(address, remain);
            let time_log = self.ro_context().time_log();
            // Get the 2 cells
            let val_lo = self.dummy_read(addr_lo);
            let val_hi = self.dummy_read(addr_hi);
            let cell_size = self.word_size().into();
            let part_lo = (address - addr_lo).into();
            let part_hi = cell_size - part_lo;
            let mut buf = [0u8; T];

            // Concat values from 2 cells
            buf[part_hi..cell_size]
                .copy_from_slice(&<V as Into<[u8; T]>>::into(val_hi)[0..part_lo]);
            buf[0..part_hi]
                .copy_from_slice(&<V as Into<[u8; T]>>::into(val_lo)[part_lo..cell_size]);

            // @TODO: Read in the middle of 2 cells need to be translated correctly
            self.track(Self::TraceRecord::new(
                time_log,
                self.ro_context().stack_depth(),
                MemoryInstruction::Read,
                addr_lo,
                val_lo,
            ));

            self.track(Self::TraceRecord::new(
                time_log + 1,
                self.ro_context().stack_depth(),
                MemoryInstruction::Read,
                addr_hi,
                val_hi,
            ));

            self.context().set_time_log(time_log + 2);

            // Return double cells read
            Ok(CellInteraction::DoubleCell(
                MemoryInstruction::Read,
                address,
                V::from(buf),
                addr_lo,
                val_lo,
                addr_hi,
                val_hi,
            ))
        }
    }

    /// Write to memory
    fn write(&mut self, address: K, value: V) -> Result<CellInteraction<K, V>, Error> {
        let remain = address % self.word_size();
        if remain.is_zero() {
            let time_log = self.ro_context().time_log();
            // Write on a cell
            self.context().memory().insert(address, value);
            self.track(Self::TraceRecord::new(
                time_log,
                self.ro_context().stack_depth(),
                MemoryInstruction::Write,
                address,
                value,
            ));

            self.context().set_time_log(time_log + 1);

            // Return single cell write
            Ok(CellInteraction::SingleCell(
                MemoryInstruction::Write,
                address,
                value,
            ))
        } else {
            // Get the address of 2 cells
            let (addr_lo, addr_hi) = self.compute_address(address, remain);
            let time_log = self.ro_context().time_log();
            // Calculate memory address and offset
            let cell_size = self.word_size().into();
            let part_lo: usize = (address - addr_lo).into();
            let part_hi = cell_size - part_lo;

            let val: [u8; T] = value.into();

            // Write the low part of value to the buffer
            let mut buf: [u8; T] = self.dummy_read(addr_lo).into();
            buf[part_lo..cell_size].copy_from_slice(&val[0..part_hi]);
            let val_lo = V::from(buf);

            // Write the high part of value to the buffer
            let mut buf: [u8; T] = self.dummy_read(addr_hi).into();
            buf[0..part_lo].copy_from_slice(&val[part_hi..cell_size]);
            let val_hi = V::from(buf);

            self.context().memory().replace_or_insert(addr_lo, val_lo);
            self.context().memory().replace_or_insert(addr_hi, val_hi);

            // @TODO: Write in the middle of 2 cells need to be translated correctly
            self.track(Self::TraceRecord::new(
                time_log,
                self.ro_context().stack_depth(),
                MemoryInstruction::Write,
                addr_lo,
                val_lo,
            ));

            self.track(Self::TraceRecord::new(
                time_log + 1,
                self.ro_context().stack_depth(),
                MemoryInstruction::Write,
                addr_hi,
                val_hi,
            ));

            self.context().set_time_log(time_log + 2);

            // Return double cells write
            Ok(CellInteraction::DoubleCell(
                MemoryInstruction::Write,
                address,
                value,
                addr_lo,
                val_lo,
                addr_hi,
                val_hi,
            ))
        }
    }

    /// Read from memory (only read one whole cell)
    fn dummy_read(&mut self, address: K) -> V {
        match self.context().memory().get(&address) {
            Some(r) => *r,
            None => V::zero(),
        }
    }

    /// Compute the addresses
    fn compute_address(&self, address: K, remain: K) -> (K, K) {
        let base = address - remain;
        (base, base + self.word_size())
    }
}

/// Abstract stack machine
pub trait AbstractStackMachine<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
    Self: AbstractMemoryMachine<K, V, S, T>,
{
    /// Push the value to the stack and return stack_depth
    fn push(&mut self, value: V) -> Result<(u64, CellInteraction<K, V>), Error> {
        // Check for stack overflow
        if self.ro_context().stack_depth() == self.max_stack_depth() {
            return Err(Error::StackOverflow);
        }
        // Update stack depth and stack pointer
        let stack_depth = self.ro_context().stack_depth() + 1;
        self.context().set_stack_depth(stack_depth);

        // Push first then update the stack pointer
        let address = self.ro_context().stack_ptr();
        let next_address = address + self.word_size();
        self.context().set_stack_ptr(next_address);

        match self.write(address, value) {
            Ok(v) => Ok((stack_depth, v)),
            Err(e) => Err(e),
        }
    }

    /// Get value from the stack and return stack_depth and value
    fn pop(&mut self) -> Result<(u64, CellInteraction<K, V>), Error> {
        // Check for stack underflow
        if self.ro_context().stack_depth() == 0 {
            return Err(Error::StackUnderflow);
        }
        // Update stack depth and stack pointer
        let stack_depth = self.ro_context().stack_depth() - 1;
        self.context().set_stack_depth(stack_depth);
        let address = self.ro_context().stack_ptr() - self.word_size();
        self.context().set_stack_ptr(address);

        match self.read(address) {
            Ok(v) => Ok((stack_depth, v)),
            Err(e) => Err(e),
        }
    }
}

/// Virtual register structure
#[derive(Debug, Clone, Copy)]
pub struct Register<K>(usize, K);

impl<K> Register<K>
where
    K: Copy,
{
    /// Create a new register
    pub fn new(register_index: usize, register_address: K) -> Self {
        Self(register_index, register_address)
    }

    /// Get the register address
    pub fn address(&self) -> K {
        self.1
    }

    /// Get the register index
    pub fn index(&self) -> usize {
        self.0
    }
}

/// Abstract register machine
pub trait AbstractRegisterMachine<K, V, const S: usize, const T: usize>
where
    K: Base<S>,
    V: Base<T>,
    Self: AbstractMemoryMachine<K, V, S, T>,
{
    /// Set the value of the register
    fn set(&mut self, register: Register<K>, value: V) -> Result<CellInteraction<K, V>, Error> {
        self.write(register.address(), value)
    }

    /// Get the value of the register
    fn get(&mut self, register: Register<K>) -> Result<CellInteraction<K, V>, Error> {
        self.read(register.address())
    }

    /// Create new register from index
    fn new_register(&self, register_index: usize) -> Option<Register<K>>;
}

impl<K, V, const S: usize, const T: usize> AbstractTraceRecord<K, V> for TraceRecord<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    fn new(
        time_log: u64,
        stack_depth: u64,
        instruction: MemoryInstruction,
        address: K,
        value: V,
    ) -> Self {
        Self {
            time_log,
            stack_depth,
            instruction,
            address,
            value,
        }
    }

    fn time_log(&self) -> u64 {
        self.time_log
    }

    fn stack_depth(&self) -> u64 {
        self.stack_depth
    }

    fn address(&self) -> K {
        self.address
    }

    fn value(&self) -> V {
        self.value
    }

    fn instruction(&self) -> MemoryInstruction {
        self.instruction
    }
}

impl<K, V, const S: usize, const T: usize> PartialOrd for TraceRecord<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<K, V, const S: usize, const T: usize> Ord for TraceRecord<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match self.time_log.cmp(&other.time_log) {
            core::cmp::Ordering::Equal => {
                panic!("Time log never been equal")
            }
            ord => ord,
        }
    }
}

// pub trait KZGMemoryCommitment

#[macro_export]
/// Export macro for implementing [AbstractMemoryMachine](crate::machine::AbstractMemoryMachine) trait
macro_rules! impl_state_machine {
    ($machine_struct: ident) => {
        use zkmemory::machine::AbstractMemoryMachine;

        impl<K, V, const S: usize, const T: usize> AbstractMemoryMachine<K, V, S, T>
            for $machine_struct<K, V, S, T>
        where
            K: Base<S>,
            V: Base<T>,
            Self: AbstractMachine<K, V>,
        {
        }
    };
}

#[macro_export]
/// Export macro for implementing [AbstractRegisterMachine](crate::machine::AbstractRegisterMachine) trait
macro_rules! impl_register_machine {
    ($machine_struct: ident) => {
        use zkmemory::machine::AbstractRegisterMachine;

        impl<K, V, const S: usize, const T: usize> AbstractRegisterMachine<K, V, S, T>
            for $machine_struct<K, V, S, T>
        where
            K: Base<S>,
            V: Base<T>,
            Self: AbstractMemoryMachine<K, V, S, T>,
        {
            fn new_register(
                &self,
                register_index: usize,
            ) -> Option<zkmemory::machine::Register<K>> {
                Some(Register::new(
                    register_index,
                    self.register_start() + K::from(register_index) * K::WORD_SIZE,
                ))
            }
        }
    };
}

#[macro_export]
/// Export macro for implementing [AbstractStackMachine](crate::machine::AbstractStackMachine) trait
macro_rules! impl_stack_machine {
    ($machine_struct: ident) => {
        use zkmemory::machine::AbstractStackMachine;

        impl<K, V, const S: usize, const T: usize> AbstractStackMachine<K, V, S, T>
            for $machine_struct<K, V, S, T>
        where
            K: Base<S>,
            V: Base<T>,
            Self: AbstractMemoryMachine<K, V, S, T>,
        {
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::{
        base::{Base, B256},
        config::{AllocatedSection, Config, ConfigArgs, DefaultConfig},
        error::Error,
        machine::{
            AbstractContext, AbstractInstruction, AbstractMachine, AbstractMemoryMachine,
            AbstractRegisterMachine, AbstractStackMachine, CellInteraction, Register, TraceRecord,
        },
    };
    extern crate alloc;
    extern crate std;
    use alloc::{vec, vec::Vec};
    use core::marker::PhantomData;
    use rbtree::RBTree;

    /// My instruction set for the machine
    #[derive(Debug, Clone, Copy)]
    pub enum MyInstruction<M, K, V, const S: usize, const T: usize>
    where
        K: Base<S>,
        V: Base<T>,
    {
        /// Read from memory
        Read(K),
        /// Write to memory
        Write(K, V),
        /// Push to stack
        Push(V),
        /// Pop from stack
        Pop(),
        /// Move from register to register (Mov(r2, r1) moves the value of r1 to r2)
        Mov(Register<K>, Register<K>),
        /// Swap value from top stack  to register
        Swap(Register<K>),
        /// Load from memory to register
        Load(Register<K>, K),
        /// Save from register to memory
        Save(K, Register<K>),
        /// Invalid instruction
        Invalid(PhantomData<M>),
        /// Add two registers, register 1 = register 1 + register 2
        Add(Register<K>, Register<K>),
    }

    /// Type alias Instruction
    pub type Instruction = MyInstruction<StateMachine<B256, B256, 32, 32>, B256, B256, 32, 32>;

    /// RAM Machine
    #[derive(Debug, Clone)]
    pub struct StateMachine<K, V, const S: usize, const T: usize>
    where
        K: Base<S>,
        V: Base<T>,
    {
        // Memory
        memory: RBTree<K, V>,
        memory_allocated: AllocatedSection<K>,
        word_size: K,
        time_log: u64,

        // Stack
        stack_allocated: AllocatedSection<K>,
        max_stack_depth: u64,
        stack_depth: u64,
        stack_ptr: K,

        // Register
        register_allocated: AllocatedSection<K>,

        /// Register r0
        pub r0: Register<K>,
        /// Register r1
        pub r1: Register<K>,
        /// Register r2
        pub r2: Register<K>,
        /// Register r3
        pub r3: Register<K>,
        /// Register r4
        pub r4: Register<K>,

        // Trace
        execution_trace: RBTree<TraceRecord<K, V, S, T>, PhantomData<()>>,
    }

    impl<M, K, V, const S: usize, const T: usize> AbstractContext<M, K, V> for StateMachine<K, V, S, T>
    where
        Self: core::fmt::Debug
            + Sized
            + AbstractMachine<K, V, Context = M::Context, Instruction = M::Instruction>,
        K: Base<S>,
        V: Base<T>,
        M: AbstractMachine<K, V, Machine = StateMachine<K, V, S, T>>,
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
        M: AbstractMachine<K, V, Machine = StateMachine<K, V, S, T>>,
    {
        fn exec(&self, machine: &mut M::Machine) {
            match self {
                MyInstruction::Invalid(_) => {
                    panic!("Invalid instruction")
                }
                MyInstruction::Read(addr) => {
                    if !machine.memory_allocated.contain(*addr) {
                        panic!("{}", Error::MemoryAccessDeinied);
                    } else {
                        machine.read(*addr).expect("Unable to read to memory");
                    }
                }
                MyInstruction::Write(addr, val) => {
                    if !machine.memory_allocated.contain(*addr) {
                        panic!("{}", Error::MemoryAccessDeinied);
                    } else {
                        machine
                            .write(*addr, *val)
                            .expect("Unable to write to memory");
                    }
                }
                MyInstruction::Push(value) => {
                    machine.push(*value).expect("Unable to push value to stack");
                }
                MyInstruction::Pop() => {
                    machine.pop().expect("Unable to pop value from stack");
                }
                MyInstruction::Mov(reg1, reg2) => {
                    match machine.get(*reg2).expect("Unable to access register 1") {
                        CellInteraction::SingleCell(_, _, value) => {
                            machine.set(*reg1, value).expect("Unable to set register 2");
                        }
                        _ => panic!("Register unable to be two cells"),
                    }
                    // Mov value from register 2 to register 1
                }
                MyInstruction::Swap(reg) => {
                    match machine.pop().expect("Unable to pop value from stack") {
                        (_, CellInteraction::SingleCell(_op, _addr, value)) => {
                            machine
                                .push(value)
                                .expect("Unable to push register's value to stack");
                            machine.set(*reg, value).expect("Unable to set register");
                        }
                        _ => panic!("Stack unable to be two cells"),
                    };
                }
                MyInstruction::Load(reg, addr) => {
                    match machine.read(*addr).expect("Unable to read memory") {
                        CellInteraction::SingleCell(_, _, value) => {
                            machine.set(*reg, value).expect("Unable to set register");
                        }
                        CellInteraction::DoubleCell(_, _, cvalue, _, _, _, _) => {
                            machine.set(*reg, cvalue).expect("Unable to set register");
                        }
                    };
                }
                MyInstruction::Save(address, reg) => {
                    match machine.get(*reg).expect("Unable to access register") {
                        CellInteraction::SingleCell(_, _, value) => {
                            machine
                                .write(*address, value)
                                .expect("Unable to write to memory");
                        }
                        _ => panic!("Register unable to be two cells"),
                    }
                }
                MyInstruction::Add(reg1, reg2) => {
                    match machine.get(*reg1).expect("Unable to access register 1") {
                        CellInteraction::SingleCell(_, _, value1) => {
                            match machine.get(*reg2).expect("Unable to access register 2") {
                                CellInteraction::SingleCell(_, _, value2) => {
                                    machine
                                        .set(*reg1, value1 + value2)
                                        .expect("Unable to set register 1");
                                }
                                _ => panic!("Register unable to be two cells"),
                            }
                        }
                        _ => panic!("Register unable to be two cells"),
                    }
                }
            }
        }
    }

    impl<K, V, const S: usize, const T: usize> StateMachine<K, V, S, T>
    where
        K: Base<S>,
        V: Base<T>,
    {
        /// Create a new RAM machine
        pub fn new(config: ConfigArgs<K>) -> Self {
            let config = Config::new(K::WORD_SIZE, config);
            Self {
                // Memory section
                memory: RBTree::new(),
                memory_allocated: config.memory,
                word_size: config.word_size,
                time_log: 0,

                // Stack
                stack_allocated: config.stack,
                max_stack_depth: config.stack_depth.into(),
                stack_depth: 0,
                stack_ptr: K::zero(),

                // Register
                register_allocated: config.register,
                r0: config.create_register(0),
                r1: config.create_register(1),
                r2: config.create_register(2),
                r3: config.create_register(3),
                r4: config.create_register(4),

                // Execution trace
                execution_trace: RBTree::new(),
            }
        }
    }

    impl<K, V, const S: usize, const T: usize> AbstractMachine<K, V> for StateMachine<K, V, S, T>
    where
        K: Base<S>,
        V: Base<T>,
    {
        type Machine = Self;
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
            self.register_allocated.low()
        }

        fn ro_context(&self) -> &'_ Self::Context {
            self
        }

        fn track(&mut self, trace: Self::TraceRecord) {
            self.execution_trace.insert(trace, PhantomData);
        }

        fn trace(&self) -> Vec<Self::TraceRecord> {
            self.execution_trace.keys().copied().collect()
        }

        fn exec(&mut self, instruction: &Self::Instruction) {
            instruction.exec(self);
        }

        fn base_address(&self) -> K {
            self.memory_allocated.low()
        }

        fn get_memory_address(&self) -> (K, K) {
            (self.memory_allocated.low(), self.memory_allocated.high())
        }

        fn get_stack_depth(&self) -> u64 {
            self.ro_context().stack_depth
        }

        fn max_stack_depth(&self) -> u64 {
            self.ro_context().max_stack_depth
        }
    }

    impl<K, V, const S: usize, const T: usize> AbstractMemoryMachine<K, V, S, T>
        for StateMachine<K, V, S, T>
    where
        K: Base<S>,
        V: Base<T>,
        Self: AbstractMachine<K, V>,
    {
    }

    impl<K, V, const S: usize, const T: usize> AbstractRegisterMachine<K, V, S, T>
        for StateMachine<K, V, S, T>
    where
        K: Base<S>,
        V: Base<T>,
        Self: AbstractMemoryMachine<K, V, S, T>,
    {
        fn new_register(&self, register_index: usize) -> Option<crate::machine::Register<K>> {
            Some(Register::new(
                register_index,
                self.register_start() + K::from(register_index) * K::WORD_SIZE,
            ))
        }
    }

    impl<K, V, const S: usize, const T: usize> AbstractStackMachine<K, V, S, T>
        for StateMachine<K, V, S, T>
    where
        K: Base<S>,
        V: Base<T>,
        Self: AbstractMemoryMachine<K, V, S, T>,
    {
    }

    #[test]
    fn test_read_write_one_cell() {
        let mut sm = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default_config());
        let base = sm.base_address();
        let write_chunk = B256::from(1025);
        let program = vec![
            Instruction::Write(base + B256::from(32), B256::from(1025)),
            Instruction::Read(base + B256::from(32)),
        ];
        // Execute the program
        for instruction in program {
            sm.exec(&instruction);
        }
        assert_eq!(write_chunk, sm.dummy_read(base + B256::from(32)));
    }

    #[test]
    fn test_read_write_two_cells() {
        let mut sm = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default_config());
        let base = sm.base_address();
        let write_chunk = [5u8; 32];
        let program = vec![
            Instruction::Write(base + B256::from(1), B256::from(write_chunk)),
            Instruction::Read(base + B256::from(0)),
            Instruction::Read(base + B256::from(32)),
            Instruction::Read(base + B256::from(1)),
        ];
        // Execute the program
        for instruction in program {
            sm.exec(&instruction);
        }
        let read_chunk_low = {
            let mut buffer = [5u8; 32];
            buffer[0] = 0u8;
            buffer
        };

        let read_chunk_high = {
            let mut buffer = [0u8; 32];
            buffer[0] = 5u8;
            buffer
        };

        assert_eq!(sm.dummy_read(base), B256::from(read_chunk_low));
        assert_eq!(
            sm.dummy_read(base + B256::from(32)),
            B256::from(read_chunk_high)
        );
    }

    #[test]
    fn test_arithmetics() {
        let chunk1 = [5u8; 32];
        let chunk2 = [190u8; 32];
        let add_chunk = [195u8; 32];

        let mut sm = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default_config());

        let base = sm.base_address();
        let program = vec![
            Instruction::Write(base + B256::from(0), B256::from(chunk1)),
            Instruction::Write(base + B256::from(32), B256::from(chunk2)),
            Instruction::Load(sm.r0, base + B256::from(0)),
            Instruction::Load(sm.r1, base + B256::from(32)),
            Instruction::Add(sm.r0, sm.r1),
            Instruction::Save(base + B256::from(64), sm.r0),
        ];
        // Execute the program
        for instruction in program {
            sm.exec(&instruction);
        }

        assert_eq!(sm.dummy_read(base + B256::from(64)), B256::from(add_chunk));
    }

    #[test]
    fn test_stack_machine() {
        let mut sm = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default_config());

        assert_eq!(sm.stack_allocated.low(), B256::zero());
        let base = sm.base_address();
        let program = vec![
            Instruction::Push(B256::from(1000)),
            Instruction::Push(B256::from(170)),
            Instruction::Swap(sm.r0),
            Instruction::Pop(),
            Instruction::Swap(sm.r1),
            Instruction::Pop(),
            Instruction::Mov(sm.r2, sm.r0),
            Instruction::Save(base + B256::from(128), sm.r0),
            Instruction::Save(base + B256::from(160), sm.r1),
            Instruction::Save(base + B256::from(192), sm.r2),
        ];
        // Execute program1
        for instruction in program {
            sm.exec(&instruction);
        }

        assert_eq!(sm.dummy_read(base + B256::from(128)), B256::from(170));
        assert_eq!(sm.dummy_read(base + B256::from(160)), B256::from(1000));
        assert_eq!(sm.dummy_read(base + B256::from(192)), B256::from(170));
    }

    #[test]
    fn test_stack_machine_part_two() {
        let mut sm = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default_config());

        assert_eq!(sm.stack_allocated.low(), B256::zero());
        let base = sm.base_address();
        let program = vec![
            Instruction::Push(B256::from(1000)),
            Instruction::Push(B256::from(170)),
            Instruction::Swap(sm.r0),
            Instruction::Pop(),
            Instruction::Swap(sm.r1),
            Instruction::Pop(),
            Instruction::Mov(sm.r3, sm.r0),
            Instruction::Save(base + B256::from(128), sm.r0),
            Instruction::Save(base + B256::from(160), sm.r1),
            Instruction::Save(base + B256::from(192), sm.r3),
            Instruction::Mov(sm.r3, sm.r4),
        ];
        // Execute program1
        for instruction in program {
            sm.exec(&instruction);
        }

        assert_eq!(sm.dummy_read(base + B256::from(128)), B256::from(170));
        assert_eq!(sm.dummy_read(base + B256::from(160)), B256::from(1000));
        assert_eq!(sm.dummy_read(base + B256::from(192)), B256::from(170));
    }

    #[test]
    #[should_panic]
    fn test_invalid_instruction() {
        let mut sm = StateMachine::<B256, B256, 32, 32>::new(DefaultConfig::default_config());
        let program = vec![Instruction::Invalid(PhantomData)];

        for instruction in program {
            sm.exec(&instruction);
        }
    }
}
