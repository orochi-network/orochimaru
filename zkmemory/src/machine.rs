extern crate alloc;
use alloc::vec::Vec;
use crate::{base::Base, error::Error};
use halo2curves::bn256::{Bn256, G1, Fr};
use rbtree::RBTree;
use halo2_proofs::{
    arithmetic::{lagrange_interpolate, best_multiexp},
    poly::{Polynomial, Coeff, EvaluationDomain},
    poly::commitment::ParamsProver,
    poly::kzg::commitment::ParamsKZG,
};

/// Basic Memory Instruction
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryInstruction {
    /// Write to memory
    Write,

    /// Read from memory
    Read,
}

/// Trace record struct of [AbstractTraceRecord](crate::machine::AbstractTraceRecord)
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Get the KZG params
    fn get_params_domain(&self) -> (ParamsKZG<Bn256>, EvaluationDomain<Fr>);
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
pub trait AbstractTraceRecord<M: AbstractMachine<K, V>, K, V>
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
    type TraceRecord: AbstractTraceRecord<Self, K, V>;

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

    /// Get the KZG params
    fn get_params_domain(&self) -> (ParamsKZG<Bn256>, EvaluationDomain<Fr>);
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
            _ = self.commit_memory_state();

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
            _ = self.commit_memory_state();

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
            _ = self.commit_memory_state();

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
            _ = self.commit_memory_state();

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
            Some(r) => r.clone(),
            None => V::zero(),
        }
    }

    /// Compute the addresses
    fn compute_address(&self, address: K, remain: K) -> (K, K) {
        let base = address - remain;
        (base, base + self.word_size())
    }

    /// Get all RAM cells (excluding buffers) as a vector of 2-tuple (K, V)
    fn get_memory_cells(&mut self) -> Vec<(K, V)> {
        let mut kv_vec = Vec::new();
        let (base, terminal) = self.get_memory_address();
        let mut index = base;
        while index < terminal {
            kv_vec.push((index, self.dummy_read(index)));
            index = index + self.word_size();
        }
        kv_vec
    }

    /// Commit to a polynomial, the result is in G1
    fn commit_polynomial_in_g1(&self, poly: Polynomial<Fr, Coeff>) -> G1 {
        let (params, _) = self.get_params_domain();
        let mut scalars = Vec::with_capacity(poly.len());
        scalars.extend(poly.iter());
        let bases = params.get_g();
        let size = scalars.len();
        assert!(bases.len() >= size);
        best_multiexp(&scalars, &bases[0..size])
    }

    /// Convert points of type Base<S> to Fr element
    fn base_to_field_elements(&self, points: Vec<(K, V)>) -> Vec<(Fr, Fr)> {
        let mut field_point_vec: Vec<(Fr, Fr)> = Vec::new();
        for (point, value) in points.into_iter() {
            field_point_vec.push((
                self.be_bytes_to_field(point.zfill32().as_mut_slice()), 
                self.be_bytes_to_field(value.zfill32().as_mut_slice())));
        }
        field_point_vec
    }

    /// Convert raw bytes from big endian to Fr element
    fn be_bytes_to_field(&self, bytes: &mut [u8]) -> Fr {
        bytes.reverse();
        let b = bytes.as_ref();
        let inner =
        [0, 8, 16, 24].map(|i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap()));
        Fr::from_raw(inner)
    }

    /// Use lagrange interpolation to form a polynomial from points
    fn lagrange_from_points(&self, points: Vec<(Fr, Fr)>) -> Polynomial<Fr, Coeff> {
        let (_, domain) = self.get_params_domain();
        let point: Vec<Fr> = points.iter().map(|&(a, _)| a).collect();
        let value: Vec<Fr> = points.iter().map(|&(_, b)| b).collect();
        let poly_coefficients = lagrange_interpolate(&point, &value);
        domain.coeff_from_vec(poly_coefficients)
    }

    /// Commit the memory state
    fn commit_memory_state(&mut self) -> G1 {
        let cells = self.get_memory_cells();
        let points_vec = self.base_to_field_elements(cells);
        let state_poly = self.lagrange_from_points(points_vec);
        let commitment = self.commit_polynomial_in_g1(state_poly);
        commitment
    }

    /// Get the memory state represented as a polynomial
    fn get_poly_state(&mut self) -> Polynomial<Fr, Coeff> {
        let cells = self.get_memory_cells();
        let points_vec = self.base_to_field_elements(cells);
        self.lagrange_from_points(points_vec)
    }

    /// Verify the polynomial state is valid
    fn verify_poly(&mut self, commitment: G1) -> bool {
        let state_commitment = self.commit_memory_state();
        state_commitment == commitment
    }

    // /// Get KZG params
    // fn get_kzg_params(&self) -> {

    // }

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
            Err(e) => return Err(e),
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
            Err(e) => return Err(e),
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

impl<M, K, V, const S: usize, const T: usize> AbstractTraceRecord<M, K, V>
    for TraceRecord<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
    M: AbstractMachine<K, V>,
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
        match self.address.partial_cmp(&other.address) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        match self.instruction.partial_cmp(&other.instruction) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        match self.time_log.partial_cmp(&other.time_log) {
            Some(core::cmp::Ordering::Equal) => {
                panic!("Time log never been equal")
            }
            ord => return ord,
        }
    }
}

impl<K, V, const S: usize, const T: usize> Ord for TraceRecord<K, V, S, T>
where
    K: Base<S>,
    V: Base<T>,
{
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.partial_cmp(other)
            .expect("Two trace records wont be equal")
    }
}

// pub trait KZGMemoryCommitment


#[macro_export]
/// Export macro for implementing [AbstractMemoryMachine](crate::state_machine::AbstractMemoryMachine) trait
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
/// Export macro for implementing [AbstractRegisterMachine](crate::register_machine::AbstractRegisterMachine) trait
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
/// Export macro for implementing [AbstractStackMachine](crate::stack_machine::AbstractStackMachine) trait
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
