use crate::base::UsizeConvertible;
use core::ops::{Add, Mul};

/// Config for RAM machine
#[derive(Debug, Clone, Copy)]
pub struct Config<T> {
    /// Base address of memory
    pub memory_base: T,
    /// Size of a memory cell
    pub cell_size: T,
    /// Stack depth
    pub stack_depth: T,
    /// Stack base address
    pub stack_lo: T,
    /// Stack top address
    pub stack_hi: T,
    /// Register base address
    pub register_lo: T,
    /// Register top address
    pub register_hi: T,
}

/// Config arguments for RAM machine
pub struct ConfigArgs<T> {
    /// Start address of stack
    pub stack_base: T,
    /// Stack depth
    pub stack_depth: T,
    /// Number of registers
    pub no_register: T,
    /// Buffer size
    pub buffer_size: T,
    /// Size of a memory cell
    pub cell_size: T,
}

impl<T> ConfigArgs<T> {
    /// Create a new config arguments
    pub fn new(
        stack_base: T,
        stack_depth: T,
        no_register: T,
        buffer_size: T,
        cell_size: T,
    ) -> Self {
        Self {
            stack_base,
            stack_depth,
            no_register,
            buffer_size,
            cell_size,
        }
    }
}

/// Default config
pub struct DefaultConfig;

impl DefaultConfig {
    /// Create a default config for 256 bit machine
    pub fn default256() -> ConfigArgs<usize> {
        ConfigArgs::<usize>::new(0, 1024, 16, 64, 32)
    }

    /// Create a default config for 64 bit machine
    pub fn default64() -> ConfigArgs<usize> {
        ConfigArgs::<usize>::new(0, 1024, 16, 64, 8)
    }

    /// Create a default config for 32 bit machine
    pub fn default32() -> ConfigArgs<usize> {
        ConfigArgs::<usize>::new(0, 1024, 16, 64, 4)
    }
}

impl<T> Config<T>
where
    T: Mul<T, Output = T> + Add<T, Output = T> + Copy,
{
    /// Create a new config for given arguments
    pub fn new(args: ConfigArgs<T>) -> Self {
        let stack_lo = args.stack_base;
        let stack_hi = stack_lo + (args.stack_depth * args.cell_size);
        let register_lo = stack_hi + args.buffer_size;
        let register_hi = register_lo + (args.no_register * args.cell_size);
        let memory_base = register_hi + args.buffer_size;
        Self {
            stack_depth: args.stack_depth,
            stack_lo,
            stack_hi,
            register_lo,
            register_hi,
            cell_size: args.cell_size,
            memory_base,
        }
    }
}

impl<T> From<Config<usize>> for Config<T>
where
    T: UsizeConvertible,
{
    fn from(cfg: Config<usize>) -> Self {
        Self {
            stack_depth: T::from_usize(cfg.stack_depth),
            stack_lo: T::from_usize(cfg.stack_lo),
            stack_hi: T::from_usize(cfg.stack_hi),
            register_lo: T::from_usize(cfg.register_lo),
            register_hi: T::from_usize(cfg.register_hi),
            cell_size: T::from_usize(cfg.cell_size),
            memory_base: T::from_usize(cfg.memory_base),
        }
    }
}
