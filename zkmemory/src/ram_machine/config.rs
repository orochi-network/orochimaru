use crate::base::Base;

/// Memory section
#[derive(Debug, Clone, Copy)]
pub struct AllocatedSection<T>(T, T);

impl<T> AllocatedSection<T>
where
    T: PartialEq + PartialOrd + Copy,
{
    /// Check if the address is in the section
    pub fn contain(&self, address: T) -> bool {
        address >= self.0 && address <= self.1
    }

    /// Get the low address
    pub fn low(&self) -> T {
        self.0
    }

    /// Get the high address
    pub fn high(&self) -> T {
        self.1
    }
}

/// Config for RAM machine
#[derive(Debug, Clone, Copy)]
pub struct Config<T, const S: usize> {
    /// Size of a memory cell
    pub cell_size: T,
    /// Stack depth
    pub stack_depth: T,
    /// Base address of memory
    pub memory: AllocatedSection<T>,
    /// Stack base address
    pub stack: AllocatedSection<T>,
    /// Register base address
    pub register: AllocatedSection<T>,
}

/// Config arguments for RAM machine
pub struct ConfigArgs<T> {
    /// Is head layout
    pub head_layout: bool,
    /// Stack depth
    pub stack_depth: T,
    /// Number of registers
    pub no_register: T,
    /// Buffer size
    pub buffer_size: T,
}

/// Default config
pub struct DefaultConfig;

impl DefaultConfig {
    /// Create a default config
    pub fn default<const S: usize, T: Base<S>>() -> ConfigArgs<T> {
        ConfigArgs {
            head_layout: true,
            stack_depth: T::from_usize(1024),
            no_register: T::from_usize(16),
            buffer_size: T::from_usize(32),
        }
    }
}

impl<T, const S: usize> Config<T, S>
where
    T: Base<S>,
{
    /// Create a new config for given arguments
    pub fn new(cell_size: T, args: ConfigArgs<T>) -> Self {
        if args.head_layout {
            let stack_lo = T::MIN;
            let stack_hi = stack_lo + (args.stack_depth * cell_size);
            let register_lo = stack_hi + args.buffer_size;
            let register_hi = register_lo + (args.no_register * cell_size);
            let memory_lo = register_hi + args.buffer_size;
            let memory_hi = T::MAX;
            Self {
                cell_size: cell_size,
                stack_depth: args.stack_depth,
                stack: AllocatedSection(stack_lo, stack_hi),
                register: AllocatedSection(register_lo, register_hi),
                memory: AllocatedSection(memory_lo, memory_hi),
            }
        } else {
            let length =
                (args.stack_depth + args.no_register + args.buffer_size + args.buffer_size)
                    * cell_size;
            let stack_lo = T::MAX - length;
            let remain = stack_lo % cell_size;
            let stack_lo = stack_lo - remain + cell_size;
            let stack_hi = stack_lo + (args.stack_depth * cell_size);
            let register_lo = stack_hi + args.buffer_size;
            let register_hi = register_lo + (args.no_register * cell_size);
            let memory_lo = T::MIN;
            let memory_hi = T::MAX - length;
            Self {
                cell_size: cell_size,
                stack_depth: args.stack_depth,
                stack: AllocatedSection(stack_lo, stack_hi),
                register: AllocatedSection(register_lo, register_hi),
                memory: AllocatedSection(memory_lo, memory_hi),
            }
        }
    }
}
