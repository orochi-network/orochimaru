use crate::base::Base;
use crate::machine::Register;

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
    pub word_size: T,
    /// Stack depth
    pub stack_depth: T,
    /// Buffer size
    pub buffer_size: T,
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
    /// Number of memory cell
    pub no_memory_cell: T,
}

/// Default config
pub struct DefaultConfig;

impl DefaultConfig {
    /// Create a default config
    pub fn default<const S: usize, T: Base<S>>() -> ConfigArgs<T> {
        ConfigArgs {
            head_layout: true,
            stack_depth: T::from(1024),
            no_register: T::from(32),
            buffer_size: T::from(32),
            no_memory_cell: T::from(1024)
        }
    }
}

impl<T, const S: usize> Config<T, S>
where
    T: Base<S>,
{
    /// Create a new config for given arguments
    pub fn new(word_size: T, args: ConfigArgs<T>) -> Self {
        if args.head_layout {
            let stack_lo = T::MIN;
            let stack_hi = stack_lo + (args.stack_depth * word_size);
            let register_lo = stack_hi + args.buffer_size;
            let register_hi = register_lo + (args.no_register * word_size);
            let memory_lo = register_hi + args.buffer_size;
            let memory_hi = memory_lo + (args.no_memory_cell * word_size);
            Self {
                word_size,
                stack_depth: args.stack_depth,
                buffer_size: args.buffer_size,
                stack: AllocatedSection(stack_lo, stack_hi),
                register: AllocatedSection(register_lo, register_hi),
                memory: AllocatedSection(memory_lo, memory_hi),
            }
        } else {
            let memory_lo = T::MIN;
            let memory_hi = memory_lo + (args.no_memory_cell * word_size);
            let stack_lo = memory_hi + args.buffer_size;
            let stack_hi = stack_lo + (args.stack_depth * word_size);
            let register_lo = stack_hi + args.buffer_size;
            let register_hi = register_lo + (args.no_register * word_size);

            Self {
                word_size: word_size,
                stack_depth: args.stack_depth,
                buffer_size: args.buffer_size,
                stack: AllocatedSection(stack_lo, stack_hi),
                register: AllocatedSection(register_lo, register_hi),
                memory: AllocatedSection(memory_lo, memory_hi),
            }
        }
    }

    /// Create a new register by index
    pub fn create_register(&self, index: usize) -> Register<T> {
        Register::new(
            index,
            self.register.low() + (T::from(index) * self.word_size),
        )
    }

    /// Computes the total volume of RAM in bytes
    pub fn calc_ram_size(&self) -> T {
        let stack_size = self.word_size * self.stack_depth;
        let register_size = self.register.high() - self.register.low();
        let memory_size = self.memory.high() - self.memory.low();
        stack_size + register_size + memory_size + self.buffer_size + self.buffer_size
    }
}
