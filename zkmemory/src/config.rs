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
            let memory_hi = T::MAX;
            Self {
                word_size,
                stack_depth: args.stack_depth,
                buffer_size: args.buffer_size,
                stack: AllocatedSection(stack_lo, stack_hi),
                register: AllocatedSection(register_lo, register_hi),
                memory: AllocatedSection(memory_lo, memory_hi),
            }
        } else {
            let length =
                (args.stack_depth + args.no_register + args.buffer_size + args.buffer_size)
                    * word_size;
            let stack_lo = T::MAX - length;
            let remain = stack_lo % word_size;
            let stack_lo = stack_lo - remain + word_size;
            let stack_hi = stack_lo + (args.stack_depth * word_size);
            let register_lo = stack_hi + args.buffer_size;
            let register_hi = register_lo + (args.no_register * word_size);
            let memory_lo = T::MIN;
            let memory_hi = T::MAX - length;

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
}
