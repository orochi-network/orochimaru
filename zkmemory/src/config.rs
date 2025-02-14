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
#[derive(Debug)]
pub struct ConfigArgs<T> {
    /// Is head layout
    pub head_layout: bool,
    /// Stack depth
    pub stack_depth: T,
    /// Number of registers
    pub no_register: T,
    /// Buffer size in words
    pub buffer_size: T,
}

/// Default config
pub struct DefaultConfig;

impl DefaultConfig {
    /// Create a default config
    pub fn default_config<const S: usize, T: Base<S>>() -> ConfigArgs<T> {
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
            // [stack - buffer - register - buffer - memory]
            let stack_lo = T::MIN;
            let stack_hi = stack_lo + (args.stack_depth * word_size);
            let register_lo = stack_hi + args.buffer_size * word_size;
            let register_hi = register_lo + (args.no_register * word_size);
            let memory_lo = register_hi + args.buffer_size * word_size;
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
            // [memory - buffer - stack - buffer - register]
            let stack_register_buffer_total_size =
                (args.stack_depth + args.no_register + args.buffer_size + args.buffer_size)
                    * word_size;
            let stack_lo = T::MAX - stack_register_buffer_total_size;
            let remain = stack_lo % word_size;
            let stack_lo = stack_lo - remain; // Align to the nearest previous word-aligned address to ensure sufficient allocation for stack and register sections.
            let stack_hi = stack_lo + (args.stack_depth * word_size);
            let register_lo = stack_hi + args.buffer_size * word_size;
            let register_hi = register_lo + (args.no_register * word_size);
            let memory_lo = T::MIN;
            let memory_hi = stack_lo - args.buffer_size * word_size;

            Self {
                word_size,
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

#[cfg(test)]
mod tests {
    use super::ConfigArgs;
    use crate::base::{Base, B256};
    use crate::config::{Config, DefaultConfig};

    impl PartialEq for ConfigArgs<B256> {
        fn eq(&self, other: &Self) -> bool {
            self.head_layout == other.head_layout
                && self.stack_depth == other.stack_depth
                && self.no_register == other.no_register
                && self.buffer_size == other.buffer_size
        }
    }

    #[test]
    fn test_default_config() {
        let config = ConfigArgs {
            head_layout: true,
            stack_depth: B256::from(1024),
            no_register: B256::from(32),
            buffer_size: B256::from(32),
        };
        assert_eq!(config, DefaultConfig::default_config());
    }

    #[test]
    fn test_config_sections() {
        // Test memory section
        let config = Config::<B256, 32>::new(B256::from(32), DefaultConfig::default_config());
        assert!(config.memory.contain(B256::MAX - B256::from(1)));

        assert_eq!(config.stack.low(), B256::from(0));
        assert_eq!(
            config.register.low(),
            B256::from(config.stack.high() + config.buffer_size * config.word_size)
        );
        assert_eq!(
            config.memory.low(),
            B256::from(config.register.high() + config.buffer_size * config.word_size)
        );
        assert_eq!(config.memory.high(), B256::MAX);

        let no_register = B256::from(32);
        // Test tail layout
        let config = Config::<B256, 32>::new(
            B256::from(32),
            ConfigArgs {
                head_layout: false,
                stack_depth: B256::from(1024),
                no_register,
                buffer_size: B256::from(32),
            },
        );

        assert!(config.memory.contain(B256::from(0x10000f)));
        assert_eq!(config.memory.low(), B256::from(0));
        assert_eq!(
            config.memory.high(),
            B256::from(config.stack.low() - config.buffer_size * config.word_size)
        );
        assert_eq!(
            config.stack.high(),
            B256::from(config.register.low() - config.buffer_size * config.word_size)
        );
        assert_eq!(
            config.register.high(),
            config.register.low() + no_register * config.word_size
        );

        // Test register
        config.create_register(0);
        assert!(!config.register.contain(B256::from(10)));
    }
}
