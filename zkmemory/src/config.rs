extern crate alloc;

use crate::base::Base;
use crate::machine::Register;
use alloc::vec::Vec;

/// Memory section
#[derive(Debug, Clone, Copy)]
pub struct Section<T>(T, T);

impl<T> Section<T>
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
    pub memory: Section<T>,
    /// Stack base address
    pub stack: Section<T>,
    /// Register base address
    pub register: Section<T>,
}

/// Config arguments for RAM machine
#[derive(Debug)]
pub struct ConfigArgs {
    /// Is head layout
    pub head_layout: bool,
    /// Stack depth
    pub stack_depth: usize,
    /// Number of registers
    pub no_register: usize,
    /// Number of buffer elements
    pub no_buffer: usize,
}

impl ConfigArgs {
    /// Default configuration
    pub fn default() -> Self {
        ConfigArgs {
            head_layout: true,
            stack_depth: 1024,
            no_register: 32,
            no_buffer: 32,
        }
    }
}

/// Memory allocation for RAM machine (Section based implementation)
pub(crate) struct MemoryAllocation<T, const S: usize> {
    pub(crate) section: Vec<Section<T>>,
    pub(crate) word_size: T,
    pub(crate) buffer_size: T,
}

impl<T, const S: usize> MemoryAllocation<T, S>
where
    T: Base<S>,
{
    /// Create a new memory allocation instance
    /// Buffer size is number of elements
    pub fn new(word_size: T, no_buffer: usize) -> Self {
        MemoryAllocation {
            section: Vec::new(),
            word_size: word_size,
            buffer_size: T::from(no_buffer) * word_size,
        }
    }

    /// Get the last offset in memory allocation
    pub fn last_offset(&self) -> T {
        match self.section.last() {
            None => T::zero(),
            Some(&last) => last.1 + self.buffer_size,
        }
    }

    /// Add a section to the allocation instance with given size
    /// Size is number of elements
    pub fn add_fixed_section(&mut self, size: usize) {
        let last = self.last_offset();
        self.section
            .push(Section(last, last + T::from(size) * self.word_size));
    }

    /// Add a section to the allocation instance with given size
    /// Size is number of elements
    pub fn add_section(&mut self, end: T) {
        let last = self.last_offset();
        self.section.push(Section(last, end));
    }

    /// Set the offset of all sections
    pub fn set_offset(&mut self, offset: T) {
        for section in &mut self.section {
            section.0 = section.0 + offset;
            section.1 = section.1 + offset;
        }
    }
}

impl<T, const S: usize> Config<T, S>
where
    T: Base<S>,
{
    /// Create a new config for given arguments
    pub fn new(word_size: T, args: ConfigArgs) -> Self {
        let mut mem_alloc = MemoryAllocation::new(word_size, args.no_buffer);
        if args.head_layout {
            mem_alloc.add_fixed_section(args.stack_depth);
            mem_alloc.add_fixed_section(args.no_register);
            mem_alloc.add_section(T::MAX);
            Self {
                word_size,
                stack_depth: T::from(args.stack_depth),
                buffer_size: mem_alloc.buffer_size,
                stack: mem_alloc.section[0],
                register: mem_alloc.section[1],
                memory: mem_alloc.section[2],
            }
        } else {
            mem_alloc.add_fixed_section(args.stack_depth);
            mem_alloc.add_fixed_section(args.no_register);
            let begin_of_fixed_section = T::MAX - mem_alloc.last_offset();
            let begin_of_fixed_section =
                begin_of_fixed_section - (begin_of_fixed_section % word_size);

            mem_alloc.set_offset(begin_of_fixed_section);

            Self {
                word_size,
                stack_depth: T::from(args.stack_depth),
                buffer_size: mem_alloc.buffer_size,
                stack: mem_alloc.section[0],
                register: mem_alloc.section[1],
                memory: Section(T::zero(), begin_of_fixed_section - mem_alloc.buffer_size),
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
    use crate::config::Config;

    #[test]
    fn test_config_sections() {
        // Test memory section
        let config = Config::<B256, 32>::new(B256::from(32), ConfigArgs::default());
        assert!(config.memory.contain(B256::MAX - B256::from(1)));

        assert_eq!(config.stack.low(), B256::from(0));
        assert_eq!(
            config.register.low(),
            B256::from(config.stack.high() + config.buffer_size)
        );
        assert_eq!(
            config.memory.low(),
            B256::from(config.register.high() + config.buffer_size)
        );
        assert_eq!(config.memory.high(), B256::MAX);

        let no_register = B256::from(32);
        // Test tail layout
        let config = Config::<B256, 32>::new(
            B256::from(32),
            ConfigArgs {
                head_layout: false,
                stack_depth: 1024,
                no_register: 32,
                no_buffer: 32,
            },
        );

        assert!(config.memory.contain(B256::from(0x10000f)));
        assert_eq!(config.memory.low(), B256::from(0));
        assert_eq!(
            config.memory.high(),
            B256::from(config.stack.low() - config.buffer_size)
        );
        assert_eq!(
            config.stack.high(),
            B256::from(config.register.low() - config.buffer_size)
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
