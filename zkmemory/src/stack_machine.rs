use crate::{abstract_machine::AbstractContext, state_machine::AbstractStateMachine};

/// Abstract stack machine
pub trait AbstractStackMachine<K, V>
where
    Self: AbstractStateMachine<K, V>,
{
    /// Push the value to the stack and return stack_depth
    fn push(&mut self, value: V) -> usize {
        let mut stack_depth = self.context().get_stack_depth();
        stack_depth += 1;
        self.context().set_stack_depth(stack_depth);
        let address = self.context().stack_ptr();
        self.write(address, value);

        stack_depth
    }

    /// Get value from the stack and return stack_depth and value
    fn pop(&mut self) -> (usize, V) {
        let mut stack_depth = self.context().get_stack_depth();
        stack_depth -= 1;
        self.context().set_stack_depth(stack_depth);
        let address = self.context().stack_ptr();
        let value = self.read(address);

        (stack_depth, value)
    }
}
