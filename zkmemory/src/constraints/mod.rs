/// Common traits for permutation, original and sorted memory
pub mod common;
/// The final circuit for memory consistency check
pub mod consistency_check_circuit;
/// Gadgets supports original, sorted memory constraints and permutation
pub mod gadgets;
/// Helper for memory consistency check circuit
pub mod helper;
/// Check the correctness of the original memory
pub mod original_memory_circuit;
/// Permutation circuit for trace record permutation check
pub mod permutation_circuit;
/// Check the correctness of memory sorting
pub mod sorted_memory_circuit;
