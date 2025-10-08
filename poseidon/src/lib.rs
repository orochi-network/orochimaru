/// The Poseidon hash circuit
pub mod circuit;

/// The gadget functions
/// (In this repo, gadgets is the functions help assign 
/// the witness of poseidon circuit into correct columns)
pub mod gadgets;

/// The chip implementation for poseidon hash
/// The responsibility of chip is define the constraints 
/// between the columns in the circuit
/// With chip we can reuse the the logic of poseidon hash 
/// as the component of the larger circuit
pub mod chip;

/// The public constants for the Poseidon hash
pub mod poseidon_constants;
/// The implelentation of Poseidon hash
pub mod poseidon_hash;
