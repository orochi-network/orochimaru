//! The implelemtation of Poseidon hash, with most details based from
//! [Zcash implementation](https://github.com/zcash/halo2/blob/main/halo2_gadgets/src/poseidon/primitives.rs)
//! We originally wanted to import the implementation from Zcash's library directly.
//! However, since we are using the Halo2 version from PSE, we need to
//! clone many functions and fix some details so that the implementation
//! will be compatible with our implementation.
//! The hash function is used in some circuits for verifying the correctness of
//! Merkle tree and Verkle tree opening proofs.

extern crate alloc;
use alloc::vec::Vec;
use core::{fmt::Debug, iter, marker::PhantomData};
use ff::{Field, PrimeField};

/// The type of a square matrix of size T
pub(crate) type Mtrx<F, const T: usize> = [[F; T]; T];

/// The trait for specifying the hash parameters
pub trait Spec<F: Field + PrimeField, const T: usize, const R: usize> {
    /// The number of full rounds for Poseidon hash.
    fn full_rounds() -> usize;

    /// The number of partial rounds for Poseidon hash.
    fn partial_rounds() -> usize;

    /// The S-box for poseidon hash.
    fn sbox(val: F) -> F;

    /// Generates `(round_constants, mds, mds^-1)` corresponding to Poseidon hash.
    fn constants() -> (Vec<[F; T]>, Mtrx<F, T>, Mtrx<F, T>);
}

/// The trait for specifying the domain of messages
pub trait Domain<F: Field + PrimeField, const R: usize> {
    /// Iterator that outputs padding Field+PrimeField elements.
    type Padding: IntoIterator<Item = F>;

    /// The initial capacity element, encoding this domain.
    fn initial_capacity_element() -> F;

    /// Returns the padding to be appended to the input.
    fn padding(input_len: usize) -> Self::Padding;
}

/// The number of messages to be hashed
#[derive(Clone)]
pub struct ConstantLength<const L: usize>;

impl<F: Field + PrimeField, const R: usize, const L: usize> Domain<F, R> for ConstantLength<L> {
    type Padding = iter::Take<iter::Repeat<F>>;

    fn initial_capacity_element() -> F {
        F::from_u128((L as u128) << 64)
    }

    fn padding(input_len: usize) -> Self::Padding {
        assert_eq!(input_len, L);
        let k = (L + R - 1) / R;
        iter::repeat(F::ZERO).take(k * R - L)
    }
}

/// The state of the `Sponge`.
pub trait SpongeMode {}

impl<F, const R: usize> SpongeMode for Absorbing<F, R> {}
impl<F, const R: usize> SpongeMode for Squeezing<F, R> {}

impl<F: Debug, const R: usize> Absorbing<F, R> {
    pub(crate) fn init_with(val: F) -> Self {
        Self(
            iter::once(Some(val))
                .chain((1..R).map(|_| None))
                .collect::<Vec<Option<F>>>()
                .try_into()
                .expect("cannot init"),
        )
    }
}

/// The absorbing state of the `Sponge`.
pub struct Absorbing<F, const R: usize>(pub(crate) [Option<F>; R]);

/// The squeezing state of the `Sponge`.
pub struct Squeezing<F, const R: usize>(pub(crate) [Option<F>; R]);

/// The type used to hold permutation state.
pub(crate) type State<F, const T: usize> = [F; T];

/// A Poseidon sponge.
pub(crate) struct Sponge<
    F: Field + PrimeField,
    S: Spec<F, T, R>,
    M: SpongeMode,
    const T: usize,
    const R: usize,
> {
    mode: M,
    state: State<F, T>,
    mds_matrix: Mtrx<F, T>,
    round_constants: Vec<[F; T]>,
    _marker: PhantomData<S>,
}

impl<F: Field + PrimeField, S: Spec<F, T, R>, const T: usize, const R: usize>
    Sponge<F, S, Absorbing<F, R>, T, R>
{
    /// Constructs a new sponge for the given Poseidon specification.
    pub(crate) fn new(initial_capacity_element: F) -> Self {
        let (round_constants, mds_matrix, _) = S::constants();
        let mut state = [F::ZERO; T];
        state[R] = initial_capacity_element;

        Sponge {
            mode: Absorbing([None; R]),
            state,
            mds_matrix,
            round_constants,
            _marker: PhantomData,
        }
    }

    /// Absorbs an element into the sponge.
    pub(crate) fn absorb(&mut self, value: F) {
        for entry in self.mode.0.iter_mut() {
            if entry.is_none() {
                *entry = Some(value);
                return;
            }
        }

        // We've already absorbed as many elements as we can
        let _ = poseidon_sponge::<F, S, T, R>(
            &mut self.state,
            Some(&self.mode),
            &self.mds_matrix,
            &self.round_constants,
        );
        self.mode = Absorbing::init_with(value);
    }

    /// Transitions the sponge into its squeezing state.
    pub(crate) fn finish_absorbing(mut self) -> Sponge<F, S, Squeezing<F, R>, T, R> {
        let mode = poseidon_sponge::<F, S, T, R>(
            &mut self.state,
            Some(&self.mode),
            &self.mds_matrix,
            &self.round_constants,
        );

        Sponge {
            mode,
            state: self.state,
            mds_matrix: self.mds_matrix,
            round_constants: self.round_constants,
            _marker: PhantomData,
        }
    }
}

fn poseidon_sponge<F: Field + PrimeField, S: Spec<F, T, R>, const T: usize, const R: usize>(
    state: &mut State<F, T>,
    input: Option<&Absorbing<F, R>>,
    mds_matrix: &Mtrx<F, T>,
    round_constants: &[[F; T]],
) -> Squeezing<F, R> {
    if let Some(Absorbing(input)) = input {
        for (word, value) in state.iter_mut().zip(input.iter()) {
            *word += value.expect("poseidon_sponge is called with a padded input");
        }
    }

    // add round constants + sbox +  multiplication by mds
    permute::<F, S, T, R>(state, mds_matrix, round_constants);

    let mut output = [None; R];
    for (word, value) in output.iter_mut().zip(state.iter()) {
        *word = Some(*value);
    }
    Squeezing(output)
}

/// Runs the Poseidon permutation on the given state. Given inputs a state,
/// a MDS matrix and a list of round_constants, this function transform the
/// state into a new state.
pub(crate) fn permute<F: Field + PrimeField, S: Spec<F, T, R>, const T: usize, const R: usize>(
    state: &mut State<F, T>,
    mds: &[[F; T]; T],
    round_constants: &[[F; T]],
) {
    // The number of full rounds and partial rounds, respectively
    let r_f = S::full_rounds() / 2;
    let r_p = S::partial_rounds();

    // Multiply the state by mds
    let mix_layer = |state: &mut State<F, T>| {
        let mut new_state = [F::ZERO; T];
        for i in 0..T {
            for (j, k) in mds[i].iter().zip(state.iter()).take(T) {
                new_state[i] += *j * k;
            }
        }
        *state = new_state;
    };

    let full_round = |state: &mut State<F, T>, rcs: &[F; T]| {
        // add round constant
        for (word, rc) in state.iter_mut().zip(rcs.iter()) {
            *word += rc;
        }
        // perform sbox
        for word in state.iter_mut() {
            *word = S::sbox(*word);
        }
        // multiply by mds
        mix_layer(state);
    };

    let part_round = |state: &mut State<F, T>, rcs: &[F; T]| {
        // add round constant
        for (word, rc) in state.iter_mut().zip(rcs.iter()) {
            *word += rc;
        }
        // In a partial round, the S-box is only applied to the first state word.
        state[0] = S::sbox(state[0]);
        // multiply by mds
        mix_layer(state);
    };

    for i in round_constants.iter().take(r_f) {
        full_round(state, i);
    }
    for i in round_constants.iter().skip(r_f).take(r_p) {
        part_round(state, i);
    }
    for i in round_constants.iter().take(r_p + 2 * r_f).skip(r_p + r_f) {
        full_round(state, i);
    }
}

impl<F: Field + PrimeField, S: Spec<F, T, R>, const T: usize, const R: usize>
    Sponge<F, S, Squeezing<F, R>, T, R>
{
    /// Squeezes an element from the sponge.
    pub(crate) fn squeeze(&mut self) -> F {
        loop {
            for entry in self.mode.0.iter_mut() {
                if let Some(e) = entry.take() {
                    return e;
                }
            }

            // We've already squeezed out all available elements
            self.mode = poseidon_sponge::<F, S, T, R>(
                &mut self.state,
                None,
                &self.mds_matrix,
                &self.round_constants,
            );
        }
    }
}

/// A Poseidon hash function, built around a sponge.
pub struct Hash<
    F: Field + PrimeField,
    S: Spec<F, T, R>,
    D: Domain<F, R>,
    const T: usize,
    const R: usize,
> {
    sponge: Sponge<F, S, Absorbing<F, R>, T, R>,
    _marker: PhantomData<D>,
}

impl<F: Field + PrimeField, S: Spec<F, T, R>, D: Domain<F, R>, const T: usize, const R: usize>
    Hash<F, S, D, T, R>
{
    /// Initializes a new hasher.
    pub fn init() -> Self {
        Hash {
            sponge: Sponge::new(D::initial_capacity_element()),
            _marker: PhantomData,
        }
    }
}

impl<F: Field + PrimeField, S: Spec<F, T, R>, const T: usize, const R: usize, const L: usize>
    Hash<F, S, ConstantLength<L>, T, R>
{
    /// Hashes the given input.
    pub fn hash(mut self, message: [F; L]) -> F {
        for value in message
            .into_iter()
            .chain(<ConstantLength<L> as Domain<F, R>>::padding(L))
        {
            self.sponge.absorb(value);
        }
        self.sponge.finish_absorbing().squeeze()
    }
}

use crate::poseidon::poseidon_constants::{MDS, MDS_INV, ROUND_CONSTANTS};
use halo2curves::pasta::Fp;
/// Generate specific constants for testing the poseidon hash
#[derive(Clone)]
pub struct OrchardNullifier;

impl Spec<Fp, 3, 2> for OrchardNullifier {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime([5])
    }

    fn constants() -> (Vec<[Fp; 3]>, Mtrx<Fp, 3>, Mtrx<Fp, 3>) {
        (ROUND_CONSTANTS[..].to_vec(), MDS, MDS_INV)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use halo2curves::pasta::pallas::Base;
    #[test]
    fn poseidon_hash() {
        let message = [Base::from(120), Base::from(240)];

        let (round_constants, mds, _) = OrchardNullifier::constants();

        let hasher = Hash::<Fp, OrchardNullifier, ConstantLength<2>, 3, 2>::init();

        let result = hasher.hash(message);
        let mut state = [message[0], message[1], Base::from_u128(2 << 64)];
        permute::<Fp, OrchardNullifier, 3, 2>(&mut state, &mds, &round_constants);
        assert_eq!(state[0], result);
    }
}
