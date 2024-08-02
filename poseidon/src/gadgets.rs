extern crate alloc;
use core::marker::PhantomData;

use alloc::format;
use alloc::vec::Vec;
use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Region, Value};
use halo2_proofs::plonk::Selector;
use halo2_proofs::{circuit::Layouter, plonk::Error};

use super::circuit::PoseidonConfig;
use super::poseidon_hash::{Absorbing, ConstantLength, Domain, Spec, SpongeMode, Squeezing, State};

#[derive(Clone, Debug)]
/// A word from the padded input to a Poseidon sponge.
pub enum PaddedWord<F: PrimeField> {
    /// A message word provided by the prover.
    Message(AssignedCell<F, F>),
    /// A padding word, that will be fixed in the circuit parameters.
    Padding(F),
}

/// Simplified type to pass cargo check
pub type Sqz<F, const R: usize> = Squeezing<StateWord<F>, R>;

/// Poseidon hash struct, used in verification circuit
pub struct Hash<F: PrimeField, S: Spec<F, T, R>, D: Domain<F, R>, const T: usize, const R: usize> {
    sponge: Sponge<F, S, Absorbing<PaddedWord<F>, R>, D, T, R>,
}

impl<F: PrimeField, S: Spec<F, T, R>, D: Domain<F, R>, const T: usize, const R: usize>
    Hash<F, S, D, T, R>
{
    /// Initializes a new hasher.
    pub fn init(
        config: PoseidonConfig<F, T, R>,
        layouter: impl Layouter<F>,
    ) -> Result<Self, Error> {
        Sponge::new(config, layouter).map(|sponge| Hash { sponge })
    }
}

impl<F: PrimeField, S: Spec<F, T, R>, const T: usize, const R: usize, const L: usize>
    Hash<F, S, ConstantLength<L>, T, R>
{
    /// Hashes the given input.
    pub fn hash(
        mut self,
        mut layouter: impl Layouter<F>,
        message: [AssignedCell<F, F>; L],
    ) -> Result<AssignedCell<F, F>, Error> {
        for (i, value) in message
            .into_iter()
            .map(PaddedWord::Message)
            .chain(<ConstantLength<L> as Domain<F, R>>::padding(L).map(PaddedWord::Padding))
            .enumerate()
        {
            self.sponge
                .absorb(layouter.namespace(|| format!("absorb_{}", i)), value)?;
        }
        self.sponge
            .finish_absorbing(layouter.namespace(|| "finish absorbing"))?
            .squeeze(layouter.namespace(|| "squeeze"))
    }
}

///
#[derive(Debug)]
pub struct Sponge<
    F: PrimeField,
    S: Spec<F, T, R>,
    M: SpongeMode,
    D: Domain<F, R>,
    const T: usize,
    const R: usize,
> {
    config: PoseidonConfig<F, T, R>,
    mode: M,
    state: State<StateWord<F>, T>,
    _marker: PhantomData<D>,
    _marker2: PhantomData<S>,
}

impl<F: PrimeField, S: Spec<F, T, R>, D: Domain<F, R>, const T: usize, const R: usize>
    Sponge<F, S, Absorbing<PaddedWord<F>, R>, D, T, R>
{
    /// Constructs a new duplex sponge for the given Poseidon specification.
    pub fn new(
        config: PoseidonConfig<F, T, R>,
        mut layouter: impl Layouter<F>,
    ) -> Result<Self, Error> {
        config
            .initial_state::<D>(&mut layouter)
            .map(|state| Sponge {
                config,
                mode: Absorbing(
                    (0..R)
                        .map(|_| None)
                        .collect::<Vec<_>>()
                        .try_into()
                        .expect("unable to get mode"),
                ),
                state,
                _marker: PhantomData,
                _marker2: PhantomData,
            })
    }

    /// Absorbs an element into the sponge.
    pub fn absorb(
        &mut self,
        mut layouter: impl Layouter<F>,
        value: PaddedWord<F>,
    ) -> Result<(), Error> {
        for entry in self.mode.0.iter_mut() {
            if entry.is_none() {
                *entry = Some(value);
                return Ok(());
            }
        }

        // We've already absorbed as many elements as we can
        let _ = poseidon_sponge::<F, D, T, R>(
            &self.config,
            layouter.namespace(|| "PoseidonSponge"),
            &mut self.state,
            Some(&self.mode),
        )?;
        self.mode = Absorbing::init_with(value);
        Ok(())
    }

    /// Transitions the sponge into its squeezing state.
    pub fn finish_absorbing(
        mut self,
        mut layouter: impl Layouter<F>,
    ) -> Result<Sponge<F, S, Sqz<F, R>, D, T, R>, Error> {
        let mode = poseidon_sponge::<F, D, T, R>(
            &self.config,
            layouter.namespace(|| "PoseidonSponge"),
            &mut self.state,
            Some(&self.mode),
        )?;

        Ok(Sponge {
            config: self.config,
            mode,
            state: self.state,
            _marker: PhantomData,
            _marker2: PhantomData,
        })
    }
}
impl<F: PrimeField, S: Spec<F, T, R>, D: Domain<F, R>, const T: usize, const R: usize>
    Sponge<F, S, Squeezing<StateWord<F>, R>, D, T, R>
{
    /// Squeezes an element from the sponge.
    pub fn squeeze(&mut self, mut layouter: impl Layouter<F>) -> Result<AssignedCell<F, F>, Error> {
        loop {
            for entry in self.mode.0.iter_mut() {
                if let Some(inner) = entry.take() {
                    return Ok(inner.into());
                }
            }
            // We've already squeezed out all available elements
            self.mode = poseidon_sponge::<F, D, T, R>(
                &self.config,
                layouter.namespace(|| "PoseidonSponge"),
                &mut self.state,
                None,
            )?;
        }
    }
}

fn poseidon_sponge<F: PrimeField, D: Domain<F, R>, const T: usize, const R: usize>(
    config: &PoseidonConfig<F, T, R>,
    mut layouter: impl Layouter<F>,
    state: &mut State<StateWord<F>, T>,
    input: Option<&Absorbing<PaddedWord<F>, R>>,
) -> Result<Squeezing<StateWord<F>, R>, Error> {
    if let Some(input) = input {
        *state = config.add_input(&mut layouter, state, input)?;
    }
    *state = config.permute::<D>(&mut layouter, state)?;
    Ok(PoseidonConfig::<F, T, R>::get_output(state))
}

#[derive(Clone, Debug)]
///
pub struct StateWord<F: PrimeField>(pub AssignedCell<F, F>);

impl<F: PrimeField> From<StateWord<F>> for AssignedCell<F, F> {
    fn from(state_word: StateWord<F>) -> AssignedCell<F, F> {
        state_word.0
    }
}

///
pub struct PoseidonState<F: PrimeField, const T: usize>(pub [StateWord<F>; T]);

impl<F: PrimeField, const T: usize> PoseidonState<F, T> {
    ///
    pub fn load<D: Domain<F, R>, const R: usize>(
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, T, R>,
        initial_state: &State<StateWord<F>, T>,
    ) -> Result<Self, Error> {
        let load_state_word = |i: usize| {
            initial_state[i]
                .0
                .copy_advice(|| format!("load state_{}", i), region, config.state[i], 0)
                .map(StateWord)
        };

        let state: Result<Vec<StateWord<F>>, Error> = (0..T).map(load_state_word).collect();
        state.map(|state| PoseidonState(state.try_into().expect("unable to get state")))
    }

    fn round<const R: usize>(
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, T, R>,
        round: usize,
        offset: usize,
        round_gate: Selector,
        round_fn: impl FnOnce(&mut Region<'_, F>) -> Result<(usize, [Value<F>; T]), Error>,
    ) -> Result<Self, Error> {
        // Enable the required gate.
        round_gate.enable(region, offset)?;

        // Load the round constants.
        let mut load_round_constant = |i: usize| {
            region.assign_fixed(
                || format!("round_{} rc_{}", round, i),
                config.rc_a[i],
                offset,
                || Value::known(config.round_constants[round][i]),
            )
        };
        for i in 0..T {
            load_round_constant(i)?;
        }

        // Compute the next round's state.
        let (next_round, next_state) = round_fn(region)?;

        let next_state_word = |i: usize| {
            let value = next_state[i];
            let var = region.assign_advice(
                || format!("round_{} state_{}", next_round, i),
                config.state[i],
                offset + 1,
                || value,
            )?;
            Ok(StateWord(var))
        };

        let next_state: Result<Vec<StateWord<F>>, Error> = (0..T).map(next_state_word).collect();
        next_state.map(|next_state| {
            PoseidonState(next_state.try_into().expect("unable to get next_state"))
        })
    }

    /// update the state via a full round
    pub fn full_round<D: Domain<F, R>, const R: usize>(
        self,
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, T, R>,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round::<R>(region, config, round, offset, config.sel_full_round, |_| {
            let q = self.0.iter().enumerate().map(|(idx, word)| {
                word.0
                    .value()
                    .map(|v| *v + config.round_constants[round][idx])
            });
            let r: Value<Vec<F>> = q.map(|q| q.map(|q| q.pow(config.alpha))).collect();
            let m = &config.m_reg;
            let state = m.iter().map(|m_i| {
                r.as_ref().map(|r| {
                    r.iter()
                        .enumerate()
                        .fold(F::ZERO, |acc, (j, r_j)| acc + m_i[j] * r_j)
                })
            });
            Ok((
                round + 1,
                state.collect::<Vec<Value<F>>>().try_into().unwrap(),
            ))
        })
    }

    /// update a state via a half round
    pub fn partial_round<D: Domain<F, R>, const R: usize>(
        self,
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, T, R>,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round::<R>(
            region,
            config,
            round,
            offset,
            config.sel_partial_round,
            |region| {
                let m = &config.m_reg;
                let p: Value<Vec<F>> = self.0.iter().map(|word| word.0.value().cloned()).collect();
                let r: Value<Vec<F>> = p.map(|p| {
                    let r_0 = (p[0] + config.round_constants[round][0]).pow(config.alpha);
                    let r_i = p[1..]
                        .iter()
                        .enumerate()
                        .map(|(i, p_i)| *p_i + config.round_constants[round][i + 1]);
                    core::iter::empty().chain(Some(r_0)).chain(r_i).collect()
                });

                region.assign_advice(
                    || format!("round_{} partial_sbox", round),
                    config.partial_sbox,
                    offset,
                    || r.as_ref().map(|r| r[0]),
                )?;

                let p_mid: Value<Vec<F>> = m
                    .iter()
                    .map(|m_i| {
                        r.as_ref().map(|r| {
                            m_i.iter()
                                .zip(r.iter())
                                .fold(F::ZERO, |acc, (m_ij, r_j)| acc + *m_ij * r_j)
                        })
                    })
                    .collect();

                // Load the second round constants.
                let mut load_round_constant = |i: usize| {
                    region.assign_fixed(
                        || format!("round_{} rc_{}", round + 1, i),
                        config.rc_b[i],
                        offset,
                        || Value::known(config.round_constants[round + 1][i]),
                    )
                };
                for i in 0..T {
                    load_round_constant(i)?;
                }
                let r_mid: Value<Vec<F>> = p_mid.map(|p| {
                    let r_0 = (p[0] + config.round_constants[round + 1][0]).pow(config.alpha);
                    let r_i = p[1..]
                        .iter()
                        .enumerate()
                        .map(|(i, p_i)| *p_i + config.round_constants[round + 1][i + 1]);
                    core::iter::empty().chain(Some(r_0)).chain(r_i).collect()
                });

                let state: Vec<Value<F>> = m
                    .iter()
                    .map(|m_i| {
                        r_mid.as_ref().map(|r| {
                            m_i.iter()
                                .zip(r.iter())
                                .fold(F::ZERO, |acc, (m_ij, r_j)| acc + *m_ij * r_j)
                        })
                    })
                    .collect();

                Ok((round + 2, state.try_into().unwrap()))
            },
        )
    }
}
