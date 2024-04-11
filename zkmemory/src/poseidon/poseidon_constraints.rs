extern crate alloc;
use crate::poseidon::poseidon::{Spec, StateWord};
use alloc::{format, vec::Vec};
use core::{fmt::Debug, iter, marker::PhantomData};
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Any, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Fixed,
        Selector,
    },
    poly::Rotation,
};

use super::poseidon::{
    Absorbing, ConstantLength, Domain, PaddedWord, PoseidonInstructions,
    PoseidonSpongeInstructions, SpongeMode, Squeezing, State,
};

extern crate std;

#[derive(Clone, Debug)]
/// Poseidon config
pub struct PoseidonConfig<F: Field + PrimeField, const W: usize, const R: usize> {
    state: [Column<Advice>; W],
    sbox: Column<Advice>,
    rc_a: [Column<Fixed>; W],
    rc_b: [Column<Fixed>; W],
    s_full: Selector,
    s_partial: Selector,
    s_pad_and_add: Selector,
    half_full_rounds: usize,
    half_partial_rounds: usize,
    alpha: [u64; 4],
    round_constants: Vec<[F; W]>,
    m_reg: [[F; W]; W],
}
/// A Poseidon chip using an $x^5$ S-Box.
///
/// The chip is implemented using a single round per row for full rounds, and two rounds
/// per row for partial rounds.
#[derive(Debug)]
pub struct Pow5Chip<F: Field + PrimeField, const W: usize, const R: usize> {
    config: PoseidonConfig<F, W, R>,
}

impl<F: Field + PrimeField, const W: usize, const R: usize> Pow5Chip<F, W, R> {
    ///
    pub fn configure<S: Spec<F, W, R>>(meta: &mut ConstraintSystem<F>) -> PoseidonConfig<F, W, R> {
        let (round_constants, m_reg, m_inv) = S::constants();
        assert_eq!(R, W - 1);
        let state = [0; W].map(|_| meta.advice_column());
        let sbox = meta.advice_column();
        let rc_a = [0; W].map(|_| meta.fixed_column());
        let rc_b = [0; W].map(|_| meta.fixed_column());
        let s_full = meta.selector();
        let s_partial = meta.selector();
        let s_pad_and_add = meta.selector();
        let half_full_rounds = S::full_rounds() / 2;
        let half_partial_rounds = S::partial_rounds() / 2;
        let alpha = [5, 0, 0, 0];
        let pow_5 = |v: Expression<F>| {
            let v2 = v.clone() * v.clone();
            v2.clone() * v2 * v
        };

        meta.enable_constant(rc_b[0]);
        for column in iter::empty()
            .chain(state.iter().cloned().map(Column::<Any>::from))
            .chain(rc_b.iter().cloned().map(Column::<Any>::from))
        {
            meta.enable_equality(column);
        }

        meta.create_gate("full round", |meta| {
            let s_full = meta.query_selector(s_full);

            Constraints::with_selector(
                s_full,
                (0..W)
                    .map(|next_idx| {
                        let state_next = meta.query_advice(state[next_idx], Rotation::next());
                        let expr = (0..W)
                            .map(|idx| {
                                let state_cur = meta.query_advice(state[idx], Rotation::cur());
                                let rc_a = meta.query_fixed(rc_a[idx], Rotation::cur());
                                pow_5(state_cur + rc_a) * m_reg[next_idx][idx]
                            })
                            .reduce(|acc, term| acc + term)
                            .expect("W > 0");
                        expr - state_next
                    })
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("partial rounds", |meta| {
            let cur_0 = meta.query_advice(state[0], Rotation::cur());
            let mid_0 = meta.query_advice(sbox, Rotation::cur());

            let rc_a0 = meta.query_fixed(rc_a[0], Rotation::cur());
            let rc_b0 = meta.query_fixed(rc_b[0], Rotation::cur());

            let s_partial = meta.query_selector(s_partial);

            use halo2_proofs::plonk::VirtualCells;
            let mid = |idx: usize, meta: &mut VirtualCells<'_, F>| {
                let mid = mid_0.clone() * m_reg[idx][0];
                (1..W).fold(mid, |acc, cur_idx| {
                    let cur = meta.query_advice(state[cur_idx], Rotation::cur());
                    let rc_a = meta.query_fixed(rc_a[cur_idx], Rotation::cur());
                    acc + (cur + rc_a) * m_reg[idx][cur_idx]
                })
            };

            let next = |idx: usize, meta: &mut VirtualCells<'_, F>| {
                (0..W)
                    .map(|next_idx| {
                        let next = meta.query_advice(state[next_idx], Rotation::next());
                        next * m_inv[idx][next_idx]
                    })
                    .reduce(|acc, next| acc + next)
                    .expect("W > 0")
            };

            let partial_round_linear = |idx: usize, meta: &mut VirtualCells<'_, F>| {
                let rc_b = meta.query_fixed(rc_b[idx], Rotation::cur());
                mid(idx, meta) + rc_b - next(idx, meta)
            };

            Constraints::with_selector(
                s_partial,
                std::iter::empty()
                    // state[0] round a
                    .chain(Some(pow_5(cur_0 + rc_a0) - mid_0.clone()))
                    // state[0] round b
                    .chain(Some(pow_5(mid(0, meta) + rc_b0) - next(0, meta)))
                    .chain((1..W).map(|idx| partial_round_linear(idx, meta)))
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("pad-and-add", |meta| {
            let initial_state_rate = meta.query_advice(state[R], Rotation::prev());
            let output_state_rate = meta.query_advice(state[R], Rotation::next());

            let s_pad_and_add = meta.query_selector(s_pad_and_add);

            let pad_and_add = |idx: usize| {
                let initial_state = meta.query_advice(state[idx], Rotation::prev());
                let input = meta.query_advice(state[idx], Rotation::cur());
                let output_state = meta.query_advice(state[idx], Rotation::next());

                // We pad the input by storing the required padding in fixed columns and
                // then constraining the corresponding input columns to be equal to it.
                initial_state + input - output_state
            };
            Constraints::with_selector(
                s_pad_and_add,
                (0..R)
                    .map(pad_and_add)
                    // The capacity element is never altered by the input.
                    .chain(Some(initial_state_rate - output_state_rate))
                    .collect::<Vec<_>>(),
            )
        });

        PoseidonConfig {
            state,
            sbox,
            rc_a,
            rc_b,
            s_full,
            s_partial,
            s_pad_and_add,
            half_full_rounds,
            half_partial_rounds,
            alpha,
            round_constants,
            m_reg,
        }
    }

    /// Construct a [`Pow5Chip`].
    pub fn construct(config: PoseidonConfig<F, W, R>) -> Self {
        Pow5Chip { config }
    }
}

impl<F: Field + PrimeField, const W: usize, const R: usize> Chip<F> for Pow5Chip<F, W, R> {
    type Config = PoseidonConfig<F, W, R>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[derive(Debug)]
struct PoseidonState<F: Field + PrimeField, const W: usize>([StateWord<F>; W]);

impl<F: Field + PrimeField, const W: usize> PoseidonState<F, W> {
    fn full_round<const R: usize>(
        self,
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, W, R>,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round(region, config, round, offset, config.s_full, |_| {
            let q = self.0.iter().enumerate().map(|(idx, word)| {
                word.0
                    .value()
                    .map(|v| *v + config.round_constants[round][idx])
            });
            let r: Value<Vec<F>> = q.map(|q| q.map(|q| q.pow(&config.alpha))).collect();
            let m = &config.m_reg;
            let state = m.iter().map(|m_i| {
                r.as_ref().map(|r| {
                    r.iter()
                        .enumerate()
                        .fold(F::ZERO, |acc, (j, r_j)| acc + m_i[j] * r_j)
                })
            });

            Ok((round + 1, state.collect::<Vec<_>>().try_into().unwrap()))
        })
    }

    fn partial_round<const R: usize>(
        self,
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, W, R>,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round(region, config, round, offset, config.s_partial, |region| {
            let m = &config.m_reg;
            let p: Value<Vec<_>> = self.0.iter().map(|word| word.0.value().cloned()).collect();

            let r: Value<Vec<_>> = p.map(|p| {
                let r_0 = (p[0] + config.round_constants[round][0]).pow(&config.alpha);
                let r_i = p[1..]
                    .iter()
                    .enumerate()
                    .map(|(i, p_i)| *p_i + config.round_constants[round][i + 1]);
                std::iter::empty().chain(Some(r_0)).chain(r_i).collect()
            });

            region.assign_advice(
                || format!("round_{} partial_sbox", round),
                config.sbox,
                offset,
                || r.as_ref().map(|r| r[0]),
            )?;

            let p_mid: Value<Vec<_>> = m
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
            for i in 0..W {
                load_round_constant(i)?;
            }

            let r_mid: Value<Vec<_>> = p_mid.map(|p| {
                let r_0 = (p[0] + config.round_constants[round + 1][0]).pow(&config.alpha);
                let r_i = p[1..]
                    .iter()
                    .enumerate()
                    .map(|(i, p_i)| *p_i + config.round_constants[round + 1][i + 1]);
                std::iter::empty().chain(Some(r_0)).chain(r_i).collect()
            });

            let state: Vec<Value<_>> = m
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
        })
    }

    fn round<const R: usize>(
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, W, R>,
        round: usize,
        offset: usize,
        round_gate: Selector,
        round_fn: impl FnOnce(&mut Region<'_, F>) -> Result<(usize, [Value<F>; W]), Error>,
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
        for i in 0..W {
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

        let next_state: Result<Vec<_>, _> = (0..W).map(next_state_word).collect();
        next_state.map(|next_state| PoseidonState(next_state.try_into().unwrap()))
    }
}

struct HashCircuit<
    S: Spec<F, W, R>,
    F: Field + PrimeField,
    const W: usize,
    const R: usize,
    const L: usize,
> {
    message: Value<[F; L]>,
    // For the purpose of this test, witness the result.
    // TODO: Move this into an instance column.
    output: Value<F>,
    _marker: PhantomData<S>,
}

impl<S: Spec<F, W, R>, F: Field + PrimeField, const W: usize, const R: usize, const L: usize>
    Circuit<F> for HashCircuit<S, F, W, R, L>
{
    type Config = PoseidonConfig<F, W, R>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: Value::unknown(),
            output: Value::unknown(),
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> PoseidonConfig<F, W, R> {
        Pow5Chip::configure::<S>(meta)
    }

    fn synthesize(
        &self,
        config: PoseidonConfig<F, W, R>,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.clone());
        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                let message_word = |i: usize| {
                    let value = self.message.map(|message_vals| message_vals[i]);
                    region.assign_advice(
                        || format!("load message_{}", i),
                        config.state[i],
                        0,
                        || value,
                    )
                };

                let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                Ok(message?.try_into().unwrap())
            },
        )?;

        let hasher =
            Hash::<F, _, S, ConstantLength<L>, W, R>::init(chip, layouter.namespace(|| "init"))?;
        let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

        layouter.assign_region(
            || "constrain output",
            |mut region| {
                let expected_var =
                    region.assign_advice(|| "load output", config.state[0], 0, || self.output)?;
                region.constrain_equal(output.cell(), expected_var.cell())
            },
        )
    }
}

impl<F: Field + PrimeField, S: Spec<F, W, R>, const W: usize, const R: usize>
    PoseidonInstructions<F, S, W, R> for Pow5Chip<F, W, R>
{
    type Word = StateWord<F>;

    fn permute(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_state: &State<Self::Word, W>,
    ) -> Result<State<Self::Word, W>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "permute state",
            |mut region| {
                // Load the initial state into this region.
                let state = Pow5State::load(&mut region, config, initial_state)?;

                let state = (0..config.half_full_rounds).fold(Ok(state), |res, r| {
                    res.and_then(|state| state.full_round(&mut region, config, r, r))
                })?;

                let state = (0..config.half_partial_rounds).fold(Ok(state), |res, r| {
                    res.and_then(|state| {
                        state.partial_round(
                            &mut region,
                            config,
                            config.half_full_rounds + 2 * r,
                            config.half_full_rounds + r,
                        )
                    })
                })?;

                let state = (0..config.half_full_rounds).fold(Ok(state), |res, r| {
                    res.and_then(|state| {
                        state.full_round(
                            &mut region,
                            config,
                            config.half_full_rounds + 2 * config.half_partial_rounds + r,
                            config.half_full_rounds + config.half_partial_rounds + r,
                        )
                    })
                })?;

                Ok(state.0)
            },
        )
    }
}

impl<F: Field + PrimeField, S: Spec<F, W, R>, D: Domain<F, R>, const W: usize, const R: usize>
    PoseidonSpongeInstructions<F, S, D, W, R> for Pow5Chip<F, W, R>
{
    fn initial_state(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<State<Self::Word, W>, Error> {
        let config = self.config();
        let state = layouter.assign_region(
            || format!("initial state for domain {}", D::name()),
            |mut region| {
                let mut state = Vec::with_capacity(W);
                let mut load_state_word = |i: usize, value: F| -> Result<_, Error> {
                    let var = region.assign_advice_from_constant(
                        || format!("state_{}", i),
                        config.state[i],
                        0,
                        value,
                    )?;
                    state.push(StateWord(var));

                    Ok(())
                };

                for i in 0..R {
                    load_state_word(i, F::ZERO)?;
                }
                load_state_word(R, D::initial_capacity_element())?;

                Ok(state)
            },
        )?;

        Ok(state.try_into().unwrap())
    }

    fn add_input(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_state: &State<Self::Word, W>,
        input: &Absorbing<PaddedWord<F>, R>,
    ) -> Result<State<Self::Word, W>, Error> {
        let config = self.config();
        layouter.assign_region(
            || format!("add input for domain {}", D::name()),
            |mut region| {
                config.s_pad_and_add.enable(&mut region, 1)?;

                // Load the initial state into this region.
                let load_state_word = |i: usize| {
                    initial_state[i]
                        .0
                        .copy_advice(
                            || format!("load state_{}", i),
                            &mut region,
                            config.state[i],
                            0,
                        )
                        .map(StateWord)
                };
                let initial_state: Result<Vec<_>, Error> = (0..W).map(load_state_word).collect();
                let initial_state = initial_state?;

                // Load the input into this region.
                let load_input_word = |i: usize| {
                    let (cell, value) = match input.0[i].clone() {
                        Some(PaddedWord::Message(word)) => (word.cell(), word.value().copied()),
                        Some(PaddedWord::Padding(padding_value)) => {
                            let cell = region
                                .assign_fixed(
                                    || format!("load pad_{}", i),
                                    config.rc_b[i],
                                    1,
                                    || Value::known(padding_value),
                                )?
                                .cell();
                            (cell, Value::known(padding_value))
                        }
                        _ => panic!("Input is not padded"),
                    };
                    let var = region.assign_advice(
                        || format!("load input_{}", i),
                        config.state[i],
                        1,
                        || value,
                    )?;
                    region.constrain_equal(cell, var.cell())?;

                    Ok(StateWord(var))
                };
                let input: Result<Vec<_>, Error> = (0..R).map(load_input_word).collect();
                let input = input?;

                // Constrain the output.
                let constrain_output_word = |i: usize| {
                    let value = initial_state[i].0.value().copied()
                        + input
                            .get(i)
                            .map(|word| word.0.value().cloned())
                            // The capacity element is never altered by the input.
                            .unwrap_or_else(|| Value::known(F::ZERO));
                    region
                        .assign_advice(
                            || format!("load output_{}", i),
                            config.state[i],
                            2,
                            || value,
                        )
                        .map(StateWord)
                };

                let output: Result<Vec<_>, Error> = (0..W).map(constrain_output_word).collect();
                output.map(|output| output.try_into().unwrap())
            },
        )
    }

    fn get_output(state: &State<Self::Word, W>) -> Squeezing<Self::Word, R> {
        Squeezing(
            state[..R]
                .iter()
                .map(|word| Some(word.clone()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

#[derive(Debug)]
struct Pow5State<F: Field + PrimeField, const W: usize>([StateWord<F>; W]);

impl<F: Field + PrimeField, const W: usize> Pow5State<F, W> {
    fn full_round<const R: usize>(
        self,
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, W, R>,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round(region, config, round, offset, config.s_full, |_| {
            let q = self.0.iter().enumerate().map(|(idx, word)| {
                word.0
                    .value()
                    .map(|v| *v + config.round_constants[round][idx])
            });
            let r: Value<Vec<F>> = q.map(|q| q.map(|q| q.pow(&config.alpha))).collect();
            let m = &config.m_reg;
            let state = m.iter().map(|m_i| {
                r.as_ref().map(|r| {
                    r.iter()
                        .enumerate()
                        .fold(F::ZERO, |acc, (j, r_j)| acc + m_i[j] * r_j)
                })
            });

            Ok((round + 1, state.collect::<Vec<_>>().try_into().unwrap()))
        })
    }

    fn partial_round<const R: usize>(
        self,
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, W, R>,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round(region, config, round, offset, config.s_partial, |region| {
            let m = &config.m_reg;
            let p: Value<Vec<_>> = self.0.iter().map(|word| word.0.value().cloned()).collect();

            let r: Value<Vec<_>> = p.map(|p| {
                let r_0 = (p[0] + config.round_constants[round][0]).pow(&config.alpha);
                let r_i = p[1..]
                    .iter()
                    .enumerate()
                    .map(|(i, p_i)| *p_i + config.round_constants[round][i + 1]);
                std::iter::empty().chain(Some(r_0)).chain(r_i).collect()
            });

            region.assign_advice(
                || format!("round_{} partial_sbox", round),
                config.sbox,
                offset,
                || r.as_ref().map(|r| r[0]),
            )?;

            let p_mid: Value<Vec<_>> = m
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
            for i in 0..W {
                load_round_constant(i)?;
            }

            let r_mid: Value<Vec<_>> = p_mid.map(|p| {
                let r_0 = (p[0] + config.round_constants[round + 1][0]).pow(&config.alpha);
                let r_i = p[1..]
                    .iter()
                    .enumerate()
                    .map(|(i, p_i)| *p_i + config.round_constants[round + 1][i + 1]);
                std::iter::empty().chain(Some(r_0)).chain(r_i).collect()
            });

            let state: Vec<Value<_>> = m
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
        })
    }

    fn load<const R: usize>(
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, W, R>,
        initial_state: &State<StateWord<F>, W>,
    ) -> Result<Self, Error> {
        let load_state_word = |i: usize| {
            initial_state[i]
                .0
                .copy_advice(|| format!("load state_{}", i), region, config.state[i], 0)
                .map(StateWord)
        };

        let state: Result<Vec<_>, _> = (0..W).map(load_state_word).collect();
        state.map(|state| Pow5State(state.try_into().unwrap()))
    }

    fn round<const R: usize>(
        region: &mut Region<'_, F>,
        config: &PoseidonConfig<F, W, R>,
        round: usize,
        offset: usize,
        round_gate: Selector,
        round_fn: impl FnOnce(&mut Region<'_, F>) -> Result<(usize, [Value<F>; W]), Error>,
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
        for i in 0..W {
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

        let next_state: Result<Vec<_>, _> = (0..W).map(next_state_word).collect();
        next_state.map(|next_state| Pow5State(next_state.try_into().unwrap()))
    }
}

/// A Poseidon sponge.
#[derive(Debug)]
pub struct Sponge<
    F: Field + PrimeField,
    PoseidonChip: PoseidonSpongeInstructions<F, S, D, T, R>,
    S: Spec<F, T, R>,
    M: SpongeMode,
    D: Domain<F, R>,
    const T: usize,
    const R: usize,
> {
    chip: PoseidonChip,
    mode: M,
    state: State<PoseidonChip::Word, T>,
    _marker: PhantomData<D>,
}

impl<
        F: Field + PrimeField,
        PoseidonChip: PoseidonSpongeInstructions<F, S, D, T, R>,
        S: Spec<F, T, R>,
        D: Domain<F, R>,
        const T: usize,
        const R: usize,
    > Sponge<F, PoseidonChip, S, Absorbing<PaddedWord<F>, R>, D, T, R>
{
    /// Constructs a new duplex sponge for the given Poseidon specification.
    pub fn new(chip: PoseidonChip, mut layouter: impl Layouter<F>) -> Result<Self, Error> {
        chip.initial_state(&mut layouter).map(|state| Sponge {
            chip,
            mode: Absorbing((0..R).map(|_| None).collect::<Vec<_>>().try_into().unwrap()),
            state,
            _marker: PhantomData::default(),
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
        let _ = poseidon_sponge(
            &self.chip,
            layouter.namespace(|| "PoseidonSponge"),
            &mut self.state,
            Some(&self.mode),
        )?;
        self.mode = Absorbing::init_with(value);

        Ok(())
    }

    /// Transitions the sponge into its squeezing state.
    #[allow(clippy::type_complexity)]
    pub fn finish_absorbing(
        mut self,
        mut layouter: impl Layouter<F>,
    ) -> Result<Sponge<F, PoseidonChip, S, Squeezing<PoseidonChip::Word, R>, D, T, R>, Error> {
        let mode = poseidon_sponge(
            &self.chip,
            layouter.namespace(|| "PoseidonSponge"),
            &mut self.state,
            Some(&self.mode),
        )?;

        Ok(Sponge {
            chip: self.chip,
            mode,
            state: self.state,
            _marker: PhantomData::default(),
        })
    }
}

impl<
        F: Field + PrimeField,
        PoseidonChip: PoseidonSpongeInstructions<F, S, D, T, R>,
        S: Spec<F, T, R>,
        D: Domain<F, R>,
        const T: usize,
        const R: usize,
    > Sponge<F, PoseidonChip, S, Squeezing<PoseidonChip::Word, R>, D, T, R>
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
            self.mode = poseidon_sponge(
                &self.chip,
                layouter.namespace(|| "PoseidonSponge"),
                &mut self.state,
                None,
            )?;
        }
    }
}

/// A Poseidon hash function, built around a sponge.
#[derive(Debug)]
pub struct Hash<
    F: Field + PrimeField,
    PoseidonChip: PoseidonSpongeInstructions<F, S, D, T, R>,
    S: Spec<F, T, R>,
    D: Domain<F, R>,
    const T: usize,
    const R: usize,
> {
    sponge: Sponge<F, PoseidonChip, S, Absorbing<PaddedWord<F>, R>, D, T, R>,
}

impl<
        F: Field + PrimeField,
        PoseidonChip: PoseidonSpongeInstructions<F, S, D, T, R>,
        S: Spec<F, T, R>,
        D: Domain<F, R>,
        const T: usize,
        const R: usize,
    > Hash<F, PoseidonChip, S, D, T, R>
{
    /// Initializes a new hasher.
    pub fn init(chip: PoseidonChip, layouter: impl Layouter<F>) -> Result<Self, Error> {
        Sponge::new(chip, layouter).map(|sponge| Hash { sponge })
    }
}

impl<
        F: PrimeField,
        PoseidonChip: PoseidonSpongeInstructions<F, S, ConstantLength<L>, T, R>,
        S: Spec<F, T, R>,
        const T: usize,
        const R: usize,
        const L: usize,
    > Hash<F, PoseidonChip, S, ConstantLength<L>, T, R>
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

fn poseidon_sponge<
    F: Field + PrimeField,
    PoseidonChip: PoseidonSpongeInstructions<F, S, D, T, R>,
    S: Spec<F, T, R>,
    D: Domain<F, R>,
    const T: usize,
    const R: usize,
>(
    chip: &PoseidonChip,
    mut layouter: impl Layouter<F>,
    state: &mut State<PoseidonChip::Word, T>,
    input: Option<&Absorbing<PaddedWord<F>, R>>,
) -> Result<Squeezing<PoseidonChip::Word, R>, Error> {
    if let Some(input) = input {
        *state = chip.add_input(&mut layouter, state, input)?;
    }
    *state = chip.permute(&mut layouter, state)?;
    Ok(PoseidonChip::get_output(state))
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use crate::poseidon::poseidon::ConstantLength;
    use crate::poseidon::poseidon_constraints::{HashCircuit, Spec};
    use crate::poseidon::{poseidon, poseidon_constants::*};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::marker::PhantomData;
    use ff::Field;
    use halo2_proofs::circuit::Value;
    use halo2_proofs::dev::MockProver;
    use halo2curves::pasta::Fp;
    use rand_core::OsRng;
    ///
    #[derive(Debug)]
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

        fn secure_mds() -> usize {
            unimplemented!()
        }
        fn constants() -> (Vec<[Fp; 3]>, [[Fp; 3]; 3], [[Fp; 3]; 3]) {
            (ROUND_CONSTANTS[..].to_vec(), MDS, MDS_INV)
        }
    }

    #[test]
    fn poseidon_hash() {
        let rng = OsRng;

        let message = [Fp::random(rng), Fp::random(rng)];
        let output = poseidon::HashTest::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init()
            .hash(message);

        let k = 20;
        let circuit = HashCircuit::<OrchardNullifier, Fp, 3, 2, 2> {
            message: Value::known(message),
            output: Value::known(output),
            _marker: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()))
    }
}
