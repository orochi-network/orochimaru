extern crate alloc;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::{iter::once, marker::PhantomData};
use ff::{Field, PrimeField};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Fixed;
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};
use rand::thread_rng;

use super::gadgets::UTable;

#[derive(Clone, Copy, Debug)]
/// define the columns for the constraint
pub struct LexicographicConfig<F: Field + PrimeField> {
    // the difference between the current row and the previous row
    difference: Column<Advice>,
    difference_inverse: Column<Advice>,
    first_difference_limb: Column<Advice>,
    address: [Column<Advice>; 32],
    time_log: [Column<Advice>; 8],
    instruction: Column<Advice>,
    value: [Column<Advice>; 32],
    selector: Column<Fixed>,
    _marker: PhantomData<F>,
}

// implement the configure method for selecting gates
// we have the gates for checking inverse, lookup and checking that
// all values before first_difference_limb are equal to zero
impl<F: Field + PrimeField> LexicographicConfig<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        address: [Column<Advice>; 32],
        time_log: [Column<Advice>; 8],
        instruction: Column<Advice>,
        value: [Column<Advice>; 32],
        u64_table: UTable<64>,
        u40_table: UTable<40>,
        alpha_power: Vec<Expression<F>>,
    ) -> Self {
        let one = Expression::Constant(F::ONE);

        let difference = meta.advice_column();
        let difference_inverse = meta.advice_column();
        let first_difference_limb = meta.advice_column();
        let selector = meta.fixed_column();

        let mut limb_vector = vec![0 as u8];
        for i in 1..40 {
            limb_vector.push(i);
        }

        // inversion gate
        meta.create_gate("difference is non-zero", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let difference = meta.query_advice(difference, Rotation::cur());
            let difference_inverse = meta.query_advice(difference_inverse, Rotation::cur());
            vec![selector * (difference * difference_inverse - one.clone())]
        });

        // limbs before first differences are zero
        meta.create_gate("limbs before first differences are zero", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let first_difference_limb = meta.query_advice(first_difference_limb, Rotation::cur());
            let cur = Queries::new(meta, address, time_log, instruction, value, Rotation::cur());
            let prev = Queries::new(
                meta,
                address,
                time_log,
                instruction,
                value,
                Rotation::prev(),
            );
            let rlc = rlc_limb_differences(cur, prev, alpha_power.clone());
            let mut constraints = vec![];
            for (i, rlc_expression) in limb_vector.iter().zip(rlc) {
                constraints.push(
                    selector.clone()
                        * equal(
                            first_difference_limb.clone(),
                            Expression::Constant(F::from(*i as u64)),
                        )
                        * rlc_expression,
                );
            }
            constraints
        });

        // if the current trace is read, then its value must be equal to the previous trace value
        meta.create_gate("if the current trace is read, then its value must be equal to the previous trace value", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let cur = Queries::new(
                meta,
                address,
                time_log,
                instruction,
                value,
                Rotation::cur());
            let prev = Queries::new(
                meta,
                address,
                time_log,
                instruction,
                value,
                Rotation::prev());
            let mut partial_sum = Expression::Constant(F::ZERO);
            for ((cur_value, prev_value), power_of_randomness) in
                cur.value.iter().zip(prev.value.iter()).zip(alpha_power)
            {
                partial_sum =
                    partial_sum + power_of_randomness * (cur_value.clone() - prev_value.clone());
            }
            vec![selector * (cur.instruction - one.clone()) * partial_sum]
        });

        // difference equals difference of limbs at index
        meta.create_gate("difference equals difference of limbs at index", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let cur = Queries::new(meta, address, time_log, instruction, value, Rotation::cur());
            let prev = Queries::new(
                meta,
                address,
                time_log,
                instruction,
                value,
                Rotation::prev(),
            );
            let difference = meta.query_advice(difference, Rotation::cur());
            let first_difference_limb = meta.query_advice(first_difference_limb, Rotation::cur());
            let mut constraints = vec![];
            for ((i, cur_limb), prev_limb) in limb_vector
                .iter()
                .zip(&cur.be_limbs())
                .zip(&prev.be_limbs())
            {
                constraints.push(
                    selector.clone()
                        * equal(
                            first_difference_limb.clone(),
                            Expression::Constant(F::from(*i as u64)),
                        )
                        * (difference.clone() - cur_limb.clone() + prev_limb.clone()),
                )
            }
            constraints
        });

        // instruction must be equal to 0 or 1
        meta.create_gate("instruction must be equal to 0 or 1", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let cur = Queries::new(meta, address, time_log, instruction, value, Rotation::cur());
            vec![selector * cur.instruction.clone() * (cur.instruction.clone() - one)]
        });

        // lookup gate for difference. It must be in [0..64]
        u64_table.range_check(meta, "difference fits in 0..64", |meta| {
            meta.query_advice(difference, Rotation::cur())
        });

        // each limb of address and value must be in [0..64]
        for i in 0..32 {
            u64_table.range_check(meta, "limb of address fits in 0..64", |meta| {
                meta.query_advice(address[i], Rotation::cur())
            });
            u64_table.range_check(meta, "limb of value fits in 0..64", |meta| {
                meta.query_advice(value[i], Rotation::cur())
            });
        }

        // each limb of time_log must be in [0..64]
        for i in 0..8 {
            u64_table.range_check(meta, "limb of time log fits in 0..64", |meta| {
                meta.query_advice(time_log[i], Rotation::cur())
            });
        }

        // lookup gate for first_difference_limb. It must be in [0,39]
        u40_table.range_check(meta, "difference fits into 0..40", |meta| {
            meta.query_advice(first_difference_limb, Rotation::cur())
        });

        // return the config after assigning the gates
        LexicographicConfig {
            difference,
            difference_inverse,
            first_difference_limb,
            address,
            time_log,
            instruction,
            value,
            selector,
            _marker: PhantomData,
        }
    }
}
// return 1 if lhs=rhs and 0 otherwise
fn equal<F: Field + PrimeField>(lhs: Expression<F>, rhs: Expression<F>) -> Expression<F> {
    let diff = lhs - rhs;
    if diff == Expression::Constant(F::ZERO) {
        return Expression::Constant(F::ONE);
    }
    Expression::Constant(F::ZERO)
}

// Returns a vector of length 32 with the rlc of the limb differences between
// from 0 to i-l. 0 for i=0,
fn rlc_limb_differences<F: Field + PrimeField>(
    cur: Queries<F>,
    prev: Queries<F>,
    alpha_power: Vec<Expression<F>>,
) -> Vec<Expression<F>> {
    let mut result = vec![];
    let mut partial_sum = Expression::Constant(F::ZERO);
    let alpha_power = once(Expression::Constant(F::ONE)).chain(alpha_power.into_iter());
    for ((cur_limb, prev_limb), power_of_randomness) in
        cur.be_limbs().iter().zip(&prev.be_limbs()).zip(alpha_power)
    {
        result.push(partial_sum.clone());
        partial_sum = partial_sum + power_of_randomness * (cur_limb.clone() - prev_limb.clone());
    }
    result
}

/// The circuit for lexicographic ordering
#[derive(Default)]
pub struct LexicographicCircuit<F: PrimeField> {
    sorted_trace_record: Vec<ProvableTraceRecord<F>>,
    _marker: PhantomData<F>,
}

impl<F: Field + PrimeField> Circuit<F> for LexicographicCircuit<F> {
    type Config = LexicographicConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    // configure the circuit
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let rng = thread_rng();

        let alpha = Expression::Constant(F::random(rng));
        let mut tmp = Expression::Constant(F::ONE);
        let address = [meta.advice_column(); 32];
        let time_log = [meta.advice_column(); 8];
        let instruction = meta.advice_column();
        let value = [meta.advice_column(); 32];
        let u64_table = UTable::<64>::construct(meta);
        let u40_table = UTable::<40>::construct(meta);
        let mut alpha_power: Vec<Expression<F>> = vec![tmp.clone()];
        for _ in 0..40 {
            tmp = tmp * alpha.clone();
            alpha_power.push(tmp.clone());
        }
        LexicographicConfig::configure(
            meta,
            address,
            time_log,
            instruction,
            value,
            u64_table,
            u40_table,
            alpha_power,
        )
    }

    // assign the witness values to the entire witness table and their constraints
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let _ = layouter.assign_region(
            || "lexicographic_ordering",
            |mut region| {
                for i in 0..self.sorted_trace_record.len() {
                    let _ = self.assign(&mut region, config, i);
                }
                Ok(())
            },
        );
        Ok(())
    }
}

impl<F: Field + PrimeField> LexicographicCircuit<F> {
    // assign the witness values to the offset-th row of the witness table
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        config: LexicographicConfig<F>,
        offset: usize,
    ) -> Result<(), Error> {
        if offset == 0 {
            let (cur_address, cur_time_log, cur_instruction, cur_value) =
                self.sorted_trace_record[offset].get_tuple();

            // assign the address witness
            for i in 0..32 {
                region.assign_advice(
                    || format!("address{}", offset),
                    config.address[i],
                    offset,
                    || Value::known(cur_address[i]),
                )?;
            }

            // assign the time_log witness
            for i in 0..8 {
                region.assign_advice(
                    || format!("time_log{}", offset),
                    config.time_log[i],
                    offset,
                    || Value::known(cur_time_log[i]),
                )?;
            }

            // assign the instruction witness
            region.assign_advice(
                || format!("instruction{}", offset),
                config.instruction,
                offset,
                || Value::known(cur_instruction),
            )?;

            // assign the value witness
            for i in 0..32 {
                region.assign_advice(
                    || format!("value{}", offset),
                    config.value[i],
                    offset,
                    || Value::known(cur_value[i]),
                )?;
            }
        } else {
            let (cur_address, cur_time_log, cur_instruction, cur_value) =
                self.sorted_trace_record[offset].get_tuple();
            let (prev_address, prev_time_log, _prev_instruction, _prev_value) =
                self.sorted_trace_record[offset - 1].get_tuple();
            let cur_be_limbs = self.trace_to_be_limbs(cur_time_log, cur_address);
            let prev_be_limbs = self.trace_to_be_limbs(prev_time_log, prev_address);

            let mut limb_vector = vec![0 as u8];
            for i in 1..40 {
                limb_vector.push(i);
            }
            // find the minimal index such that cur is not equal to prev
            let find_result = limb_vector
                .iter()
                .zip(&cur_be_limbs)
                .zip(&prev_be_limbs)
                .find(|((_, a), b)| a != b);
            let zero = F::ZERO;
            let ((index, cur_limb), prev_limb) = if cfg!(test) {
                find_result.unwrap_or(((&40, &zero), &zero))
            } else {
                find_result.expect("two trace records cannot be the same")
            };
            let difference = *cur_limb - *prev_limb;

            // assign the selector to be one at the current row
            region.assign_fixed(
                || "selector",
                config.selector,
                offset,
                || Value::known(F::ONE),
            )?;

            // assign the difference witness
            region.assign_advice(
                || format!("difference{}", offset),
                config.difference,
                offset,
                || Value::known(difference),
            )?;

            // assign the inverse of the difference witness
            region.assign_advice(
                || format!("difference_inverse{}", offset),
                config.difference_inverse,
                offset,
                || Value::known(difference.invert().expect("cannot find inverse")),
            )?;

            // assign the first_difference_limb witness
            region.assign_advice(
                || format!("first_difference_limb{}", offset),
                config.first_difference_limb,
                offset,
                || Value::known(F::from(*index as u64)),
            )?;

            // assign the address witness
            for i in 0..32 {
                region.assign_advice(
                    || format!("address{}", offset),
                    config.address[i],
                    offset,
                    || Value::known(cur_address[i]),
                )?;
            }

            // assign the time_log witness
            for i in 0..8 {
                region.assign_advice(
                    || format!("time_log{}", offset),
                    config.time_log[i],
                    offset,
                    || Value::known(cur_time_log[i]),
                )?;
            }

            // assign the instruction witness
            region.assign_advice(
                || format!("instruction{}", offset),
                config.instruction,
                offset,
                || Value::known(cur_instruction),
            )?;

            // assign the value witness
            for i in 0..32 {
                region.assign_advice(
                    || format!("value{}", offset),
                    config.value[i],
                    offset,
                    || Value::known(cur_value[i]),
                )?;
            }
        }
        Ok(())
    }

    fn trace_to_be_limbs(&self, time_log: [F; 8], address: [F; 32]) -> Vec<F> {
        let mut be_bytes = vec![];
        be_bytes.extend_from_slice(&address);
        be_bytes.extend_from_slice(&time_log);
        be_bytes
    }
}

// convert a trace record into a list of element having the form of Expression<F>
struct Queries<F: Field + PrimeField> {
    address: [Expression<F>; 32], //64 bits
    time_log: [Expression<F>; 8], //64 bits
    instruction: Expression<F>,   // 0 or 1
    value: [Expression<F>; 32],   //64 bit
}

impl<F: Field + PrimeField> Queries<F> {
    // converts the attributes of a trace record to type Expression<F>
    fn new(
        meta: &mut VirtualCells<'_, F>,
        address: [Column<Advice>; 32],
        time_log: [Column<Advice>; 8],
        instruction: Column<Advice>,
        value: [Column<Advice>; 32],
        rotation: Rotation,
    ) -> Self {
        let mut query_advice = |column| meta.query_advice(column, rotation);
        Self {
            address: address.map(&mut query_advice),
            time_log: time_log.map(&mut query_advice),
            instruction: query_advice(instruction),
            value: value.map(&mut query_advice),
        }
    }

    // stack address and time_log into a single array for comparison
    fn be_limbs(&self) -> Vec<Expression<F>> {
        self.address
            .iter()
            .rev()
            .chain(self.time_log.iter().rev())
            .cloned()
            .collect()
    }
}

struct ProvableTraceRecord<F: Field + PrimeField> {
    address: [F; 32], //64 bits
    time_log: [F; 8], //64 bits
    instruction: F,   // 0 or 1
    value: [F; 32],   //64 bit
}

impl<F: Field + PrimeField> ProvableTraceRecord<F> {
    fn get_tuple(&self) -> ([F; 32], [F; 8], F, [F; 32]) {
        (self.address, self.time_log, self.instruction, self.value)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    #[test]
    fn unit_test() {
        let trace0 = ProvableTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(1),
            value: [Fp::from(0); 32],
        };
        let trace1 = ProvableTraceRecord {
            address: [Fp::from(1); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(0),
            value: [Fp::from(0); 32],
        };
        let trace = vec![trace0, trace1];
        let circuit = LexicographicCircuit {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };
        // the number of rows cannot exceed 2^k
        let k = 7;
        let res = Fp::from(0);
        let prover = MockProver::run(k, &circuit, vec![vec![res]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
