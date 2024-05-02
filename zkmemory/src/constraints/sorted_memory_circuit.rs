//! Circuit for checking the constraints of the sorted memory trace record
extern crate alloc;
use crate::constraints::{
    common::CircuitExtension,
    gadgets::{
        ConvertedTraceRecord, GreaterThanConfig, IsZeroConfig, LookUpTables, Queries, Table,
        TraceRecordWitnessTable,
    },
};
use alloc::{format, vec, vec::Vec};
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use rand::thread_rng;

#[derive(Clone, Copy, Debug)]
/// Define the columns for the constraint
pub(crate) struct SortedMemoryConfig<F: Field + PrimeField> {
    /// The fields of an execution trace
    pub(crate) trace_record: TraceRecordWitnessTable<F>,
    /// The difference between the current and the previous address
    pub(crate) addr_cur_prev: IsZeroConfig<F>,
    /// The config for checking the current address||time_log is bigger
    /// than the previous one
    pub(crate) greater_than: GreaterThanConfig<F, 6>,
    /// The selectors
    pub(crate) selector: Column<Fixed>,
    pub(crate) selector_zero: Selector,
    /// The lookup table
    pub(crate) lookup_tables: LookUpTables,
    /// Just the phantom data
    pub(crate) _marker: PhantomData<F>,
}
// Current constraints in this configure:
// 1) instruction[0]=1
// 2) address[i+1]||time[i+1]>address[i]||time[i]
// 3) (addr[i+1]-addr[i])*(instruction[i+1]-1)*(val[i+1]-val[i])=0
// 4) (addr[i+1]-addr[i])*(instruction[i+1]-1)=0
// There will be more constraints in the config when we support push and pop
impl<F: Field + PrimeField> SortedMemoryConfig<F> {
    /// Configuration for the circuit
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        trace_record: TraceRecordWitnessTable<F>,
        lookup_tables: LookUpTables,
        alpha_power: Vec<Expression<F>>,
    ) -> Self {
        let one = Expression::Constant(F::ONE);

        let selector = meta.fixed_column();
        let selector_zero = meta.selector();
        let addr_cur_prev = IsZeroConfig::<F>::configure(meta, selector);

        // addr[i+1]>addr[i] OR addr[i+1]=addr[i] and time[i+1]>time[i]
        let greater_than = GreaterThanConfig::<F, 6>::configure(
            meta,
            trace_record,
            alpha_power,
            lookup_tables,
            selector,
            true,
        );
        // instruction[0]=1
        meta.create_gate("instruction of the first access must be write", |meta| {
            let cur = Queries::new(meta, trace_record, Rotation::cur());
            let selector_zero = meta.query_selector(selector_zero);
            vec![selector_zero * (cur.instruction - one.clone())]
        });

        // (addr[i+1]-addr[i])*(instruction[i+1]-1)*(val[i+1]-val[i])=0
        meta.create_gate("if the current trace is read, then its value must be equal to the previous trace value", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let cur = Queries::new(meta,trace_record,Rotation::cur());
            let prev = Queries::new(meta,trace_record,Rotation::prev());
            let addr_diff=meta.query_advice(addr_cur_prev.val, Rotation::cur());
            let temp=meta.query_advice(addr_cur_prev.temp, Rotation::cur());
            let val_diff=limbs_to_expression(cur.value)-limbs_to_expression(prev.value);
            let should_be_zero=one.clone()-addr_diff.clone()*temp;
            let should_be_zero_2=limbs_to_expression(cur.address)-limbs_to_expression(prev.address)-addr_diff.clone();
            vec![selector.clone() * (cur.instruction - one.clone()) * val_diff*should_be_zero,
            selector.clone()*should_be_zero_2]
        });

        // (addr[i+1]-addr[i])*(instruction[i+1]-1)=0
        meta.create_gate(
            "the first time an address is accessed, it instruction must be write",
            |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                let cur = Queries::new(meta, trace_record, Rotation::cur());
                let prev = Queries::new(meta, trace_record, Rotation::prev());
                let addr_diff =
                    limbs_to_expression(cur.address) - limbs_to_expression(prev.address);
                vec![selector * (cur.instruction - one.clone()) * addr_diff.clone()]
            },
        );

        // instruction[i] is in [0,1] for all i
        lookup_tables
            .size2_table
            .range_check(meta, "instruction must be in 0..1", |meta| {
                meta.query_advice(trace_record.instruction, Rotation::cur())
            });

        // Each limb of address and value must be in [0..256]
        for (addr, val) in trace_record.address.iter().zip(&trace_record.value) {
            lookup_tables.size256_table.range_check(
                meta,
                "limb of address fits in 0.256",
                |meta| meta.query_advice(*addr, Rotation::cur()),
            );
            lookup_tables
                .size256_table
                .range_check(meta, "limb of value fits in 0..256", |meta| {
                    meta.query_advice(*val, Rotation::cur())
                });
        }

        // Each limb of time_log must be in [0..256]
        for i in trace_record.time_log {
            lookup_tables.size256_table.range_check(
                meta,
                "limb of time log fits in 0..256",
                |meta| meta.query_advice(i, Rotation::cur()),
            );
        }

        // Return the config after assigning the gates
        SortedMemoryConfig {
            trace_record,
            addr_cur_prev,
            greater_than,
            selector,
            selector_zero,
            lookup_tables,
            _marker: PhantomData,
        }
    }
}

fn limbs_to_expression<F: Field + PrimeField>(limb: [Expression<F>; 32]) -> Expression<F> {
    let mut sum = Expression::Constant(F::ZERO);
    for t in limb.iter().skip(1) {
        sum = sum * Expression::Constant(F::from(256_u64)) + t.clone();
    }
    sum
}

/// Circuit for sorted trace record
#[derive(Default)]
pub(crate) struct SortedMemoryCircuit<F: PrimeField> {
    /// The sorted memory trace record
    pub(crate) sorted_trace_record: Vec<ConvertedTraceRecord<F>>,
    pub(crate) _marker: PhantomData<F>,
}

/// Implement the CircuitExtension trait for the SortedMemoryCircuit
impl<F: Field + PrimeField> CircuitExtension<F> for SortedMemoryCircuit<F> {
    fn synthesize_with_layouter(
        &self,
        config: Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "sorted memory trace region",
            |mut region| {
                for i in 0..self.sorted_trace_record.len() {
                    self.sorted_memory_assign(&mut region, config, i)?;
                }
                config.lookup_tables.size40_table.load(&mut region)?;
                config.lookup_tables.size256_table.load(&mut region)?;
                config.lookup_tables.size2_table.load(&mut region)?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

impl<F: Field + PrimeField> Circuit<F> for SortedMemoryCircuit<F> {
    type Config = SortedMemoryConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    // Configure the circuit
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let rng = thread_rng();

        // The elements of the trace record
        let trace_record = TraceRecordWitnessTable::<F>::new(meta);

        // Lookup tables
        let lookup_tables = LookUpTables {
            size256_table: Table::<256>::construct(meta),
            size40_table: Table::<40>::construct(meta),
            size2_table: Table::<2>::construct(meta),
        };
        // The random challenges
        // For debugging of testing, we let alpha to be uniformly distributed
        // Later, one can force the prover to commit the memory traces first, then
        // let alpha to be the hash of the commitment
        let alpha = Expression::Constant(F::random(rng));
        let mut temp = Expression::Constant(F::ONE);
        let mut alpha_power: Vec<Expression<F>> = vec![temp.clone()];
        for _ in 0..40 {
            temp = temp * alpha.clone();
            alpha_power.push(temp.clone());
        }

        SortedMemoryConfig::configure(meta, trace_record, lookup_tables, alpha_power)
    }

    // Assign the witness values to the entire witness table and their constraints
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.synthesize_with_layouter(config, &mut layouter)
    }
}

impl<F: Field + PrimeField> SortedMemoryCircuit<F> {
    // Assign the witness values to the offset-th row of the witness table
    fn sorted_memory_assign(
        &self,
        region: &mut Region<'_, F>,
        config: SortedMemoryConfig<F>,
        offset: usize,
    ) -> Result<(), Error> {
        // Handle the case offset=0
        if offset == 0 {
            let (cur_address, cur_time_log, cur_instruction, cur_value) =
                self.sorted_trace_record[offset].get_tuple();

            // Turn on the first selector when offset=0
            config.selector_zero.enable(region, offset)?;

            // Assign the address witness
            for (i, j) in cur_address.iter().zip(config.trace_record.address) {
                region.assign_advice(
                    || format!("address{}", offset),
                    j,
                    offset,
                    || Value::known(*i),
                )?;
            }
            // Assign the time_log witness
            for (i, &cur_t) in cur_time_log.iter().enumerate() {
                region.assign_advice(
                    || format!("time_log{}", offset),
                    config.trace_record.time_log[i],
                    offset,
                    || Value::known(cur_t),
                )?;
            }

            // Assign the instruction witness
            region.assign_advice(
                || format!("instruction{}", offset),
                config.trace_record.instruction,
                offset,
                || Value::known(cur_instruction),
            )?;
            // Assign the value witness
            for (i, j) in cur_value.iter().zip(config.trace_record.value) {
                region.assign_advice(
                    || format!("value{}", offset),
                    j,
                    offset,
                    || Value::known(*i),
                )?;
            }
        }
        // Handle the case offset >= 1
        else {
            let rng = thread_rng();
            // Get the current and the previous trace record
            let (cur_address, cur_time_log, cur_instruction, cur_value) =
                self.sorted_trace_record[offset].get_tuple();
            let (prev_address, prev_time_log, _prev_instruction, _prev_value) =
                self.sorted_trace_record[offset - 1].get_tuple();
            // Stack the address and time log together
            let cur_be_limbs = self.trace_to_be_limbs(cur_time_log, cur_address);
            let prev_be_limbs = self.trace_to_be_limbs(prev_time_log, prev_address);
            let limb_vector: Vec<u8> = (0..40).collect();
            // Find the minimal index such that cur is not equal to prev
            let find_result = limb_vector
                .iter()
                .zip(&cur_be_limbs)
                .zip(&prev_be_limbs)
                .find(|((_, a), b)| a != b);
            let zero = F::ZERO;
            let ((index, cur_limb), prev_limb) = if cfg!(test) {
                find_result.unwrap_or(((&40, &zero), &zero))
            } else {
                find_result.expect("two trace records cannot have the same address then time log")
            };
            // Difference of address||time_log
            let difference = *cur_limb - *prev_limb;

            // Difference of address
            let address_diff =
                self.address_limb_to_field(cur_address) - self.address_limb_to_field(prev_address);

            // Compute the inverse of address_diff
            let (temp, temp_inv) = if address_diff == F::ZERO {
                let temp = F::random(rng);
                let temp_inv = temp.invert().expect("cannot find inverse");
                (temp, temp_inv)
            } else {
                let temp = address_diff.invert().expect("cannot find inverse");
                let temp_inv = address_diff;
                (temp, temp_inv)
            };

            // Assign the selector to be one at the current row
            region.assign_fixed(
                || "selector",
                config.selector,
                offset,
                || Value::known(F::ONE),
            )?;

            // Assign the address witness
            for (i, j) in cur_address.iter().zip(config.trace_record.address) {
                region.assign_advice(
                    || format!("address{}", offset),
                    j,
                    offset,
                    || Value::known(*i),
                )?;
            }

            // Assign the time_log witness
            for (i, &cur_t) in cur_time_log.iter().enumerate() {
                region.assign_advice(
                    || format!("time_log{}", offset),
                    config.trace_record.time_log[i],
                    offset,
                    || Value::known(cur_t),
                )?;
            }

            // Assign the instruction witness
            region.assign_advice(
                || format!("instruction{}", offset),
                config.trace_record.instruction,
                offset,
                || Value::known(cur_instruction),
            )?;

            // Assign the value witness
            for (i, j) in cur_value.iter().zip(config.trace_record.value) {
                region.assign_advice(
                    || format!("value{}", offset),
                    j,
                    offset,
                    || Value::known(*i),
                )?;
            }

            // Assign the address difference witness
            region.assign_advice(
                || format!("difference of address{}", offset),
                config.addr_cur_prev.val,
                offset,
                || Value::known(address_diff),
            )?;

            // Assign the inverse of address difference witness
            region.assign_advice(
                || format!("inverse difference of address{}", offset),
                config.addr_cur_prev.temp,
                offset,
                || Value::known(temp),
            )?;

            // Assign the inverse of inverse of address difference witness
            region.assign_advice(
                || format!("inverse of inverse of address{}", offset),
                config.addr_cur_prev.temp_inv,
                offset,
                || Value::known(temp_inv),
            )?;

            // Assign the difference of address||time witness
            region.assign_advice(
                || format!("difference of address||time_log{}", offset),
                config.greater_than.difference,
                offset,
                || Value::known(difference),
            )?;

            // Assign the inverse of the address||time difference witness
            region.assign_advice(
                || format!("address||time_log difference_inverse{}", offset),
                config.greater_than.difference_inverse,
                offset,
                || Value::known(difference.invert().expect("cannot find inverse")),
            )?;

            // Assign the first_difference_limb witness
            config
                .greater_than
                .first_difference_limb
                .assign(region, offset, *index)?;
        }
        Ok(())
    }

    // Stack address and time into a single array of type F
    fn trace_to_be_limbs(&self, time_log: [F; 8], address: [F; 32]) -> Vec<F> {
        address.iter().chain(time_log.iter()).cloned().collect()
    }

    // Converts the limbs of time_log into a single value of type F
    fn address_limb_to_field(&self, address: [F; 32]) -> F {
        let mut sum = F::ZERO;
        for t in address.iter().skip(1) {
            sum = sum * F::from(256_u64) + *t;
        }
        sum
    }
}

#[cfg(test)]
mod test {
    use crate::constraints::sorted_memory_circuit::{ConvertedTraceRecord, SortedMemoryCircuit};
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr as Fp;
    extern crate alloc;
    extern crate std;
    use alloc::{vec, vec::Vec};
    use std::marker::PhantomData;
    // Common test function to build and the the SortedMemoryCircuit
    fn build_and_test_circuit(trace: Vec<ConvertedTraceRecord<Fp>>, k: u32) {
        let circuit = SortedMemoryCircuit::<Fp> {
            sorted_trace_record: trace,
            _marker: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![]).expect("Cannot run the circuit");
        assert_eq!(prover.verify(), Ok(()));
    }
    #[test]
    fn test_ok_one_trace() {
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };
        build_and_test_circuit(vec![trace0], 10);
    }

    #[test]
    #[should_panic]
    fn test_error_invalid_instruction() {
        // First instruction is supposed to be write
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };
        build_and_test_circuit(vec![trace0], 10);
    }

    #[test]
    #[should_panic]
    fn test_invalid_address() {
        // Each limb of address is supposed to be in [0..256]
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(256); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };
        build_and_test_circuit(vec![trace0], 10);
    }

    #[test]
    #[should_panic]
    fn test_invalid_time_log() {
        // Each limb of address is supposed to be in [0..256]
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(256); 8],
            instruction: Fp::from(1),
            value: [Fp::from(0); 32],
        };
        build_and_test_circuit(vec![trace0], 10);
    }

    #[test]
    #[should_panic]
    fn test_invalid_value() {
        // Each limb of address is supposed to be in [0..255]
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(1),
            value: [Fp::from(256); 32],
        };
        build_and_test_circuit(vec![trace0], 10);
    }

    #[test]
    fn test_ok_two_trace() {
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };
        build_and_test_circuit(vec![trace0, trace1], 10);
    }

    #[test]
    #[should_panic]
    fn wrong_address_order() {
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(1); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };
        build_and_test_circuit(vec![trace0, trace1], 10);
    }

    #[test]
    #[should_panic]
    fn wrong_time_log_order() {
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };
        build_and_test_circuit(vec![trace0, trace1], 10);
    }

    #[test]
    #[should_panic]
    fn invalid_read() {
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(0),
            value: [Fp::from(50); 32],
        };
        build_and_test_circuit(vec![trace0, trace1], 10);
    }

    #[test]
    #[should_panic]
    fn non_first_write_access_for_two_traces() {
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = ConvertedTraceRecord {
            address: [Fp::from(1); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(0),
            value: [Fp::from(50); 32],
        };
        build_and_test_circuit(vec![trace0, trace1], 10);
    }

    #[test]
    fn test_ok_three_trace() {
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(0); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };

        let trace2 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(2); 8],
            instruction: Fp::from(1),
            value: [Fp::from(50); 32],
        };
        build_and_test_circuit(vec![trace0, trace1, trace2], 10);
    }

    #[test]
    #[should_panic]
    fn invalid_read2() {
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(2); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };

        let trace2 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(3); 8],
            instruction: Fp::from(0),
            value: [Fp::from(50); 32],
        };
        build_and_test_circuit(vec![trace0, trace1, trace2], 10);
    }

    #[test]
    #[should_panic]
    fn invalid_read3() {
        let trace0 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(1); 8],
            instruction: Fp::from(1),
            value: [Fp::from(63); 32],
        };

        let trace1 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(2); 8],
            instruction: Fp::from(1),
            value: [Fp::from(50); 32],
        };

        let trace2 = ConvertedTraceRecord {
            address: [Fp::from(0); 32],
            time_log: [Fp::from(3); 8],
            instruction: Fp::from(0),
            value: [Fp::from(63); 32],
        };
        build_and_test_circuit(vec![trace0, trace1, trace2], 10);
    }
}
