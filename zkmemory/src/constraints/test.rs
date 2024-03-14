#[cfg(test)]
mod tests {
    use crate::{
        base::{Base, B256},
        constraints::{
            consistency_check_circuit::MemoryConsistencyCircuit,
            permutation_circuit::successive_powers,
        },
        machine::{AbstractTraceRecord, MemoryInstruction, TraceRecord},
    };
    extern crate alloc;
    use alloc::{vec, vec::Vec};
    use ff::{Field, PrimeField};
    use halo2_proofs::dev::MockProver;
    use halo2curves::pasta::Fp;

    // Sort the trace by address -> time_log as keys
    fn sort_trace<K, V, const S: usize, const T: usize, F>(
        trace: Vec<(F, TraceRecord<K, V, S, T>)>,
    ) -> Vec<(F, TraceRecord<K, V, S, T>)>
    where
        K: Base<S>,
        V: Base<T>,
        F: Field + PrimeField,
    {
        let mut buffer = trace;
        buffer.sort_by(|a, b| {
            if a.1.address() == b.1.address() {
                a.1.time_log().cmp(&b.1.time_log())
            } else {
                a.1.address().cmp(&b.1.address())
            }
        });
        buffer
    }

    // Outputs the trace with their respective indexes
    fn trace_with_index<
        K: Base<S>,
        V: Base<T>,
        const S: usize,
        const T: usize,
        F: Field + PrimeField,
    >(
        trace: Vec<TraceRecord<K, V, S, T>>,
    ) -> Vec<(F, TraceRecord<K, V, S, T>)> {
        let indexes = successive_powers::<F>(trace.len() as u64);
        indexes
            .into_iter()
            .zip(trace)
            .collect::<Vec<(F, TraceRecord<K, V, S, T>)>>()
    }

    // Common test function to build and check the consistency circuit
    fn build_and_test_circuit(trace: Vec<TraceRecord<B256, B256, 32, 32>>, k: u32) {
        // Initially, the trace is sorted by time_log
        let trace = trace_with_index::<B256, B256, 32, 32, Fp>(trace);

        // Sort this trace in address and time_log
        let sorted_trace = sort_trace::<B256, B256, 32, 32, Fp>(trace.clone());

        let circuit = MemoryConsistencyCircuit::<Fp> {
            input: trace.clone(),
            shuffle: sorted_trace.clone(),
        };

        let prover = MockProver::run(k, &circuit, vec![]).expect("Cannot run the circuit");
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    #[should_panic]
    fn invalid_read_in_time_0() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Read,
            B256::from(0),
            B256::from(1),
        );

        // First instruction is read
        build_and_test_circuit(vec![trace_0], 10);
    }

    #[test]
    fn test_one_trace() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        build_and_test_circuit(vec![trace_0], 10);
    }

    #[test]
    #[should_panic]
    fn test_read_unwritten_address() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_1 = TraceRecord::<B256, B256, 32, 32>::new(
            1,
            0,
            MemoryInstruction::Read,
            B256::from(0x20),
            B256::from(0),
        );

        // Read instruction in the unwritten address
        build_and_test_circuit(vec![trace_0, trace_1], 10);
    }

    #[test]
    #[should_panic]
    fn wrong_read() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_1 = TraceRecord::<B256, B256, 32, 32>::new(
            1,
            0,
            MemoryInstruction::Read,
            B256::from(0),
            B256::from(9),
        );

        // The trace read does not match the previous write in the same address
        build_and_test_circuit(vec![trace_0, trace_1], 10);
    }

    #[test]
    #[should_panic]
    fn wrong_starting_time() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            6,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        // The trace does not start at time 0
        build_and_test_circuit(vec![trace_0], 10);
    }

    #[test]
    #[should_panic]
    fn wrong_initial_ordering() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_1 = TraceRecord::<B256, B256, 32, 32>::new(
            1,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_2 = TraceRecord::<B256, B256, 32, 32>::new(
            1,
            0,
            MemoryInstruction::Write,
            B256::from(0x20),
            B256::from(5),
        );

        build_and_test_circuit(vec![trace_0, trace_1, trace_2], 10);
    }

    #[test]
    #[should_panic]
    fn wrong_initial_ordering_continued() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_1 = TraceRecord::<B256, B256, 32, 32>::new(
            2,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_2 = TraceRecord::<B256, B256, 32, 32>::new(
            1,
            0,
            MemoryInstruction::Write,
            B256::from(0x20),
            B256::from(5),
        );

        // Initial trace is not sorted by time_log
        build_and_test_circuit(vec![trace_0, trace_1, trace_2], 10);
    }

    #[test]
    #[should_panic]
    fn wrong_permutation() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_1 = TraceRecord::<B256, B256, 32, 32>::new(
            1,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1),
        );

        let trace_2 = TraceRecord::<B256, B256, 32, 32>::new(
            2,
            0,
            MemoryInstruction::Write,
            B256::from(0x20),
            B256::from(5),
        );

        // Initially, the trace is sorted by time_log
        let trace = trace_with_index::<B256, B256, 32, 32, Fp>(vec![trace_0, trace_1, trace_2]);

        // Sort this trace in address and time_log
        let mut sorted_trace = sort_trace::<B256, B256, 32, 32, Fp>(trace.clone());
        // Tamper the permutation
        sorted_trace.swap(0, 1);

        let circuit = MemoryConsistencyCircuit::<Fp> {
            input: trace.clone(),
            shuffle: sorted_trace.clone(),
        };

        let prover = MockProver::run(9, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_basic_read_write() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0),
            B256::from(1234567),
        );

        let trace_1 = TraceRecord::<B256, B256, 32, 32>::new(
            1844674407411614,
            0,
            MemoryInstruction::Write,
            B256::from(0x20fffab),
            B256::from(231768),
        );

        let trace_2 = TraceRecord::<B256, B256, 32, 32>::new(
            1844674407551616,
            0,
            MemoryInstruction::Read,
            B256::from(0x20fffab),
            B256::from(231768),
        );

        let trace_3 = TraceRecord::<B256, B256, 32, 32>::new(
            2844674608551677,
            0,
            MemoryInstruction::Write,
            B256::from(0x60abcd1),
            B256::from(333333),
        );

        let trace_4 = TraceRecord::<B256, B256, 32, 32>::new(
            4744674428611677,
            0,
            MemoryInstruction::Read,
            B256::from(0),
            B256::from(1234567),
        );

        let trace_5 = TraceRecord::<B256, B256, 32, 32>::new(
            4744674528611677,
            0,
            MemoryInstruction::Write,
            B256::from(0x60abed1),
            B256::from(23121323),
        );

        let trace_6 = TraceRecord::<B256, B256, 32, 32>::new(
            4744674528641677,
            0,
            MemoryInstruction::Read,
            B256::from(0x60abed1),
            B256::from(23121323),
        );

        build_and_test_circuit(
            vec![
                trace_0, trace_1, trace_2, trace_3, trace_4, trace_5, trace_6,
            ],
            10,
        );
    }

    #[test]
    fn test_basic_read_write2() {
        let trace_0 = TraceRecord::<B256, B256, 32, 32>::new(
            0,
            0,
            MemoryInstruction::Write,
            B256::from(0xeeff111),
            B256::from(1231413414),
        );

        let trace_1 = TraceRecord::<B256, B256, 32, 32>::new(
            253,
            0,
            MemoryInstruction::Write,
            B256::from(0xeeff112),
            B256::from(1231431414),
        );

        let trace_2 = TraceRecord::<B256, B256, 32, 32>::new(
            500,
            0,
            MemoryInstruction::Read,
            B256::from(0xeeff112),
            B256::from(1231431414),
        );

        let trace_3 = TraceRecord::<B256, B256, 32, 32>::new(
            603,
            0,
            MemoryInstruction::Write,
            B256::from(0xeeff222),
            B256::from(1231433214),
        );

        let trace_4 = TraceRecord::<B256, B256, 32, 32>::new(
            724,
            0,
            MemoryInstruction::Write,
            B256::from(0xeeff222),
            B256::from(23434123),
        );

        let trace_5 = TraceRecord::<B256, B256, 32, 32>::new(
            897,
            0,
            MemoryInstruction::Read,
            B256::from(0xeeff222),
            B256::from(23434123),
        );

        let trace_6 = TraceRecord::<B256, B256, 32, 32>::new(
            8192,
            0,
            MemoryInstruction::Write,
            B256::from(0xffff222),
            B256::from(231121323),
        );
        build_and_test_circuit(
            vec![
                trace_0, trace_1, trace_2, trace_3, trace_4, trace_5, trace_6,
            ],
            10,
        );
    }
}
