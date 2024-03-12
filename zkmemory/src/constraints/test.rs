#[cfg(test)]
mod test {
    use crate::machine::{AbstractTraceRecord, MemoryInstruction, TraceRecord};
    extern crate alloc;
    use crate::base::{Base, B256};
    use crate::constraints::consistency_check_circuit::MemoryConsistencyCircuit;
    use crate::constraints::permutation_circuit::successive_powers;
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

        let prover = MockProver::run(k, &circuit, vec![]).expect("What");
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
        build_and_test_circuit(vec![trace_2, trace_0, trace_1], 10);
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
            B256::from(1),
        );

        let trace_1 = TraceRecord::<B256, B256, 32, 32>::new(
            1,
            0,
            MemoryInstruction::Write,
            B256::from(0x20),
            B256::from(2),
        );

        let trace_2 = TraceRecord::<B256, B256, 32, 32>::new(
            2,
            0,
            MemoryInstruction::Read,
            B256::from(0x20),
            B256::from(0x2),
        );

        let trace_3 = TraceRecord::<B256, B256, 32, 32>::new(
            3,
            0,
            MemoryInstruction::Write,
            B256::from(0x6f),
            B256::from(3),
        );

        let trace_4 = TraceRecord::<B256, B256, 32, 32>::new(
            4,
            0,
            MemoryInstruction::Read,
            B256::from(0),
            B256::from(1),
        );
        build_and_test_circuit(vec![trace_0, trace_1, trace_2, trace_3, trace_4], 10);
    }
}
