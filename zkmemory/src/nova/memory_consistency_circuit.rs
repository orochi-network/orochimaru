extern crate alloc;
use alloc::format;
use alloc::vec::{Vec};
use alloc::vec;
/// Reference to be added later.
use nova_snark::{traits::{Group, circuit::StepCircuit}
};
use bellpepper_core::{ConstraintSystem, num::AllocatedNum, SynthesisError};
use ff::Field;


#[derive(Copy, Clone)]
/// the trace record struct
pub struct TraceRecord<G: Group> {
  address: G::Scalar,
  instruction: G::Scalar,
  value: G::Scalar,
}

#[derive(Copy, Clone)]
/// memory consistency circuit
pub struct NovaMemoryConsistencyCircuit<G: Group> {
  memory_len: usize,
  trace_record: TraceRecord<G>,
}

impl<G: Group> StepCircuit<G::Scalar> for NovaMemoryConsistencyCircuit<G> {
  fn arity(&self) -> usize {
    self.memory_len + 1
  }
  /// commitment at the top
  /// the next is the changed index
  fn synthesize<CS: ConstraintSystem<G::Scalar>>(
    &self,
    cs: &mut CS,
    z_in: &[AllocatedNum<G::Scalar>],
  ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
    assert!(z_in.len() == self.memory_len + 1);
    // z_i is the i-th state of memory: The first memory_len elements are the memory cells.
    // the final element of z_i is the Merkle root of the cells.
    // trace_record is the execution trace from z_i to z_{i+1}
    // meaning that if instruction=0 then the value of trace_record must be equal to
    // z_i[address]. Also we need the merkle root in z_i

    let mut memory: Vec<AllocatedNum<G::Scalar>> = vec![];
    for i in 0..self.memory_len {
      memory.push(z_in[i].clone())
    }

    // The value variable
    let value = AllocatedNum::alloc(cs.namespace(|| format!("value")), || {
      Ok(self.trace_record.value)
    })
    .expect("unable to get value")
    .get_variable();

    // The instruction variable
    let instruction = AllocatedNum::alloc(cs.namespace(|| format!("instruction")), || {
      Ok(self.trace_record.instruction)
    })
    .expect("unable to get instruction")
    .get_variable();

    let instruction_minus_one =
      AllocatedNum::alloc(cs.namespace(|| format!("instruction minus one")), || {
        Ok(self.trace_record.instruction - G::Scalar::ONE)
      })
      .expect("unable to get instruction_minus_one")
      .get_variable();

    // The ZERO variable
    let zero = AllocatedNum::alloc(cs.namespace(|| format!("zero")), || Ok(G::Scalar::ZERO))
      .expect("unable to get zero")
      .get_variable();

    // The ONE variable
    let one = AllocatedNum::alloc(cs.namespace(|| format!("zero")), || Ok(G::Scalar::ONE))
      .expect("unable to get one")
      .get_variable();

    let mut tmp = zero;
    for i in 0..self.memory_len {
      if G::Scalar::from(i as u64) == self.trace_record.address {
        tmp = memory[i].get_variable();
      }
    }

    let tmp2 = AllocatedNum::alloc(cs.namespace(|| format!("value")), || {
      Ok(self.trace_record.value)
    })
    .expect("unable to get tmp2");

    // create the output, which includes the memory and the Merkle
    // tree commitment of the memory
    let mut z_out = vec![];
    for i in 0..self.memory_len {
      if G::Scalar::from(i as u64) != self.trace_record.address {
        z_out.push(memory[i].clone());
      } else {
        z_out.push(tmp2.clone());
      }
    }

    // create the Merkle commitment of the tree
    let commitment = AllocatedNum::alloc(cs.namespace(|| format!("merkle root")), || {
      Ok(self.merkle_tree_commit(memory.clone()))
    })
    .expect("unable to get commitment")
    .get_variable();

    // commitment to the new updated memory
    let new_commitment = AllocatedNum::alloc(cs.namespace(|| format!("merkle root")), || {
      Ok(self.merkle_tree_commit(z_out.clone()))
    })
    .expect("unable to get new commitment");

    z_out.push(new_commitment);
    assert!(z_out.len() == self.memory_len + 1);

    // commitment to the memory must be valid
    cs.enforce(
      || format!("commitment to the memory must be valid"),
      |lc| lc + commitment,
      |lc| lc + one,
      |lc| lc + z_in[self.memory_len].get_variable(),
    );

    // if instruction = 0 then memory[address]=value
    cs.enforce(
      || format!("memory[address] = value"),
      |lc| lc + instruction_minus_one,
      |lc| lc + tmp - value,
      |lc| lc + zero,
    );

    // instruction must be read or write
    cs.enforce(
      || format!("operation is read or write"),
      |lc| lc + instruction,
      |lc| lc + instruction_minus_one,
      |lc| lc + zero,
    );

    Ok(z_out)
  }
}

impl<G: Group> NovaMemoryConsistencyCircuit<G> {
  /// Create a new trace_record 
  pub fn new(memory_len: usize, address: u64, instruction: u64, value: u64) -> Self {
    Self {
      memory_len,
      trace_record: TraceRecord::<G> {
        address: G::Scalar::from(address),
        instruction: G::Scalar::from(instruction),
        value: G::Scalar::from(value),
      },
    }
  }

  /// compute the merkle root of the memory
  pub fn merkle_tree_commit
  (self, memory: Vec<AllocatedNum<G::Scalar>>) -> G::Scalar {
    let mut tmp: Vec<G::Scalar> = memory
      .into_iter()
      .map(|x| x.get_value().expect("unable to get memory values"))
      .collect();
    let mut size = tmp.len();
    while size > 1 {
      let mut tmp2 = size;
      while tmp2 > 1 {
        let left = tmp.pop().expect("unable to get left");
        let right = tmp.pop().expect("unable to get right");
        // TODO: replace "out" with a hash function
        let out = left + right + G::Scalar::ONE;
        // End TODO
        tmp.push(out);
        tmp2 = tmp2 - 2;
      }
      size = tmp.len();
    }
    tmp[0]
  }
}





