use core::marker::PhantomData;

use crate::{
  constants::{NUM_FE_WITHOUT_IO_FOR_CRHF, NUM_HASH_BITS},
  gadgets::{
    ecc::AllocatedPoint,
    r1cs::{AllocatedR1CSInstance, AllocatedRelaxedR1CSInstance},
    utils::{
      alloc_num_equals, alloc_scalar_as_base, alloc_zero, conditionally_select_vec, le_bits_to_num,
    },
  },
  r1cs::{R1CSInstance, RelaxedR1CSInstance},
  traits::{
    circuit::StepCircuit, commitment::CommitmentTrait, Engine, ROCircuitTrait, ROConstantsCircuit,
  },
  Commitment,
};

pub struct MemoryCommitmentConfig<F: Field + PrimeField, const M: usize> {
   
    memory: [Column<Advice>; M],
    indices: Column<Advice>,
    pub merkle_root: Column<Instance>,
    path: MerkleTreeConfig<F>,
    /// the selectors
    selector: Column<Fixed>,
    selector_zero: Selector,
    _marker0: PhantomData<F>,
}

impl<F: Field + PrimeField> MerkleTreeConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>, merkle_root: Column<Instance>) -> Self {
        let memory = [0; 3].map(|_| meta.advice_column());
        let indices = meta.advice_column();
        let selector = meta.fixed_column();
        let selector_zero = meta.selector();
        for i in memory {
            meta.enable_equality(i);
        }

        let one = Expression::Constant(F::ONE);

        // for i=0 indices[i] is equal to zero or one
        // we handle i=0 seperately with selector_zero, since we are using
        // a common selector for the other gates.
        meta.create_gate("indices must be 0 or 1", |meta| {
            let selector_zero = meta.query_selector(selector_zero);
            let indices = meta.query_advice(indices, Rotation::cur());
            vec![selector_zero * indices.clone() * (one.clone() - indices)]
        });

        // for all i>=1 indices[i] is equal to zero or one
        meta.create_gate("indices must be 0 or 1", |meta| {
            let indices = meta.query_advice(indices, Rotation::cur());
            let selector = meta.query_fixed(selector, Rotation::cur());
            vec![selector * indices.clone() * (one.clone() - indices)]
        });

        // if indices[i]=0 then advice_cur[i][0]=advice_cur[i-1][2]
        // otherwise advice_cur[i][1]=advice_cur[i-1][2]
        meta.create_gate(
            "output of the current layer is equal to the left or right input of the next layer",
            |meta| {
                let advice_cur = advice.map(|x| meta.query_advice(x, Rotation::cur()));
                let advice_prev = advice.map(|x| meta.query_advice(x, Rotation::prev()));
                let indices = meta.query_advice(indices, Rotation::cur());
                let selector = meta.query_fixed(selector, Rotation::cur());
                vec![
                    selector
                        * ((one - indices.clone())
                            * (advice_cur[0].clone() - advice_prev[2].clone())
                            + indices * (advice_cur[1].clone() - advice_prev[2].clone())),
                ]
            },
        );

        let path=MerkleTreeConfig::<F>::config(merkle_root);

        MerkleTreeConfig {
            memory,
            indices,
            merkle_root,
            path,
            selector,
            selector_zero,
            _marker0: PhantomData,
        }
    }
}

#[derive(Default)]
/// Merkle tree circuit
pub(crate) struct MemoryTreeCircuit<
    S: Spec<F, W, R>,
    F: Field + PrimeField,
    const W: usize,
    const R: usize,
> {
    /// the leaf node we would like to open
    pub(crate) leaf: F,
    /// the values of the sibling nodes in the path
    pub(crate) elements: Vec<F>,
    /// the index of the path from the leaf to the merkle root
    pub(crate) indices: Vec<F>,
    _marker: PhantomData<S>,
}


impl<S: Spec<F, W, R> + Clone, F: Field + PrimeField, const W: usize, const R: usize, const M: usize> Circuit<F>
    for MemoryTreeCircuit<S, F, W, R>
{
    type Config = MerkleTreeConfig<F,M>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            leaf: F::ZERO,
            elements: vec![F::ZERO],
            indices: vec![F::ZERO],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        MerkleTreeConfig::<F,M>::configure(meta, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        assert_eq!(self.indices.len(), self.elements.len());
        let mut v = vec![self.leaf];

        layouter.assign_region(
            || "Merkle proof",
            |mut region| {
                for i in 0..self.indices.len() {
                    let digest = self.assign(v[i], &mut region, config, i);
                    v.push(digest.expect("cannot get digest"));
                }
                Ok(())
            },
        )?;

        let leaf_cell = layouter.assign_region(
            || "assign leaf",
            |mut region| {
                region.assign_advice(
                    || "assign leaf",
                    config.advice[0],
                    0,
                    || Value::known(self.leaf),
                )
            },
        )?;

        let digest = layouter.assign_region(
            || "assign root",
            |mut region| {
                region.assign_advice(
                    || "assign root",
                    config.advice[0],
                    0,
                    || Value::known(v[self.indices.len()]),
                )
            },
        )?;

        layouter.constrain_instance(leaf_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(digest.cell(), config.instance, 1)?;
        Ok(())
    }
}


pub struct NovaAugmentedCircuitInputs<E: Engine> {
  params: E::Scalar,
  i: E::Base,
  z0: Vec<E::Base>,
  zi: Option<Vec<E::Base>>,
  U: Option<RelaxedR1CSInstance<E>>,
  u: Option<R1CSInstance<E>>,
  T: Option<Commitment<E>>,
}

impl<E: Engine> NovaAugmentedCircuitInputs<E> {
  /// Create new inputs/witness for the verification circuit
  pub fn new(
    params: E::Scalar,
    i: E::Base,
    z0: Vec<E::Base>,
    zi: Option<Vec<E::Base>>,
    U: Option<RelaxedR1CSInstance<E>>,
    u: Option<R1CSInstance<E>>,
    T: Option<Commitment<E>>,
  ) -> Self {
    Self {
      params,
      i,
      z0,
      zi,
      U,
      u,
      T,
    }
  }
}

/// The augmented circuit F' in Nova that includes a step circuit F
/// and the circuit for the verifier in Nova's non-interactive folding scheme
pub struct NovaAugmentedCircuit<'a, E: Engine, SC: StepCircuit<E::Base>> {
  params: &'a NovaAugmentedCircuitParams,
  ro_consts: ROConstantsCircuit<E>,
  inputs: Option<NovaAugmentedCircuitInputs<E>>,
  step_circuit: &'a SC, // The function that is applied for each step
}

impl<'a, E: Engine, SC: StepCircuit<E::Base>> NovaAugmentedCircuit<'a, E, SC> {
  /// Create a new verification circuit for the input relaxed r1cs instances
  pub const fn new(
    params: &'a NovaAugmentedCircuitParams,
    inputs: Option<NovaAugmentedCircuitInputs<E>>,
    step_circuit: &'a SC,
    ro_consts: ROConstantsCircuit<E>,
  ) -> Self {
    Self {
      params,
      inputs,
      step_circuit,
      ro_consts,
    }
  }

  /// Allocate all witnesses and return
  fn alloc_witness<CS: ConstraintSystem<<E as Engine>::Base>>(
    &self,
    mut cs: CS,
    arity: usize,
  ) -> Result<
    (
      AllocatedNum<E::Base>,
      AllocatedNum<E::Base>,
      Vec<AllocatedNum<E::Base>>,
      Vec<AllocatedNum<E::Base>>,
      AllocatedRelaxedR1CSInstance<E>,
      AllocatedR1CSInstance<E>,
      AllocatedPoint<E>,
    ),
    SynthesisError,
  > {
    // Allocate the params
    let params = alloc_scalar_as_base::<E, _>(
      cs.namespace(|| "params"),
      self.inputs.as_ref().map(|inputs| inputs.params),
    )?;

    // Allocate i
    let i = AllocatedNum::alloc(cs.namespace(|| "i"), || Ok(self.inputs.get()?.i))?;

    // Allocate z0
    let z_0 = (0..arity)
      .map(|i| {
        AllocatedNum::alloc(cs.namespace(|| format!("z0_{i}")), || {
          Ok(self.inputs.get()?.z0[i])
        })
      })
      .collect::<Result<Vec<AllocatedNum<E::Base>>, _>>()?;

    // Allocate zi. If inputs.zi is not provided (base case) allocate default value 0
    let zero = vec![E::Base::ZERO; arity];
    let z_i = (0..arity)
      .map(|i| {
        AllocatedNum::alloc(cs.namespace(|| format!("zi_{i}")), || {
          Ok(self.inputs.get()?.zi.as_ref().unwrap_or(&zero)[i])
        })
      })
      .collect::<Result<Vec<AllocatedNum<E::Base>>, _>>()?;

    // Allocate the running instance
    let U: AllocatedRelaxedR1CSInstance<E> = AllocatedRelaxedR1CSInstance::alloc(
      cs.namespace(|| "Allocate U"),
      self.inputs.as_ref().and_then(|inputs| inputs.U.as_ref()),
      self.params.limb_width,
      self.params.n_limbs,
    )?;

    // Allocate the instance to be folded in
    let u = AllocatedR1CSInstance::alloc(
      cs.namespace(|| "allocate instance u to fold"),
      self.inputs.as_ref().and_then(|inputs| inputs.u.as_ref()),
    )?;

    // Allocate T
    let T = AllocatedPoint::alloc(
      cs.namespace(|| "allocate T"),
      self
        .inputs
        .as_ref()
        .and_then(|inputs| inputs.T.map(|T| T.to_coordinates())),
    )?;
    T.check_on_curve(cs.namespace(|| "check T on curve"))?;

    Ok((params, i, z_0, z_i, U, u, T))
  }

  /// Synthesizes non base case and returns the new relaxed `R1CSInstance`
  /// And a boolean indicating if all checks pass
  fn synthesize_non_base_case<CS: ConstraintSystem<<E as Engine>::Base>>(
    &self,
    mut cs: CS,
    params: &AllocatedNum<E::Base>,
    i: &AllocatedNum<E::Base>,
    z_0: &[AllocatedNum<E::Base>],
    z_i: &[AllocatedNum<E::Base>],
    U: &AllocatedRelaxedR1CSInstance<E>,
    u: &AllocatedR1CSInstance<E>,
    T: &AllocatedPoint<E>,
    arity: usize,
  ) -> Result<(AllocatedRelaxedR1CSInstance<E>, AllocatedBit), SynthesisError> {
    // Check that u.x[0] = Hash(params, U, i, z0, zi)
    let mut ro = E::ROCircuit::new(
      self.ro_consts.clone(),
      NUM_FE_WITHOUT_IO_FOR_CRHF + 2 * arity,
    );
    ro.absorb(params);
    ro.absorb(i);
    for e in z_0 {
      ro.absorb(e);
    }
    for e in z_i {
      ro.absorb(e);
    }
    U.absorb_in_ro(cs.namespace(|| "absorb U"), &mut ro)?;

    let hash_bits = ro.squeeze(cs.namespace(|| "Input hash"), NUM_HASH_BITS)?;
    let hash = le_bits_to_num(cs.namespace(|| "bits to hash"), &hash_bits)?;
    let check_pass = alloc_num_equals(
      cs.namespace(|| "check consistency of u.X[0] with H(params, U, i, z0, zi)"),
      &u.X0,
      &hash,
    )?;

    // Run NIFS Verifier
    let U_fold = U.fold_with_r1cs(
      cs.namespace(|| "compute fold of U and u"),
      params,
      u,
      T,
      self.ro_consts.clone(),
      self.params.limb_width,
      self.params.n_limbs,
    )?;

    Ok((U_fold, check_pass))
  }
}

impl<'a, E: Engine, SC: StepCircuit<E::Base>> NovaAugmentedCircuit<'a, E, SC> {
  /// synthesize circuit giving constraint system
  pub fn synthesize<CS: ConstraintSystem<<E as Engine>::Base>>(
    self,
    cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<E::Base>>, SynthesisError> {
    let arity = self.step_circuit.arity();

    // Allocate all witnesses
    let (params, i, z_0, z_i, U, u, T) =
      self.alloc_witness(cs.namespace(|| "allocate the circuit witness"), arity)?;

    // Compute variable indicating if this is the base case
    let zero = alloc_zero(cs.namespace(|| "zero"));
    let is_base_case = alloc_num_equals(cs.namespace(|| "Check if base case"), &i.clone(), &zero)?;

    // Synthesize the circuit for the base case and get the new running instance
    let Unew_base = self.synthesize_base_case(cs.namespace(|| "base case"), u.clone())?;

    // Synthesize the circuit for the non-base case and get the new running
    // instance along with a boolean indicating if all checks have passed
    let (Unew_non_base, check_non_base_pass) = self.synthesize_non_base_case(
      cs.namespace(|| "synthesize non base case"),
      &params,
      &i,
      &z_0,
      &z_i,
      &U,
      &u,
      &T,
      arity,
    )?;

    // Either check_non_base_pass=true or we are in the base case
    let should_be_false = AllocatedBit::nor(
      cs.namespace(|| "check_non_base_pass nor base_case"),
      &check_non_base_pass,
      &is_base_case,
    )?;
    cs.enforce(
      || "check_non_base_pass nor base_case = false",
      |lc| lc + should_be_false.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc,
    );

    // Compute the U_new
    let Unew = Unew_base.conditionally_select(
      cs.namespace(|| "compute U_new"),
      &Unew_non_base,
      &Boolean::from(is_base_case.clone()),
    )?;

    // Compute i + 1
    let i_new = AllocatedNum::alloc(cs.namespace(|| "i + 1"), || {
      Ok(*i.get_value().get()? + E::Base::ONE)
    })?;
    cs.enforce(
      || "check i + 1",
      |lc| lc,
      |lc| lc,
      |lc| lc + i_new.get_variable() - CS::one() - i.get_variable(),
    );

    // Compute z_{i+1}
    let z_input = conditionally_select_vec(
      cs.namespace(|| "select input to F"),
      &z_0,
      &z_i,
      &Boolean::from(is_base_case),
    )?;

    let z_next = self
      .step_circuit
      .synthesize(&mut cs.namespace(|| "F"), &z_input)?;

    if z_next.len() != arity {
      return Err(SynthesisError::IncompatibleLengthVector(
        "z_next".to_string(),
      ));
    }

    // Compute the new hash H(params, Unew, i+1, z0, z_{i+1})
    let mut ro = E::ROCircuit::new(self.ro_consts, NUM_FE_WITHOUT_IO_FOR_CRHF + 2 * arity);
    ro.absorb(&params);
    ro.absorb(&i_new);
    for e in &z_0 {
      ro.absorb(e);
    }
    for e in &z_next {
      ro.absorb(e);
    }
    Unew.absorb_in_ro(cs.namespace(|| "absorb U_new"), &mut ro)?;
    let hash_bits = ro.squeeze(cs.namespace(|| "output hash bits"), NUM_HASH_BITS)?;
    let hash = le_bits_to_num(cs.namespace(|| "convert hash to num"), &hash_bits)?;

    // Outputs the computed hash and u.X[1] that corresponds to the hash of the other circuit
    u.X1
      .inputize(cs.namespace(|| "Output unmodified hash of the other circuit"))?;
    hash.inputize(cs.namespace(|| "output new hash of this circuit"))?;

    Ok(z_next)
  }
}


pub struct SparseMatrix<F: PrimeField> {
  /// all non-zero values in the matrix
  pub data: Vec<F>,
  /// column indices
  pub indices: Vec<usize>,
  /// row information
  pub indptr: Vec<usize>,
  /// number of columns
  pub cols: usize,
}

impl<F: PrimeField> SparseMatrix<F> {
  /// 0x0 empty matrix
  pub fn empty() -> Self {
    SparseMatrix {
      data: vec![],
      indices: vec![],
      indptr: vec![0],
      cols: 0,
    }
  }

  /// Construct from the COO representation; Vec<usize(row), usize(col), F>.
  /// We assume that the rows are sorted during construction.
  pub fn new(matrix: &[(usize, usize, F)], rows: usize, cols: usize) -> Self {
    let mut new_matrix = vec![vec![]; rows];
    for (row, col, val) in matrix {
      new_matrix[*row].push((*col, *val));
    }

    for row in new_matrix.iter() {
      assert!(row.windows(2).all(|w| w[0].0 < w[1].0));
    }

    let mut indptr = vec![0; rows + 1];
    for (i, col) in new_matrix.iter().enumerate() {
      indptr[i + 1] = indptr[i] + col.len();
    }

    let mut indices = vec![];
    let mut data = vec![];
    for col in new_matrix {
      let (idx, val): (Vec<_>, Vec<_>) = col.into_iter().unzip();
      indices.extend(idx);
      data.extend(val);
    }

    SparseMatrix {
      data,
      indices,
      indptr,
      cols,
    }
  }

  /// Retrieves the data for row slice [i..j] from `ptrs`.
  /// We assume that `ptrs` is indexed from `indptrs` and do not check if the
  /// returned slice is actually a valid row.
  pub fn get_row_unchecked(&self, ptrs: &[usize; 2]) -> impl Iterator<Item = (&F, &usize)> {
    self.data[ptrs[0]..ptrs[1]]
      .iter()
      .zip(&self.indices[ptrs[0]..ptrs[1]])
  }

  /// Multiply by a dense vector; uses rayon/gpu.
  pub fn multiply_vec(&self, vector: &[F]) -> Vec<F> {
    assert_eq!(self.cols, vector.len(), "invalid shape");

    self.multiply_vec_unchecked(vector)
  }

  /// Multiply by a dense vector; uses rayon/gpu.
  /// This does not check that the shape of the matrix/vector are compatible.
  pub fn multiply_vec_unchecked(&self, vector: &[F]) -> Vec<F> {
    self
      .indptr
      .par_windows(2)
      .map(|ptrs| {
        self
          .get_row_unchecked(ptrs.try_into().unwrap())
          .map(|(val, col_idx)| *val * vector[*col_idx])
          .sum()
      })
      .collect()
  }
}