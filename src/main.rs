use ark_ff::Field;
use ark_groth16::{generate_random_parameters, create_random_proof, verify_proof, ProvingKey, VerifyingKey, Proof};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_bls12_381::Bls12_381;
use ark_std::rand::rngs::OsRng;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;

#[derive(Clone)]
struct ExampleCircuit<F: Field> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for ExampleCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = FpVar::new_witness(cs.clone(), || self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = FpVar::new_witness(cs.clone(), || self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = a * &b;

        // we expected c = 15
        let c_expected = FpVar::constant(F::from(15u64));
        c.enforce_equal(&c_expected)?;

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use BLS12-381 Curve
    type Curve = Bls12_381;

    // Define circut,  a * b = 15
    let circuit = ExampleCircuit {
        a: Some(3.into()),
        b: Some(5.into()),
    };

    // generate parameters
    let mut rng = OsRng;
    let params = generate_random_parameters::<Curve, _, _>(circuit.clone(), &mut rng)?;

    // 提取证明密钥和验证密钥
    // Extract proof private key and verify private key
    let ProvingKey { vk, .. } = &params;

    // create proof
    let proof = create_random_proof(circuit, &params, &mut rng)?;

    // verify proof
    let pvk = ark_groth16::prepare_verifying_key(vk);
    let public_inputs = vec![];
    let is_valid = verify_proof(&pvk, &proof, &public_inputs)?;

    // output verification result
    if is_valid {
        println!("Proof is valid!");
    } else {
        println!("Proof is invalid!");
    }

    Ok(())
}
