use std::{
    collections::HashMap,
    env::current_dir,
    fs::{self, File},
    io::Read,
    time::Instant,
    result::Result,
};

use ff::PrimeField;
use nova_scotia::{
    circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F1, G2,
    circom::circuit::{R1CS, CircomCircuit},
    G1, F2,
};
use nova_snark::{
    traits::{circuit::TrivialTestCircuit, Group},
    PublicParams,
};
use serde_json::Value;

type PP = PublicParams<G1, G2, CircomCircuit<F1>, TrivialTestCircuit<F2>>;

pub fn save_public_params_to_file(params: &PP, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string(params)?;
    fs::write(file_path, json)?;
    Ok(())
}

pub fn load_public_params_from_file(file_path: &str) -> Result<PP, Box<dyn std::error::Error>> {
    let json = fs::read_to_string(file_path)?;
    let params: PP = serde_json::from_str(&json)?;
    Ok(params)
}

pub fn create_public_params_if_not_exist(r1cs: R1CS<F1>, file_path: &str) -> PP {
    let pp = match load_public_params_from_file(file_path) {
        Ok(params) => {
            println!("loading public params from {:?}", file_path);
            params
        }
        Err(_) => {
            println!("creating public params...");
            let params = create_public_params(r1cs);
            println!("saving public params to {:?}", file_path);
            let _ = save_public_params_to_file(&params, file_path);
            params
        }
    };
    pp
}

fn read_json_file_to_hashmap(file_path: &str) -> Result<HashMap<String, Value>, Box<dyn std::error::Error>> {
    // Open the file
    let mut file = File::open(file_path)?;

    // Read the file content into a String
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Deserialize the JSON content into a HashMap<String, Value>
    let hashmap: HashMap<String, Value> = serde_json::from_str(&contents)?;

    // Return the HashMap
    Ok(hashmap)
}

fn bench(iteration_count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let root = current_dir().unwrap();

    let circuit_file = root.join("src/data/circom/ProcessMessages_v2_10-2-1-2_test.r1cs");
    println!("loading r1cs file: {:?}", circuit_file.clone());
    let r1cs = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_file =
        root.join("src/data/circom/ProcessMessages_v2_10-2-1-2_test");
    println!("loading witness generation bin: {:?}", witness_generator_file.clone());

    let mut start_public_input = Vec::new();

    let mut private_inputs = Vec::new();

    for i in 0..iteration_count {
        let input_path = format!("src/data/input/input_{}.json", i);
        let mut private_input = read_json_file_to_hashmap(&input_path[..])?;
        if i == 0 {
            let z0 = private_input.get("step_in")
               .and_then(|input_hash| input_hash.as_array())
               .and_then(|array| array.get(0))
               .and_then(|z0| z0.as_str())
               .and_then(|z0| F1::from_str_vartime(&z0)).ok_or("Error: cannot parse z0")?; 
            start_public_input.push(z0);
        }
        let _ = private_input.remove("step_in");
        private_inputs.push(private_input);
    }

    let file_path = "src/data/public_param.json";
    let pp = create_public_params_if_not_exist(r1cs.clone(), file_path);

    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );

    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    println!("Creating a RecursiveSNARK...");
    let start = Instant::now();
    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_file),
        r1cs,
        private_inputs,
        start_public_input.clone(),
        &pp,
    )
    .unwrap();
    let prover_time = start.elapsed();
    println!("RecursiveSNARK creation took {:?}", start.elapsed());

    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let res = recursive_snark.verify(
        &pp,
        iteration_count,
        start_public_input.clone(),
        z0_secondary.clone(),
    );
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res,
        start.elapsed()
    );
    let verifier_time = start.elapsed();
    assert!(res.is_ok());

    // produce a compressed SNARK
    // println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    // let start = Instant::now();
    // type S1 = nova_snark::spartan_with_ipa_pc::RelaxedR1CSSNARK<G1>;
    // type S2 = nova_snark::spartan_with_ipa_pc::RelaxedR1CSSNARK<G2>;
    // let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &recursive_snark);
    // println!(
    //     "CompressedSNARK::prove: {:?}, took {:?}",
    //     res.is_ok(),
    //     start.elapsed()
    // );
    // assert!(res.is_ok());
    // let compressed_snark = res.unwrap();

    // // verify the compressed SNARK
    // println!("Verifying a CompressedSNARK...");
    // let start = Instant::now();
    // let res = compressed_snark.verify(
    //     &pp,
    //     iteration_count,
    //     start_public_input.clone(),
    //     z0_secondary,
    // );
    // println!(
    //     "CompressedSNARK::verify: {:?}, took {:?}",
    //     res.is_ok(),
    //     start.elapsed()
    // );
    // assert!(res.is_ok());
    println!("prover time={:?}, verifier time={:?}", prover_time, verifier_time);
    Ok(())
}

fn main() {
    let res = bench(3);
    match res {
        Ok(()) => {
            println!("everything works fine");
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
