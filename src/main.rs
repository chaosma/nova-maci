use std::{
    collections::HashMap,
    env::current_dir,
    fs::File,
    io::Read,
    time::Instant,
    result::Result,
};

use ff::PrimeField;
use nova_scotia::{
    circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F1, G2,
};
use nova_snark::traits::Group;
use serde_json::Value;

/*
#[derive(Serialize, Deserialize)]
struct MACI_Inputs {
    pollEndTimestamp: String,
    packedVals: String,
    msgRoot: String,
    msgs: Vec<[String; 11]>,
    msgSubrootPathElements: Vec<[String; 4]>,
    coordPrivKey: String,
    coordPubKey: [String; 2],
    encPubKeys: Vec<[String; 2]>,
    currentStateRoot: String,
    currentBallotRoot: String,
    currentSbCommitment: String,
    currentSbSalt: String,
    currentStateLeaves: Vec<[String; 4]>,
    currentStateLeavesPathElements: Vec<Vec<[String; 4]>>,
    currentBallots: Vec<[String; 2]>,
    currentBallotsPathElements: Vec<Vec<[String; 4]>>,
    currentVoteWeights: Vec<String>,
    currentVoteWeightsPathElements: Vec<Vec<[String; 4]>>,
    newSbSalt: String,
    newSbCommitment: String,
    inputHash: String
} */

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
    let r1cs = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_file =
        root.join("src/data/circom/ProcessMessages_v2_10-2-1-2_test");

    let mut start_public_input = Vec::new();

    let mut private_inputs = Vec::new();

    for i in 0..iteration_count {
        let input_path = format!("src/data/input/input_{}.json", i);
        let private_input = read_json_file_to_hashmap(&input_path[..])?;
        if i == 0 {
            let z0 = private_input.get("inputHash")
               .and_then(|input_hash| input_hash.as_str())
               .and_then(|z0| F1::from_str_vartime(&z0)).ok_or("Error: cannot parse z0")?; 
            start_public_input.push(z0);
        }
        private_inputs.push(private_input);
    }

    println!("creating public params...");
    let pp = create_public_params(r1cs.clone());

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
