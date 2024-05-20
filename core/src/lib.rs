#![deny(clippy::unwrap_used, clippy::expect_used)]
use digest::Digest;
pub use md5::Md5;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::{prelude::SliceRandom, thread_rng, Rng};
pub use sha2::{Sha224, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use thiserror::Error;
use tracing::debug;

#[derive(Error, Debug)]
pub enum HashError {
    #[error("Error during hashing: {0}")]
    HashingError(String),
    #[error("Error during file operations: {0}")]
    FileError(String),
    #[error("Thread join error: {0}")]
    ThreadError(String),
}

/// This is the Function to generate passwords in parallel using multiple threads
pub fn generate_passwords(
    num_of_pwds: usize,
    var_min_character: usize,
    var_max_character: usize,
    threads: usize,
) -> Vec<String> {
    // We initialize a shared mutable vector to hold generated passwords
    let passwords = Arc::new(Mutex::new(Vec::with_capacity(num_of_pwds)));

    // This is used to calculate password count per thread and remainder of the passwords
    let var_pass_count = num_of_pwds / threads;
    let mut var_remain = num_of_pwds % threads;
    // We define a set of printable ASCII characters
    let set_printable_ascii_chars: Vec<char> = (32..=126).map(|c| c as u8 as char).collect(); //This is a set of valid ASCII

    // Debug logging message indicating the start of password generation
    debug!("Starting password generation with {} threads.", threads);
    // Spawn threads for password generation
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let passwords_clone = Arc::clone(&passwords);
            let set_printable_ascii_chars_clone = set_printable_ascii_chars.clone();
            let thread_extra = if var_remain > 0 {
                var_remain -= 1;
                1
            } else {
                0
            };

            thread::spawn(move || {
                let mut var_randg = thread_rng();
                let count = var_pass_count + thread_extra;
                let local_passwords: Vec<String> = (0..count)
                    .map(|_| {
                        let length = var_randg.gen_range(var_min_character..=var_max_character);
                        (0..length)
                            .map(|_| {
                                *set_printable_ascii_chars_clone
                                    .choose(&mut var_randg)
                                    .unwrap_or(&'!')
                            })
                            .collect()
                    })
                    .collect();

                let mut pwds = match passwords_clone.lock() {
                    Ok(pwd) => pwd,
                    Err(err) => panic!("Error acquiring lock: {}", err),
                };
                pwds.extend(local_passwords);
            })
        })
        .collect();

    // Waiting for all threads to finish
    for handle in handles {
        match handle.join() {
            Ok(_) => (),
            Err(err) => {
                eprintln!("Error joining thread: {:#?}", err);
            }
        }
    }

    // We are using this to extract generated passwords from the mutex and return as vector
    let locked_passwords = match passwords.lock() {
        Ok(locked) => locked,
        Err(err) => {
            panic!("Failed to acquire lock on passwords: {:?}", err);
            // Handle the error in appropriate way
        }
    };
    locked_passwords.clone()
}

/// Function to hash passwords using selected algorithm and multiple threads
pub fn hash_passwords(
    input: &[String],
    algorithm: &str,
    threads: usize,
) -> Result<Vec<Vec<u8>>, HashError> {
    // Debug logging message indicating the start of hashing process
    debug!(
        "Hashing passwords using {} algorithm across {} threads.",
        algorithm, threads
    );
    // Create a channel for inter-thread communication
    let (sender, receiver) = channel();
    let input = Arc::new(input.to_vec());
    let algorithm = algorithm.to_string(); // Clone the algorithm into a String

    let chunk_size = if input.len() % threads == 0 {
        input.len() / threads
    } else {
        input.len() / threads + 1
    };

    // Debug message indicating the start of hashing process
    debug!("Starting hash generation with {} threads.", threads);

    // Spawn threads for hashing
    for i in 0..threads {
        let input_clone = Arc::clone(&input);
        let sender_clone = sender.clone();
        let algorithm_clone = algorithm.clone(); // Clone for each thread

        thread::spawn(move || {
            let start = i * chunk_size;
            let end = std::cmp::min(start + chunk_size, input_clone.len());
            let hashes: Vec<(usize, Vec<u8>)> = input_clone[start..end]
                .iter()
                .enumerate()
                .map(|(index, password)| {
                    let hash = match algorithm_clone.as_str() {
                        "MD5" => {
                            let mut hasher = Md5::new();
                            hasher.update(password.as_bytes());
                            hasher.finalize().to_vec()
                        }
                        "SHA256" => {
                            let mut hasher = Sha256::new();
                            hasher.update(password.as_bytes());
                            hasher.finalize().to_vec()
                        }
                        "SHA512" => {
                            let mut hasher = Sha512::new();
                            hasher.update(password.as_bytes());
                            hasher.finalize().to_vec()
                        }
                        "SHA224" => {
                            let mut hasher = Sha224::new();
                            hasher.update(password.as_bytes());
                            hasher.finalize().to_vec()
                        }
                        "SHA384" => {
                            let mut hasher = Sha384::new();
                            hasher.update(password.as_bytes());
                            hasher.finalize().to_vec()
                        }
                        _ => panic!("Unsupported algorithm"),
                    };
                    (start + index, hash)
                })
                .collect();
            match sender_clone.send(hashes) {
                Ok(_) => (),
                Err(err) => {
                    eprintln!("Error sending hash data: {:?}", err);
                }
            }
        });
    }

    // This will receive hashed data from threads
    let mut result: Vec<(usize, Vec<u8>)> = Vec::with_capacity(input.len());
    for _ in 0..threads {
        match receiver.recv() {
            Ok(partial) => {
                let mut partial_result = partial;
                result.append(&mut partial_result);
            }
            Err(err) => {
                eprintln!("Error receiving hash data : {:?}", err);
            }
        }
    }

    // Sort the hashed data by index
    result.sort_by_key(|k| k.0);
    let x = result.into_iter().map(|(_, hash)| hash).collect();
    Ok(x)
}

/// Reverse lookup in the rainbow table for unmatched hashes.
fn reverse_lookup(
    hash: &[u8],
    table: &HashMap<String, String>,
    charset: &[char],
    password_length: usize,
    num_links: usize,
    algorithm: &str,
) -> Option<String> {
    let _rng = thread_rng();
    let mut current_hash = hash.to_vec();

    for _ in 0..num_links {
        let potential_pwd = reduce(&current_hash, charset, password_length);

        let new_hash = hash_password(&potential_pwd, algorithm);

        if let Some(starting_pwd) = table.get(&potential_pwd) {
            return Some(starting_pwd.clone());
        }

        current_hash = new_hash;
    }

    None
}

type MyHash = Vec<Vec<u8>>;
/// Crack passwords using a precomputed rainbow table with reverse lookup.
pub fn crack_hashes(
    hashes: MyHash,
    rainbow_table_path: &str,
    threads: usize,
    algorithm: String,
    num_links: usize,
    password_length: usize,
) -> Result<HashMap<Vec<u8>, String>, HashError> {
    let file = File::open(rainbow_table_path).map_err(|e| HashError::FileError(e.to_string()))?;
    let reader = BufReader::new(file);
    let mut rainbow_table = HashMap::new();

    // Read the rainbow table into memory
    for line in reader.lines() {
        let line = line.map_err(|e| HashError::FileError(e.to_string()))?;
        let parts: Vec<_> = line.split('\t').collect();
        if parts.len() == 2 {
            rainbow_table.insert(parts[1].to_string(), parts[0].to_string()); // end to start mapping
        }
    }

    let set_printable_ascii_chars: Vec<char> = (32..=126).map(|c| c as u8 as char).collect();

    let results = Arc::new(Mutex::new(HashMap::new()));
    let hashes = Arc::new(hashes.to_vec());
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let hashes = Arc::clone(&hashes);
            let results = Arc::clone(&results);
            let table = rainbow_table.clone();
            let set_printable_ascii_chars_clone = set_printable_ascii_chars.clone();
            let algo_clone = algorithm.clone();

            thread::spawn(move || {
                let mut local_results = HashMap::new();
                for hash in hashes.iter() {
                    if let Some(found_pwd) = reverse_lookup(
                        hash,
                        &table,
                        &set_printable_ascii_chars_clone,
                        password_length,
                        num_links,
                        &algo_clone,
                    ) {
                        local_results.insert(hash.clone(), found_pwd);
                    }
                }
                let mut res = match results.lock() {
                    Ok(mut guard) => {
                        guard.extend(local_results.clone()); // Using .clone()
                        guard
                    }
                    Err(e) => {
                        panic!("Failed to acquire mutex lock: {:?}", e);
                        // Handling error instead of panicking
                        // by logging the error or returning an error if in a function that returns Result
                    }
                };
                res.extend(local_results);
            })
        })
        .collect();

    for handle in handles {
        handle
            .join()
            .map_err(|_| HashError::ThreadError("Thread join failed".to_string()))?;
    }

    let results = match results.lock() {
        Ok(guard) => guard.clone(),
        Err(e) => {
            panic!("Failed to acquire mutex lock: {:?}", e);
        }
    };

    //
    let results = results
        .iter()
        .map(|(hash, password)| (hash.to_vec(), password.to_string()))
        .collect::<HashMap<_, _>>();
    Ok(results)
}

///Function to be used in rainbow table generation
fn hash_password(password: &str, algorithm: &str) -> Vec<u8> {
    match algorithm {
        "MD5" => {
            let mut hasher = Md5::new();
            hasher.update(password.as_bytes());
            hasher.finalize().to_vec()
        }
        "SHA256" => {
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            hasher.finalize().to_vec()
        }
        _ => panic!("Unsupported hashing algorithm: {}", algorithm),
    }
}

///Reduction function to convert hash into plain text
fn reduce(hash: &[u8], charset: &[char], length: usize) -> String {
    let number = BigUint::from_bytes_le(hash);
    let base = BigUint::from(charset.len());
    let mut pwd = String::new();

    let mut temp_number = number.clone();
    while pwd.len() < length {
        let idx = (&temp_number % &base).to_usize().unwrap_or(0);
        pwd.push(charset[idx]);
        temp_number /= &base;
    }

    pwd
}

/// Generate a rainbow table with the specified parameters.
pub fn generate_rainbow_table(
    seed_passwords: &[String],
    num_links: usize,
    password_length: usize,
    algorithm: &str,
    threads: usize,
    out_path: &str,
) -> Result<(), HashError> {
    let mut chains = Vec::new();
    let set_printable_ascii_chars: Vec<char> = (32..=126).map(|c| c as u8 as char).collect();

    let handles: Vec<_> = seed_passwords
        .chunks(seed_passwords.len() / threads + 1)
        .map(|chunk| {
            let chunk = chunk.to_vec();
            let set_chars = set_printable_ascii_chars.clone();
            let algo = algorithm.to_string();
            thread::spawn(move || {
                let mut local_chains = Vec::new();
                let _rng = thread_rng();
                for password in chunk {
                    let mut current_pwd = password.clone();
                    let mut last_hash: Vec<u8>;
                    for _ in 0..num_links {
                        last_hash = hash_password(&current_pwd, &algo);
                        current_pwd = reduce(&last_hash, &set_chars, password_length);
                    }
                    local_chains.push((password.clone(), current_pwd));
                }
                local_chains
            })
        })
        .collect();

    for handle in handles {
        let local_chains = handle
            .join()
            .map_err(|_| HashError::ThreadError("Thread join failed".to_string()))?;
        chains.extend(local_chains);
    }

    // Output to file
    let file = File::create(out_path).map_err(|e| HashError::FileError(e.to_string()))?;
    let mut writer = BufWriter::new(file);
    for (start, end) in chains {
        writeln!(writer, "{}\t{}", start, end).map_err(|e| HashError::FileError(e.to_string()))?;
    }

    Ok(())
}
