#![deny(clippy::unwrap_used, clippy::expect_used)]

// Import necessary crates and modules
use anyhow::{Context, Result};
use clap::{Arg, Command};
use hashassin_core::{crack_hashes, generate_passwords, generate_rainbow_table, hash_passwords};
use std::net::TcpListener;
use std::thread;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::Path,
};
use tracing::{debug, error, info, Level};
//use tracing_subscriber;

fn main() -> Result<()> {
    // We use this to initialize the logger with debug level
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    // This is used to define command-line interface using clap
    let mtch_com = Command::new("Hashassin")
        .subcommand(
            Command::new("gen-passwords")
                .arg(
                    clap::Arg::new("min-chars")
                        .long("min-chars")
                        .takes_value(true)
                        .default_value("4"),
                )
                .arg(
                    clap::Arg::new("max-chars")
                        .long("max-chars")
                        .takes_value(true)
                        .default_value("4"),
                )
                .arg(
                    clap::Arg::new("out-path")
                        .long("out-path")
                        .takes_value(true),
                )
                .arg(
                    clap::Arg::new("threads")
                        .long("threads")
                        .takes_value(true)
                        .default_value("1"),
                )
                .arg(
                    clap::Arg::new("num-to-gen")
                        .long("num-to-gen")
                        .takes_value(true)
                        .default_value("10"),
                ),
        )
        .subcommand(
            Command::new("gen-hashes")
                .arg(
                    clap::Arg::new("in-path")
                        .long("in-path")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    clap::Arg::new("out-path")
                        .long("out-path")
                        .takes_value(true),
                )
                .arg(
                    clap::Arg::new("algorithm")
                        .long("algorithm")
                        .takes_value(true)
                        .default_value("SHA256"),
                )
                .arg(
                    Arg::new("threads")
                        .long("threads")
                        .takes_value(true)
                        .default_value("1"),
                ),
        )
        .subcommand(
            Command::new("gen-rainbow-table")
                .arg(
                    Arg::new("num-links")
                        .long("num-links")
                        .takes_value(true)
                        .default_value("5"),
                )
                .arg(
                    Arg::new("threads")
                        .long("threads")
                        .takes_value(true)
                        .default_value("1"),
                )
                .arg(
                    Arg::new("out-path")
                        .long("out-path")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::new("password-length")
                        .long("password-length")
                        .takes_value(true)
                        .default_value("4"),
                )
                .arg(
                    Arg::new("algorithm")
                        .long("algorithm")
                        .takes_value(true)
                        .default_value("md5"),
                )
                .arg(
                    Arg::new("in-path")
                        .long("in-path")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("crack")
                .arg(
                    Arg::new("rainbow-table")
                        .long("rainbow-table")
                        .takes_value(true)
                        .required(true),
                )
                .arg(Arg::new("out-path").long("out-path").takes_value(true))
                .arg(
                    Arg::new("threads")
                        .long("threads")
                        .takes_value(true)
                        .default_value("1"),
                )
                .arg(
                    Arg::new("algorithm")
                        .long("algorithm")
                        .takes_value(true)
                        .default_value("md5"),
                )
                .arg(
                    Arg::new("in-path")
                        .long("in-path")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::new("num-links")
                        .long("num-links")
                        .takes_value(true)
                        .default_value("5"),
                )
                .arg(
                    Arg::new("password-length")
                        .long("password-length")
                        .takes_value(true)
                        .default_value("8"),
                ),
        )
        .subcommand(
            Command::new("server")
                .arg(
                    Arg::new("host")
                        .long("host")
                        .takes_value(true)
                        .default_value("127.0.0.1"),
                )
                .arg(
                    Arg::new("port")
                        .long("port")
                        .takes_value(true)
                        .default_value("4515"),
                )
                .arg(
                    Arg::new("rainbow-table")
                        .long("rainbow-table")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::new("algorithm")
                        .long("algorithm")
                        .takes_value(true)
                        .default_value("md5"),
                )
                .arg(
                    Arg::new("num-links")
                        .long("num-links")
                        .takes_value(true)
                        .default_value("5"),
                )
                .arg(
                    Arg::new("password-length")
                        .long("password-length")
                        .takes_value(true),
                )
                .arg(
                    Arg::new("threads")
                        .long("threads")
                        .takes_value(true)
                        .default_value("1"),
                ),
        )
        .get_matches();

    // Match subcommand
    match mtch_com.subcommand() {
        Some(("gen-passwords", sub_m)) => gen_passwords_func(sub_m)?,
        Some(("gen-hashes", sub_m)) => gen_hashes_func(sub_m)?,
        Some(("gen-rainbow-table", sub_m)) => gen_rainbow_table_func(sub_m)?,
        Some(("crack", sub_m)) => crack_func(sub_m)?,
        Some(("server", sub_m)) => server_func(sub_m)?,
        _ => unreachable!(),
    }

    Ok(())
}

/// Function to read command line arguments and call generate_passwords()
fn gen_passwords_func(sub_m: &clap::ArgMatches) -> Result<()> {
    // We will extract command-line arguments here
    let var_min_character = sub_m
        .value_of_t::<usize>("min-chars")
        .context("Invalid value for min-chars")?;
    let var_max_character = sub_m
        .value_of_t::<usize>("max-chars")
        .context("Invalid value for max-chars")?;
    let num_of_pwds = sub_m
        .value_of_t::<usize>("num-to-gen")
        .context("Invalid value for num-to-gen")?;
    let cpu_threads = sub_m
        .value_of_t::<usize>("threads")
        .context("Invalid value for threads")?;
    let file_outputpath = sub_m.value_of("out-path");

    // Checking the values of arguments as per constraints in project description
    if var_min_character == 0 {
        eprintln!("Minimum characters must be greater than zero.");
        std::process::exit(1);
    }

    if var_max_character == 0 {
        eprintln!("Maximum characters must be greater than zero.");
        std::process::exit(1);
    }

    if cpu_threads == 0 {
        eprintln!("Threads must be greater than zero.");
        std::process::exit(1);
    }

    if num_of_pwds == 0 {
        eprintln!("Number of passwords must be greater than zero.");
        std::process::exit(1);
    }

    if var_max_character < var_min_character {
        eprintln!("Maximum characters must be greater than or equal to minimum characters.");
        std::process::exit(1);
    }
    // Logging debug information
    debug!(
        "Log > Generating passwords with min_chars: {}, max_chars: {}, count: {}, threads: {}",
        var_min_character, var_max_character, num_of_pwds, cpu_threads
    );

    // Calling the Generate passwords function from library
    let passwords = generate_passwords(
        num_of_pwds,
        var_min_character,
        var_max_character,
        cpu_threads,
    );

    // Writing passwords to file or print to stdout
    match file_outputpath {
        Some(path) => {
            let pwds_file = File::create(path)?;
            let mut buffered_write_file = BufWriter::new(pwds_file);
            for pwd in passwords.iter() {
                writeln!(buffered_write_file, "{}", pwd)?;
            }
            info!(
                "Passwords successfully written to the following path: {}",
                path
            );
        }
        None => {
            passwords.iter().for_each(|pwd| println!("{}", pwd));
            info!("Passwords printed to stdout command line");
        }
    }

    Ok(())
}

/// Function to read command line arguments and call hash_passwords()
fn gen_hashes_func(sub_m: &clap::ArgMatches) -> Result<()> {
    let file_inpath = Path::new(sub_m.value_of("in-path").context("Path is required")?);
    let file_outputpath = sub_m.value_of("out-path");
    let algorithm = sub_m.value_of("algorithm").unwrap_or("SHA256");

    let cpu_threads = sub_m
        .value_of_t::<usize>("threads")
        .context("Invalid value for threads")?;

    // Performing validation on argument
    if cpu_threads == 0 {
        eprintln!("Threads must be greater than zero.");
        std::process::exit(1);
    }

    // Read passwords from file
    let pwds_file = File::open(file_inpath)?;
    let mut buffered_read_file = BufReader::new(pwds_file);
    let mut pwds_file_content = String::new();
    buffered_read_file.read_to_string(&mut pwds_file_content)?;

    // Extracting passwords from file content
    let passwords: Vec<String> = pwds_file_content.lines().map(ToOwned::to_owned).collect();

    // Hashing the passwords
    let hashed_passwords = hash_passwords(&passwords, algorithm, cpu_threads)?;

    // Writing hashed passwords to file or printing to stdout
    if let Some(path) = file_outputpath {
        let hash_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(Path::new(path))?;
        let mut buffered_write_file = BufWriter::new(hash_file);
        for hash in hashed_passwords.iter() {
            if let Err(e) = buffered_write_file.write(hash) {
                eprintln!("Failed to write hash: {:?}", e);
                break;
            }
        }
        info!(
            "Password Hashes successfully written to the following path: {}",
            path
        );
    } else {
        for hash in hashed_passwords.iter() {
            println!("{:?}", hash);
        }
        info!("Password Hashes successfully printed to stdout command line");
    }

    Ok(())
}

/// Function to read command line arguments and call generate_rainbow_table()
fn gen_rainbow_table_func(matches: &clap::ArgMatches) -> Result<()> {
    let num_links = matches.value_of_t_or_exit::<usize>("num-links");
    let threads = matches.value_of_t_or_exit::<usize>("threads");
    let out_path = matches.value_of("out-path").unwrap_or("Incorrect out path");
    let password_length = matches.value_of_t_or_exit::<usize>("password-length");
    let algorithm = matches.value_of("algorithm").unwrap_or("Incorrect algo");
    let in_path = matches.value_of("in-path").unwrap_or("Incorrect in path");

    let file = File::open(in_path)?;
    let reader = BufReader::new(file);
    let seed_passwords: Vec<String> = reader.lines().map_while(Result::ok).collect();

    generate_rainbow_table(
        &seed_passwords,
        num_links,
        password_length,
        algorithm,
        threads,
        out_path,
    )?;
    info!(
        "Rainbow table generated successfully and saved to {}",
        out_path
    );
    Ok(())
}

/// Function to read command line arguments and call crack_hashes() and write the output
fn crack_func(matches: &clap::ArgMatches) -> Result<()> {
    let rainbow_table_path = matches
        .value_of("rainbow-table")
        .unwrap_or("Incorrect rainbow table");
    let out_path = matches.value_of("out-path");
    let threads = matches.value_of_t_or_exit::<usize>("threads");
    let algorithm = matches.value_of("algorithm").unwrap_or("Incorrect algo");
    let num_links = matches.value_of_t_or_exit::<usize>("num-links");
    let password_length = matches.value_of_t_or_exit::<usize>("password-length");
    let in_path = matches.value_of("in-path").unwrap_or("Incorrect in path");

    let file = File::open(in_path)?;
    let mut hashes = Vec::new();
    let mut reader = BufReader::new(file);

    if algorithm == "MD5" {
        let mut hash_buf = [0_u8; 16];
        while let Ok(()) = reader.read_exact(&mut hash_buf) {
            hashes.push(hash_buf.to_vec());
        }
    } else if algorithm == "SHA256" {
        let mut hash_buf = [0_u8; 32];
        while let Ok(()) = reader.read_exact(&mut hash_buf) {
            hashes.push(hash_buf.to_vec());
        }
    } else {
        return Err(anyhow::anyhow!(
            "Unsupported algorithm, exiting the program"
        ));
    }

    let cracked_passwords = crack_hashes(
        hashes,
        rainbow_table_path,
        threads,
        algorithm.to_string(),
        num_links,
        password_length,
    )?;

    if cracked_passwords.is_empty() {
        return Err(anyhow::anyhow!("No passwords found."));
    }

    match out_path {
        Some(path) => {
            let file = File::create(path)?;
            let mut writer = BufWriter::new(file);
            for (hash, password) in cracked_passwords {
                writeln!(writer, "{}\t{}", hex::encode(hash), password)?;
            }
            info!("Cracked passwords saved to {}", path);
        }
        None => {
            for (hash, password) in cracked_passwords {
                println!("{}\t{}", hex::encode(hash), password);
            }
        }
    }
    Ok(())
}

///Function to read command line arguments and create a server using socket and call handle_client()
fn server_func(matches: &clap::ArgMatches) -> Result<()> {
    let host = matches.value_of("host").unwrap_or("Incorrect host");
    let port = matches.value_of_t_or_exit::<u16>("port");
    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr)?;
    let rainbow_table_path = matches
        .value_of("rainbow-table")
        .unwrap_or("Incorrect rainbow table");
    let algorithm = matches.value_of("algorithm").unwrap_or("Incorrect algo");
    let num_links = matches.value_of_t_or_exit::<usize>("num-links");
    let password_length = matches.value_of_t_or_exit::<usize>("password-length");
    let threads = matches.value_of_t_or_exit::<usize>("threads");

    info!("Server listening on {}", addr);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let rainbow_table_path = rainbow_table_path.to_string();
                let algorithm = algorithm.to_string();
                thread::spawn(move || {
                    handle_client(
                        stream,
                        &rainbow_table_path,
                        algorithm,
                        num_links,
                        password_length,
                        threads,
                    );
                });
            }
            Err(e) => {
                error!("Failed to accept client: {}", e);
            }
        }
    }

    Ok(())
}

type MyHash = Vec<Vec<u8>>;

///Function to read input from the client and call crack_hashes() and then send the output to the client
fn handle_client(
    stream: std::net::TcpStream,
    rainbow_table_path: &str,
    algorithm: String,
    num_links: usize,
    password_length: usize,
    threads: usize,
) {
    info!("Client connected: {:?}", stream.peer_addr()); // Log client connection
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(bytes_read) => {
                if bytes_read == 0 {
                    info!("Client disconnected: {:?}", reader.get_ref().peer_addr());
                    break; // Connection closed by the client
                }
                let line = line.trim();
                if let Some(hex_hash) = line.strip_prefix("CRACK ") {
                    let hex_hash = hex_hash.to_string();
                    let hexclone = hex_hash.clone();
                    let bytes = hex::decode(hex_hash).unwrap_or_default();

                    let bytes_clone = bytes.clone();

                    let my_hash: MyHash = vec![bytes_clone];

                    match crack_hashes(
                        my_hash,
                        rainbow_table_path,
                        threads,
                        algorithm.clone(),
                        num_links,
                        password_length,
                    ) {
                        Ok(results) => {
                            if results.is_empty() {
                                writeln!(writer, "Password not found.").expect("Write failed");
                            } else if let Some(password) = results.get(&bytes) {
                                writeln!(writer, "{}\t{}", hexclone, password)
                                    .expect("Write failed");
                            } else {
                                writeln!(writer, "Password not found.").expect("Write failed");
                            }
                        }

                        Err(e) => {
                            writeln!(writer, "Error processing your request: {}", e)
                                .expect_err("Write failed");
                        }
                    }
                    writer.flush().unwrap_or_else(|e| {
                        eprintln!("Flush failed: {:?}", e);
                    });
                }
            }
            Err(e) => {
                error!("Error reading from client: {}", e);
                break;
            }
        }
    }
}
