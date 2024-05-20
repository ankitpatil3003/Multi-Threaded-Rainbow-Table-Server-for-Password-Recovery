#Commands for executing Project

#We have performed cargo fmt, cargo check, cargo clippy, and cargo build and it did not give us any errors or warnings.
#We have used the project 1 as the starting point

Navigate to the root directory of the project where README.md and CREDITS.md are located.

...\project-2-rustsysproject > cargo build

=> Commands for generating passwords 
> cargo run gen-passwords --min-chars 8 --max-chars 8 --num-to-gen 10 --threads 5 --out-path passwords.txt

=> Commands for generating Hashes for the generated password
> cargo run gen-hashes --threads 5 --in-path passwords.txt --out-path hashes.txt --algorithm SHA256

> cargo run gen-hashes --threads 5 --in-path passwords.txt --out-path hashes.txt --algorithm MD5

=> Commands for generating a rainbow table
> cargo run gen-rainbow-table --num-links 10 --threads 5 --in-path passwords.txt --out-path rainbow_table.txt --password-length 8 --algorithm SHA256

> cargo run gen-rainbow-table --num-links 10 --threads 5 --in-path passwords.txt --out-path rainbow_table.txt --password-length 8 --algorithm MD5

=> Commands for cracking the password using a rainbow table
> cargo run crack --rainbow-table rainbow_table.txt --in-path hashes.txt --out-path cracked_output.txt --algorithm SHA256 --threads 5 --num-links 10 --password-length 8

> cargo run crack --rainbow-table rainbow_table.txt --in-path hashes.txt --out-path cracked_output.txt --algorithm MD5 --threads 5 --num-links 10 --password-length 8

=> Commands for running the server to crack passwords one by one
> cargo run server --host 127.0.0.1 --port 37178 --rainbow-table rainbow_table.txt --algorithm MD5 --num-links 10 --password-length 8 --threads 5

Our project currently supports 2 Hashing algorithms which are SHA256, and MD5. You can type these in the algorithm parameter to select the algorithm as per your choice. Please make sure to give appropriate paths for in-path and out-path arguments as per your system.

**************************************************************************************


#Crates used for Project from blessed.rs

Crates used in hashassin:

anyhow: Error handling

clap: Command-line argument parsing

hashassin_core: Password generation and hashing

tracing: Logging

tracing-subscriber

tokio

async-std

hex

**************************************************************************************

Crates used in hashassin-core:

rand: Random number generation

sha2: SHA-256 hashing

thiserror: Custom error types

tracing: Logging

digest = "0.10.7"

md-5 = "0.10.6"

tracing = "0.1"

num-bigint = { version = "0.4.3", features = ["rand", "std"] }

num-traits = "0.2.15"

hex = "0.4.3"

tracing-subscriber = "0.3.9"

tokio = { version = "1.19.0", features = ["full"] }

async-std = "1.11.0"

async-channel = "1.7.1"

**************************************************************************************

To open the detailed performance report, please navigate to the report folder located inside the Performance_report directory and open index.html
>> Performance_report/report/index.html

You can interact with the report. Thanks
