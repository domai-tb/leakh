use clap::{Arg, Command};
use std::fs::{self, File};
use std::io::{BufReader, BufRead, Write};
use std::path::Path;
use std::collections::HashMap;
use serde_derive::Deserialize;
use regex::Regex;
use crossbeam::channel;
use std::thread;

// Struct for configuration from TOML file
#[derive(Clone, Debug, Deserialize)]
struct Config {
    default: FileConfig,
    files: Option<HashMap<String, FileConfig>>,
}

#[derive(Clone, Debug, Deserialize)]
struct FileConfig {
    pattern: String, // regex pattern to extract password
    unwanted_strings: Vec<String>, // list of unwanted strings (as regex patterns)
    min_length: usize, // minimum length for passwords
}

fn main() {
    // Define command-line arguments using clap
    let matches = Command::new("Password Extractor")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
        .about("Extracts passwords from files")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Specifies the config file")
                .required(true),
        )
        .arg(
            Arg::new("directory")
                .short('d')
                .long("directory")
                .value_name("DIR")
                .help("Specifies the directory to scan for files")
                .required(true),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Specifies the output file location")
                .required(true),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enables verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let config_path = matches.get_one::<String>("config").unwrap();
    let directory_path = matches.get_one::<String>("directory").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();
    let verbose = *matches.get_one::<bool>("verbose").unwrap();

    // Load and parse the configuration file
    if verbose {
        println!("Loading configuration from: {}", config_path);
    }
    let config: Config = load_config(config_path);

    // Set up a channel to communicate between threads
    let (sender, receiver) = channel::unbounded();

    // Process the directory
    for entry in fs::read_dir(directory_path).expect("Unable to read directory") {
        let entry = entry.expect("Failed to read directory entry");
        let path = entry.path();
        if let Some(extension) = path.extension() {
            match extension.to_str() {
                Some("txt") | Some("csv") => {
                    println!("Processing file: {}", path.display());

                    let c_config = config.clone();
                    let c_path = path.clone();
                    let c_sender = sender.clone();

                    thread::spawn(move || {
                        let mut local_password_counts: HashMap<String, usize> = HashMap::new(); 
                        process_file(&c_path, &c_config, &mut local_password_counts, verbose);
                        c_sender.send(local_password_counts).expect("Failed to send results from thread");
                    });
                }
                _ => {  
                    println!("Ignore file: {}", path.display()); 
                }
            }
        }
    }

    // Close the sending side of the channel so the receiver will know when to stop
    drop(sender);

    // Collect all the results from the threads
    let mut password_counts: HashMap<String, usize> = HashMap::new();
    for local_counts in receiver {
        for (password, count) in local_counts {
            *password_counts.entry(password).or_insert(0) += count;
        }
    }

    // Sort passwords by count and write output
    let mut sorted_passwords: Vec<(String, usize)> = password_counts.into_iter().collect();
    sorted_passwords.sort_by(|a, b| b.1.cmp(&a.1));
    write_output(output_path, &sorted_passwords);

    println!("Password extraction complete. Output written to: {}", output_path);
}

// Load and parse the configuration file
fn load_config(config_path: &str) -> Config {
    let config_data = fs::read_to_string(config_path).expect("Unable to read config file");
    toml::from_str(&config_data).expect("Invalid TOML format")
}

// Process a single file based on the configuration
fn process_file(path: &Path, config: &Config, password_counts: &mut HashMap<String, usize>, verbose: bool) {
    let file_name = path.file_name().unwrap().to_str().unwrap();
    let file_config = config.files.as_ref()
        .and_then(|files| files.get(file_name))
        .unwrap_or(&config.default);

    let pattern = Regex::new(&file_config.pattern).expect("Invalid regex pattern");

    let file = File::open(path).expect("Unable to open file");
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.expect("Unable to read line");
        if let Some(password) = extract_password(&line, &pattern, file_config, verbose) {
            *password_counts.entry(password).or_insert(0) += 1;
        }
    }
}

// Extract the password from a line using the given pattern and filters
fn extract_password(line: &str, pattern: &Regex, config: &FileConfig, verbose: bool) -> Option<String> {
    if let Some(caps) = pattern.captures(line) {
        let password = caps[1].to_string();
        
        // Compile the unwanted strings into regex patterns
        for unwanted in &config.unwanted_strings {
            let unwanted_pattern = Regex::new(unwanted).expect("Invalid unwanted string pattern");
            if unwanted_pattern.is_match(&password) {
                if verbose {
                    println!("Filtered out unwanted password: {}", password);
                }
                return None;
            }
        }

        // Filter out passwords that are shorter than the minimum length
        if password.len() < config.min_length {
            if verbose {
                println!("Filtered out short password: {}", password);
            }
            return None;
        }

        return Some(password);
    }
    None
}

// Write the sorted passwords to the output file
fn write_output(output_path: &str, sorted_passwords: &[(String, usize)]) {
    let mut file = File::create(output_path).expect("Unable to create output file");
    let mut stats_file = File::create(format!("{}.stats.csv", output_path)).expect("Unable to create stats file");

    // stats file header
    writeln!(stats_file, "Password,Count").expect("Unable to write to stats file");

    for (password, count) in sorted_passwords {
        writeln!(file, "{}", password).expect("Unable to write to output file");
        writeln!(stats_file, "{},{}", password, count).expect("Unable to write to stats file");
    }
}
