use clap::{arg, Command};
use core::panic;
use dotenv::dotenv;
use libecvrf::{helper::random_bytes, KeyPair};
use node::SQLiteDB;
use regex::Regex;
use serde_json::json;
use std::env;

fn decode_u32(val: String) -> u32 {
    let regex_u32 = Regex::new(r#"\d{1,10}"#).expect("Unable to init Regex");
    match regex_u32.is_match(val.as_str().as_ref()) {
        true => val.as_str().parse::<u32>().expect("Unable to parse u32"),
        false => panic!("Invalid input u32 value"),
    }
}

fn decode_address(val: String) -> String {
    let regex_address = Regex::new(r#"^0x[a-fA-F0-9]{40}$"#).expect("Unable to init Regex");
    match regex_address.is_match(val.as_str().as_ref()) {
        true => val.clone().to_lowercase(),
        false => panic!("Invalid input address value"),
    }
}

fn decode_name(val: String) -> String {
    let regex_name = Regex::new(r#"^[a-zA-Z0-9]{3,40}$"#).expect("Unable to init Regex");
    match regex_name.is_match(val.as_str().as_ref()) {
        true => val.clone(),
        false => panic!("Invalid input name value"),
    }
}

fn cli() -> Command {
    Command::new("cli")
        .about("Orochi Network command line interface")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("addUser")
                .about("Add new user with given username")
                .arg(arg!(username: <USERNAME> "Username of user"))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("addReceiver")
                .about("Add new target receiver smart contract")
                .arg(arg!(name: <NAME> "The remote to target"))
                .arg(arg!(address: <ADDRESS> "Ethereum address of receiver"))
                .arg(arg!(network: <NETWORK> "Network ID of target platform"))
                .arg_required_else_help(true),
        )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenv().ok();
    let matches = cli().get_matches();
    let database_url = env::var("DATABASE_URL").expect("Can not connect to the database");
    // @todo: Move these to another module, we should separate between KEYS and API
    let sqlite = SQLiteDB::new(database_url).await;

    match matches.subcommand() {
        Some(("addUser", sub_matches)) => {
            let keyring = sqlite.table_keyring();
            let new_key_pair = KeyPair::new();
            let username = sub_matches
                .get_one::<String>("username")
                .expect("Unable to get username from argument")
                .trim()
                .to_string();
            let username = decode_name(username);
            let mut bytes = [0u8; 24];
            random_bytes(&mut bytes);
            keyring
                .insert(json!({
                    "username": username,
                    "hmac_secret": hex::encode(bytes),
                    "public_key": hex::encode(new_key_pair.public_key.serialize()),
                    "secret_key": hex::encode(new_key_pair.secret_key.serialize()),
                }))
                .await?;
            println!("Add new user: {}", username);
            println!(" - hmac_secret: {}", hex::encode(bytes));
            println!(
                " - public_key: {}",
                hex::encode(new_key_pair.public_key.serialize())
            );
            println!(
                " - secret_key: {}",
                hex::encode(new_key_pair.secret_key.serialize())
            );
        }
        Some(("addReceiver", sub_matches)) => {
            let table_receiver = sqlite.table_receiver();
            let name = sub_matches
                .get_one::<String>("name")
                .expect("Unable to get name")
                .trim()
                .to_string();
            let address = sub_matches
                .get_one::<String>("address")
                .expect("Unable to get address")
                .trim()
                .to_string();
            let network_id = sub_matches
                .get_one::<String>("network")
                .expect("Unable to get network id")
                .trim()
                .to_string();

            let name = decode_name(name);
            let address = decode_address(address);
            let network_id = decode_u32(network_id);
            table_receiver
                .insert(json!({
                    "name": name,
                    "address": address,
                    "network": network_id,
                    "nonce": 0,
                }))
                .await?;
            println!(
                "Add new receiver name: {} address: {} network: {}",
                name, address, network_id
            );
        }
        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachable!()
    }

    Ok(())
}
