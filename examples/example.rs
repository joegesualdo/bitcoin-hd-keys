use bitcoin_hd_keys::{
    concat_u8, convert_decimal_to_32_byte_hex_with, convert_decimal_to_8_byte_hex_with, decode_hex,
    encode_hex, get_256_bits_of_entropy, get_bip38_512_bit_private_key,
    get_child_key_from_derivation_path, get_child_keys_from_derivation_path,
    get_master_keys_from_seed, get_mnemonic_words, serialize_key, Keys, SerializeKeyArgs,
    IS_TESTNET,
};
use std::fmt::Write;
use std::num::{NonZeroU32, ParseIntError};
use std::str::FromStr;

use bitcoin::hashes::{ripemd160, Hash};
use bitcoin::util::base58::check_encode_slice;
use bitcoin::util::base58::from_check;
use bitcoin_hd_keys::bip39::WORDS;
use hmac_sha512::HMAC;
use num_bigint::BigUint;
use rand::{thread_rng, RngCore};
use ring::{digest, pbkdf2};
use secp256k1::{Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

fn get_depth_from_derivation_path(derivation_path: &String) -> u8 {
    let derivation_path_split_by_dash: Vec<&str> = derivation_path.split('/').collect();
    let first = derivation_path_split_by_dash.first().unwrap();
    if first.to_string() != "m" {
        panic!("derivation must start with m")
    } else {
        let derivation_path_without_m = derivation_path_split_by_dash.get(1..).unwrap();
        let depth = derivation_path_without_m.len() as u8;
        depth
    }
}
fn get_parent_derivation_path(derivation_path: &String) -> String {
    let derivation_path_split_by_dash: Vec<&str> = derivation_path.split('/').collect();
    let first = derivation_path_split_by_dash.first().unwrap();
    if first.to_string() != "m" {
        panic!("derivation must start with m")
    } else {
        derivation_path_split_by_dash
            .get(0..=derivation_path_split_by_dash.len() - 2)
            .unwrap()
            .join("/")
    }
}
fn get_child_index_from_derivation_path(derivation_path: &String) -> u32 {
    let derivation_path_split_by_dash: Vec<&str> = derivation_path.split('/').collect();
    let first = derivation_path_split_by_dash.first().unwrap();
    if first.to_string() != "m" {
        panic!("derivation must start with m")
    } else {
        derivation_path_split_by_dash
            .last()
            .unwrap()
            .to_string()
            .parse()
            .unwrap()
    }
}
fn get_extended_keys_from_derivation_path(
    derivation_path: &String,
    master_keys: &Keys,
) -> (String, String) {
    let parent_deviation_path = get_parent_derivation_path(derivation_path);
    let child_index = get_child_index_from_derivation_path(derivation_path);
    let found_child =
        get_child_key_from_derivation_path(derivation_path.to_string(), master_keys.clone());
    let parent_keys =
        get_child_key_from_derivation_path(parent_deviation_path, master_keys.clone());
    let depth = get_depth_from_derivation_path(&derivation_path.to_string());

    let bip32_extended_public_key = serialize_key(SerializeKeyArgs {
        key: found_child.public_key_hex.clone(),
        parent_public_key: Some(parent_keys.public_key_hex.clone()),
        child_chain_code: found_child.chain_code_hex.clone(),
        is_public: true,
        is_testnet: IS_TESTNET,
        depth: Some(depth),
        child_index: child_index as u32,
    });
    let bip32_extended_private_key = serialize_key(SerializeKeyArgs {
        key: found_child.private_key_hex.clone(),
        parent_public_key: Some(parent_keys.public_key_hex.clone()),
        child_chain_code: found_child.chain_code_hex.clone(),
        is_public: false,
        is_testnet: IS_TESTNET,
        depth: Some(depth),
        child_index: child_index as u32,
    });
    (bip32_extended_public_key, bip32_extended_private_key)
}
fn main() {
    // 1) Use some cryptographically secure entropy generator to generate 128 bits of entropy.
    // Create array of length 32 and fill with a random u8;
    let entropy_array = get_256_bits_of_entropy();

    let mnemonic_words = get_mnemonic_words(entropy_array.to_vec());
    // let words = vec![
    //     "punch".to_string(),
    //     "shock".to_string(),
    //     "entire".to_string(),
    //     "north".to_string(),
    //     "file".to_string(),
    //     "identify".to_string(),
    // ];
    println!("MNEMONIC WORDS: {:?}", mnemonic_words);

    let mnemonic_sentence = mnemonic_words.join(" ");
    println!("MNEMONIC SENTENCE: {}", mnemonic_sentence);

    // HARDCODED FOR TESTING
    // let bip39_seed = "67f93560761e20617de26e0cb84f7234aaf373ed2e66295c3d7397e6d7ebe882ea396d5d293808b0defd7edd2babd4c091ad942e6a9351e6d075a29d4df872af".to_string();
    // let bip39_seed = "029444d3ce936472cdd5a0a80aee9bae8fb849a489718c60fbe10783a3ec2a828693538fe12398a3db3c44b1dda57e50a02dee88914184617cad1d307fbb7922".to_string();
    let passphrase = "".to_string();
    let bip39_seed = get_bip38_512_bit_private_key(mnemonic_words, Some(passphrase));
    println!("BIP39 SEED: {}", bip39_seed);
    //

    // ==========MASTER KEYS===============================
    let master_keys = get_master_keys_from_seed(bip39_seed);
    let master_xprv = serialize_key(SerializeKeyArgs {
        key: master_keys.private_key_hex.clone(),
        parent_public_key: None,
        child_chain_code: master_keys.chain_code_hex.clone(),
        is_public: false,
        is_testnet: IS_TESTNET,
        depth: Some(0),
        child_index: 0,
    });
    println!("MASTER KEYS: {:#?}", master_keys);
    println!("MASTER WIF: {}", master_keys.get_wif());
    println!("BIP39 Root Key: {}", master_xprv);
    println!("MASTER ADDRESS: {}", master_keys.get_address(),);
    // ======================================================

    let derivation_path = "m/0/0/1/4".to_string();

    let (bip32_extended_public_key, bip32_extended_private_key) =
        get_extended_keys_from_derivation_path(&derivation_path, &master_keys);
    println!(
        "bip32_extended_public_key!: {:#?}",
        bip32_extended_public_key
    );
    println!(
        "bip32_extended_private_key: {:#?}",
        bip32_extended_private_key
    );
    // let found_child = get_child_key_from_derivation_path("m/0".to_string(), master_keys.clone());

    // let found_child_xpub = serialize_key(SerializeKeyArgs {
    //     key: found_child.public_key_hex.clone(),
    //     parent_public_key: Some(master_keys.public_key_hex.clone()),
    //     child_chain_code: found_child.chain_code_hex.clone(),
    //     is_public: true,
    //     is_testnet: IS_TESTNET,
    //     depth: Some(0),
    //     child_index: 0 as u32,
    // });
    // let found_child_xprv = serialize_key(SerializeKeyArgs {
    //     key: found_child.private_key_hex.clone(),
    //     parent_public_key: Some(master_keys.public_key_hex.clone()),
    //     child_chain_code: found_child.chain_code_hex.clone(),
    //     is_public: false,
    //     is_testnet: IS_TESTNET,
    //     depth: Some(0),
    //     child_index: 0 as u32,
    // });
    // println!("found child!: {:#?}", found_child);
    // println!("found child xpub!: {:#?}", found_child_xpub);
    // println!("found child xprv!: {:#?}", found_child_xprv);
    // println!("found child address!: {:#?}", found_child.get_address());
    // println!("found child wif!: {:#?}", found_child.get_wif());

    let found_children = get_child_keys_from_derivation_path(&derivation_path, master_keys, 5);
    for (key, value) in found_children {
        println!(
            "{}/{}   {}     {}          {}",
            &derivation_path,
            key,
            value.get_address(),
            value.public_key_hex,
            value.get_wif()
        )
    }

    //TODO ITEM: Generate a bech32 address from a private key/wif
    //Can check work here: https://secretscan.org/Bech32
}
