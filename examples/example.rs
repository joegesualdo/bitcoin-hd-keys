use bitcoin_hd_keys::{
    concat_u8, convert_decimal_to_32_byte_hex_with, convert_decimal_to_8_byte_hex_with,
    convert_wif_to_private_key, decode_hex, encode_hex, get_256_bits_of_entropy,
    get_bip38_512_bit_private_key, get_child_index_from_derivation_path,
    get_child_key_from_derivation_path, get_children_keys_from_derivation_path,
    get_extended_keys_from_derivation_path, get_master_keys_from_seed, get_mnemonic_words,
    serialize_key, DerivationChild, Keys, SerializeKeyArgs, IS_TESTNET,
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
    let bip39_seed = "887d2455533e126c9a74fc4e97d085eb77a8491d30f4434022fbc588afe4f0fdbb1b91876e7d3dff6bbe6f8249b0921f1c160006068472bc6e8fd3575599bd13".to_string();
    let passphrase = "".to_string();
    // let bip39_seed = get_bip38_512_bit_private_key(mnemonic_words, Some(passphrase));
    println!("BIP39 SEED: {}", bip39_seed);
    //

    // ==========MASTER KEYS===============================
    let master_keys = get_master_keys_from_seed(bip39_seed);
    // let master_keys = Keys {
    //     private_key_hex: "10f87383075f7586e0c45db3ecdac1da80318a4396d0aff5e8783b44e8ee5b83"
    //         .to_string(),
    //     public_key_hex: "03bebe8ff475155d2c422152670122b497c6ee8a6f8779b3bc035e2bb9be8ed2b1"
    //         .to_string(),
    //     chain_code_hex: "214dfe135937869841aabd6a79cef822337f1bab4086b0f22414b631b8e4feb3"
    //         .to_string(),
    //     is_hardened: false,
    // };
    let master_xprv = serialize_key(SerializeKeyArgs {
        child_keys: master_keys.clone(),
        parent_public_key: None,
        is_public: false,
        is_testnet: IS_TESTNET,
        depth: Some(0),
        child_index: 0,
        // Note: always false for master key
    });
    println!("MASTER KEYS: {:#?}", master_keys);
    println!("MASTER WIF: {}", master_keys.get_wif());
    println!("BIP39 Root Key: {}", master_xprv);
    println!("MASTER ADDRESS: {}", master_keys.get_address(),);
    // ======================================================

    let derivation_path = "m/0'/0'".to_string();

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
    //
    //
    //
    //

    let should_be_hardened = true;
    let found_children = get_children_keys_from_derivation_path(
        &derivation_path,
        master_keys,
        5,
        should_be_hardened,
    );
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
    println!(
        "wiftopriv: {}",
        convert_wif_to_private_key(
            &"cN9gykJNCNUdDqXqrW9Q1LJtesFLAH2McsLdKFDBcr2RMkzfaEF3".to_string() // &"cP6RMY8sjgdh7sm3KFJDE3sfEyXfXgw6bBtek7sSuCBnfFFW9Dzq".to_string()
                                                                                //&"cNEi19r8oRHFXm8HZjrvUUVR8A6AVoWq28HqHuKSJx8f2RH83qDj".to_string()
        )
    )

    //TODO ITEM: Generate a bech32 address from a private key/wif
    //Can check work here: https://secretscan.org/Bech32
}
