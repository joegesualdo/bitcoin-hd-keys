use std::collections::HashMap;

use bitcoin_hd_keys::{
    get_256_bits_of_entropy, get_bip32_extended_keys_from_derivation_path,
    get_bip32_root_key_from_seed, get_bip38_512_bit_private_key,
    get_derived_addresses_for_derivation_path, get_master_keys_from_seed, get_mnemonic_words, Keys,
    Network,
};

const NETWORK: Network = Network::Testnet;

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
    // let bip39_seed = "c4f5d3f03269fe18101b4ba87810e07bdf63a67660c1467ff146836cd6772e092a9a10d6f6d65212085a0443b18d833721c7cb64bddef54c555ef2fdb48101a6".to_string();
    let passphrase = "".to_string();
    let bip39_seed = get_bip38_512_bit_private_key(mnemonic_words, Some(passphrase));
    println!("BIP39 SEED: {}", bip39_seed);
    //

    // ==========MASTER KEYS===============================
    let master_keys = get_master_keys_from_seed(&bip39_seed);
    println!("MASTER KEYS: {:#?}", &master_keys);
    println!("MASTER WIF: {}", &master_keys.get_wif(NETWORK));
    println!("MASTER ADDRESS: {}", master_keys.get_address(NETWORK),);

    // let master_keys = Keys {
    //     private_key_hex: "10f87383075f7586e0c45db3ecdac1da80318a4396d0aff5e8783b44e8ee5b83"
    //         .to_string(),
    //     public_key_hex: "03bebe8ff475155d2c422152670122b497c6ee8a6f8779b3bc035e2bb9be8ed2b1"
    //         .to_string(),
    //     chain_code_hex: "214dfe135937869841aabd6a79cef822337f1bab4086b0f22414b631b8e4feb3"
    //         .to_string(),
    //     is_hardened: false,
    // };
    let bip32_root_key = get_bip32_root_key_from_seed(&bip39_seed, NETWORK);
    println!("BIP39 Root Key: {}", bip32_root_key);
    // ======================================================
    //

    let derivation_path = "m/0'/0'".to_string();

    let bip32_extended_keys = get_bip32_extended_keys_from_derivation_path(
        &derivation_path,
        &Keys::Master(master_keys.clone()),
        NETWORK,
    );
    println!(
        "bip32_extended_public_key!: {:#?}",
        bip32_extended_keys.xpub
    );
    println!(
        "bip32_extended_private_key: {:#?}",
        bip32_extended_keys.xpriv
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

    let found_children =
        get_derived_addresses_for_derivation_path(&derivation_path, master_keys, 5, true);

    for (key, value) in found_children {
        let public_key_hex = match &value {
            Keys::NonMaster(non_master_keys) => non_master_keys.public_key_hex.clone(),
            Keys::Master(master_keys) => master_keys.public_key_hex.clone(),
        };
        println!(
            "{}/{}   {}     {}          {}",
            &derivation_path,
            key,
            value.get_address(NETWORK),
            public_key_hex,
            value.get_wif(NETWORK)
        )
    }
    //TODO ITEM: Generate a bech32 address from a private key/wif
    //Can check work here: https://secretscan.org/Bech32
}
