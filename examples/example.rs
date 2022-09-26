use std::collections::HashMap;

use bitcoin_hd_keys::{
    create_fingerprint, generate_bip32_hd_wallet_from_mnemonic_words,
    generate_bip44_hd_wallet_from_mnemonic_words, generate_bip49_hd_wallet_from_mnemonic_words,
    generate_bip84_hd_wallet_from_mnemonic_words, get_128_bits_of_entropy,
    get_address_from_pub_key, get_address_from_pub_key_hash, get_mnemonic_words,
    get_p2sh_address_from_script_hash, get_pubkey_hash_from_bech32_address,
    get_public_key_hash_from_address, get_public_key_hash_from_non_bech_32_address,
    get_script_hash_from_p2sh_address, get_wif_from_private_key, hash160_for_hex, AddressType,
    Network,
};

const NETWORK: Network = Network::Mainnet;
const ADDRESS_TYPE: AddressType = AddressType::Bech32;

fn main() {
    let entropy_array = get_128_bits_of_entropy();

    let mnemonic_words = get_mnemonic_words(entropy_array.to_vec());

    // let bip32_hd_wallet = generate_bip32_hd_wallet_from_mnemonic_words(
    //     mnemonic_words.clone(),
    //     None,
    //     "m/0'/0'".to_string(),
    //     5,
    //     true,
    //     Network::Testnet,
    // );
    // // println!("{:#?}", bip32_hd_wallet);
    // // bip32_hd_wallet.pretty_print_derived_addressed(NETWORK, ADDRESS_TYPE);

    // let bip44_hd_wallet = generate_bip44_hd_wallet_from_mnemonic_words(
    //     mnemonic_words.clone(),
    //     None,
    //     0,
    //     5,
    //     true,
    //     Network::Testnet,
    // );
    // // println!("{:#?}", bip44_hd_wallet);
    // // bip44_hd_wallet.pretty_print_derived_addressed(NETWORK, ADDRESS_TYPE);
    // let bip49_hd_wallet = generate_bip49_hd_wallet_from_mnemonic_words(
    //     mnemonic_words.clone(),
    //     None,
    //     0,
    //     5,
    //     true,
    //     Network::Testnet,
    // );
    // // println!("{:#?}", bip49_hd_wallet);
    // // bip49_hd_wallet.pretty_print_derived_addressed(NETWORK, ADDRESS_TYPE);
    // let bip84_hd_wallet = generate_bip84_hd_wallet_from_mnemonic_words(
    //     mnemonic_words.clone(),
    //     None,
    //     0,
    //     5,
    //     true,
    //     Network::Testnet,
    // );
    // println!("{:#?}", bip84_hd_wallet);
    // bip84_hd_wallet.pretty_print_derived_addressed(NETWORK, ADDRESS_TYPE);
    //
    // FOR SPARROW
    let sparrow_p2kh_wallet_mnemonic_words = vec![
        "version".to_string(),
        "puzzle".to_string(),
        "forget".to_string(),
        "parade".to_string(),
        "twelve".to_string(),
        "barely".to_string(),
        "involve".to_string(),
        "theme".to_string(),
        "radio".to_string(),
        "muffin".to_string(),
        "around".to_string(),
        "easily".to_string(),
    ];

    let sparrow_bip44_hd_wallet = generate_bip44_hd_wallet_from_mnemonic_words(
        sparrow_p2kh_wallet_mnemonic_words,
        None,
        1,
        0,
        50,
        false,
        Network::Testnet,
    );
    println!("{:#?}", sparrow_bip44_hd_wallet);
    sparrow_bip44_hd_wallet.pretty_print_derived_addressed(Network::Testnet);

    let sparrow_p2sh_wallet_mnemonic_words = vec![
        "spy".to_string(),
        "walnut".to_string(),
        "later".to_string(),
        "daring".to_string(),
        "neglect".to_string(),
        "aspect".to_string(),
        "devote".to_string(),
        "quote".to_string(),
        "entry".to_string(),
        "maze".to_string(),
        "fall".to_string(),
        "liberty".to_string(),
    ];
    let sparrow_bip49_hd_wallet = generate_bip49_hd_wallet_from_mnemonic_words(
        sparrow_p2sh_wallet_mnemonic_words,
        None,
        1,
        0,
        10,
        false,
        Network::Testnet,
    );
    println!("{:#?}", sparrow_bip49_hd_wallet);
    sparrow_bip49_hd_wallet.pretty_print_derived_addressed(Network::Testnet);

    let sparrow_p2wpkh_wallet_mnemonic_words = vec![
        "undo".to_string(),
        "original".to_string(),
        "bitter".to_string(),
        "skin".to_string(),
        "nature".to_string(),
        "multiply".to_string(),
        "hundred".to_string(),
        "oyster".to_string(),
        "piece".to_string(),
        "inflict".to_string(),
        "era".to_string(),
        "dwarf".to_string(),
    ];
    let sparrow_bip84_hd_wallet = generate_bip84_hd_wallet_from_mnemonic_words(
        sparrow_p2wpkh_wallet_mnemonic_words,
        None,
        1,
        0,
        5,
        false,
        Network::Testnet,
    );
    println!("{:#?}", sparrow_bip84_hd_wallet);
    sparrow_bip84_hd_wallet.pretty_print_derived_addressed(Network::Testnet);

    let sparrow_taproot_wallet_mnemonic_words = vec![
        "expose".to_string(),
        "fetch".to_string(),
        "define".to_string(),
        "fossil".to_string(),
        "cool".to_string(),
        "gentle".to_string(),
        "liberty".to_string(),
        "dog".to_string(),
        "tone".to_string(),
        "angle".to_string(),
        "pulp".to_string(),
        "garage".to_string(),
    ];
    // let sparrow_bip84_hd_wallet = generate_bip84_hd_wallet_from_mnemonic_words(
    //     sparrow_p2wpkh_wallet_mnemonic_words,
    //     None,
    //     1,
    //     0,
    //     5,
    //     false,
    //     Network::Testnet,
    // );
    // println!("{:#?}", sparrow_bip84_hd_wallet);
    // sparrow_bip84_hd_wallet.pretty_print_derived_addressed(Network::Testnet);
    // let fp = create_fingerprint(
    //     "0290a2e96ae8e35adfe1a465fcd2145a83b864893c53051101b759014e558c9f41".to_string(),
    // );
    // println!("fp: {}", fp);
    //
    //
    // println!(
    //     "{}",
    //     hash160(&"615e57fbd17a5dc62c08a782d99b948887c01e18".to_string())
    // );

    // println!(
    //     "{}",
    //     hash160(&sha256(&"30440220462e3c6c2a20a9c1587fa3207a3b4bd0cc12aceb8aae042c1649361fd197663902200877a8f0ee8ebfd7e3720d7c36e3298f0fdd8c48df66576b1cea786a99f9fab201210213fd52323c795f295fbe61254080ac4f973d27d2622f3e89b3fc53a58d528200".to_string())),
    // );
    // println!(
    //     "{}",
    //     hash160(&"30440220462e3c6c2a20a9c1587fa3207a3b4bd0cc12aceb8aae042c1649361fd197663902200877a8f0ee8ebfd7e3720d7c36e3298f0fdd8c48df66576b1cea786a99f9fab2010213fd52323c795f295fbe61254080ac4f973d27d2622f3e89b3fc53a58d528200".to_string())
    // );
    // println!(
    //     "{}",
    //     &get_p2sh_address_from_script_hash(
    //         &get_script_hash_from_p2sh_address("2MuvJWP5uKxXLgUyTaTxjzSbDY6sR3H9jME"),
    //         Network::Testnet
    //     )
    // );
    //println!(
    //    "{}",
    //    hash160_for_non_hex(&"0014615e57fbd17a5dc62c08a782d99b948887c01e18".to_string())
    //);
    println!("");
    println!(
        "{}",
        hash160_for_hex(&"0014615e57fbd17a5dc62c08a782d99b948887c01e18".to_string())
    );
}
