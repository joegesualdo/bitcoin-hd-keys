use std::collections::HashMap;

use bitcoin_hd_keys::{
    generate_bip32_hd_wallet_from_mnemonic_words, generate_bip44_hd_wallet_from_mnemonic_words,
    generate_bip49_hd_wallet_from_mnemonic_words, generate_bip84_hd_wallet_from_mnemonic_words,
    get_128_bits_of_entropy, get_mnemonic_words, AddressType, Network,
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
        5,
        false,
        Network::Testnet,
    );
    println!("{:#?}", sparrow_bip44_hd_wallet);
    sparrow_bip44_hd_wallet.pretty_print_derived_addressed(Network::Testnet, AddressType::P2PKH);

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
        5,
        false,
        Network::Testnet,
    );
    println!("{:#?}", sparrow_bip49_hd_wallet);
    sparrow_bip49_hd_wallet.pretty_print_derived_addressed(Network::Testnet, AddressType::P2SH);

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
    sparrow_bip84_hd_wallet.pretty_print_derived_addressed(Network::Testnet, AddressType::Bech32);
}
