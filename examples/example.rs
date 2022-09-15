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

    let bip32_hd_wallet = generate_bip32_hd_wallet_from_mnemonic_words(
        mnemonic_words.clone(),
        None,
        "m/0'/0'".to_string(),
        5,
        true,
        Network::Testnet,
    );
    // println!("{:#?}", bip32_hd_wallet);
    // bip32_hd_wallet.pretty_print_derived_addressed(NETWORK, ADDRESS_TYPE);

    let bip44_hd_wallet = generate_bip44_hd_wallet_from_mnemonic_words(
        mnemonic_words.clone(),
        None,
        0,
        5,
        true,
        Network::Testnet,
    );
    // println!("{:#?}", bip44_hd_wallet);
    // bip44_hd_wallet.pretty_print_derived_addressed(NETWORK, ADDRESS_TYPE);
    let bip49_hd_wallet = generate_bip49_hd_wallet_from_mnemonic_words(
        mnemonic_words.clone(),
        None,
        0,
        5,
        true,
        Network::Testnet,
    );
    // println!("{:#?}", bip49_hd_wallet);
    // bip49_hd_wallet.pretty_print_derived_addressed(NETWORK, ADDRESS_TYPE);
    let bip84_hd_wallet = generate_bip84_hd_wallet_from_mnemonic_words(
        mnemonic_words.clone(),
        None,
        0,
        5,
        true,
        Network::Testnet,
    );
    println!("{:#?}", bip84_hd_wallet);
    bip84_hd_wallet.pretty_print_derived_addressed(NETWORK, ADDRESS_TYPE);
}
