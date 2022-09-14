use std::collections::HashMap;

use bitcoin_hd_keys::{
    convert_wif_to_private_key, get_128_bits_of_entropy, get_256_bits_of_entropy,
    get_bip32_extended_keys_from_derivation_path, get_bip32_root_key_from_master_keys,
    get_bip32_root_key_from_seed, get_bip38_512_bit_private_key,
    get_derived_addresses_for_derivation_path, get_master_keys_from_seed, get_mnemonic_words,
    AddressType, Keys, MasterKeys, Network,
};

const NETWORK: Network = Network::Testnet;
const ADDRESS_TYPE: AddressType = AddressType::P2SH;

fn main() {
    // 1) Use some cryptographically secure entropy generator to generate 128 bits of entropy.
    // Create array of length 32 and fill with a random u8;
    let entropy_array = get_128_bits_of_entropy();

    // let mnemonic_words = get_mnemonic_words(entropy_array.to_vec());
    let mnemonic_words = vec![
        "couch".to_string(),
        "wink".to_string(),
        "dizzy".to_string(),
        "net".to_string(),
        "prison".to_string(),
        "smile".to_string(),
        "total".to_string(),
        "zone".to_string(),
        "orphan".to_string(),
        "snake".to_string(),
        "utility".to_string(),
        "nerve".to_string(),
    ];
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
    println!(
        "MASTER ADDRESS: {}",
        master_keys.get_address(NETWORK, ADDRESS_TYPE),
    );

    let bip32_root_key = get_bip32_root_key_from_seed(&bip39_seed, NETWORK);
    println!("BIP39 Root Key: {}", bip32_root_key);
    // DELETE -------------------------------------------------
    // TODO: GET MASTER KEYS FROM XPRIV (BIP32 ROOT KEY)
    let master_keys = MasterKeys {
        private_key_hex: convert_wif_to_private_key(
            &"cPjsEWRVjtUDK42ZePL1t2ZWmhS4FtL4G8C4epwVRiowUmxZ9itH".to_string(),
        ),
        public_key_hex: "0294683e00fa1e00b978260ac9bb3e9ece9b3dc8019d4162e75b6e0bb0dd30924a"
            .to_string(),
        chain_code_hex: "a1db5ad297c2802d2cdde23e49b617517343adc895678863e4912bd6226b9636"
            .to_string(),
    };
    let bip32_root_key = get_bip32_root_key_from_master_keys(&master_keys, NETWORK);
    println!("BIP39 Root Key: {}", bip32_root_key);
    // -------------------------------------------------

    // ======================================================

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

    let should_harden = true;
    let found_children =
        get_derived_addresses_for_derivation_path(&derivation_path, master_keys, 5, should_harden);

    for (key, value) in found_children {
        let public_key_hex = match &value {
            Keys::NonMaster(non_master_keys) => non_master_keys.public_key_hex.clone(),
            Keys::Master(master_keys) => master_keys.public_key_hex.clone(),
        };
        println!(
            "{}/{}   {}     {}          {}",
            &derivation_path,
            key,
            value.get_address(NETWORK, ADDRESS_TYPE),
            public_key_hex,
            value.get_wif(NETWORK)
        )
    }
    //TODO ITEM: Generate a bech32 address from a private key/wif
    //Can check work here: https://secretscan.org/Bech32
}
