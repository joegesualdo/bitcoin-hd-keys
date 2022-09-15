use std::collections::HashMap;

use bitcoin_hd_keys::{
    convert_wif_to_private_key, decode_serialized_extended_key, get_128_bits_of_entropy,
    get_256_bits_of_entropy, get_bip32_extended_keys_from_derivation_path,
    get_bip32_root_key_from_master_keys, get_bip32_root_key_from_seed,
    get_bip38_512_bit_private_key, get_derived_addresses_for_derivation_path,
    get_master_keys_from_bip32_root_key, get_master_keys_from_seed,
    get_master_keys_from_serialized_extended_private_master_key, get_mnemonic_sentence,
    get_mnemonic_words, AddressType, Bip, DecodedExtendedKeySerialized, Keys, MasterKeys, Network,
};

const NETWORK: Network = Network::Mainnet;
const ADDRESS_TYPE: AddressType = AddressType::Bech32;

fn main() {
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

    fn get_bip32_derived_addresses(
        bip32_derivation_path: &String,
        master_keys: MasterKeys,
        children_count: i32,
        should_harden: bool,
    ) -> HashMap<String, Keys> {
        // Notice: multiple wallets use different derivation paths. Source: https://iancoleman.io/bip39/
        // - Bitcoincore
        // - Blockchain.info
        // - Multibit
        // - Coinmomi
        // // Todo: Maybe we should have presets for different vendors?
        let found_children = get_derived_addresses_for_derivation_path(
            &bip32_derivation_path,
            master_keys,
            children_count,
            should_harden,
        );
        found_children
    }

    fn get_derived_addresses_from_5_levels(
        purpose: u8,
        cointype: u8,
        account: i32,
        should_include_change_addresses: bool,
        master_keys: &MasterKeys,
        children_count: i32,
        should_harden: bool,
    ) -> HashMap<String, Keys> {
        let bip44_derivation_path_for_external_chain =
            format!("m/{}'/{}'/{}'/0", purpose, cointype, account.to_string()).to_string(); // Must use with P2PKH

        // internal chain is also known as a change address
        let bip44_derivation_path_for_internal_chain =
            format!("m/{}'/{}'/{}'/1", purpose, cointype, account.to_string()).to_string(); // Must use with P2PKH

        // Notice: multiple wallets use different derivation paths. Source: https://iancoleman.io/bip39/
        // - Bitcoincore
        // - Blockchain.info
        // - Multibit
        // - Coinmomi
        // // Todo: Maybe we should have presets for different vendors?
        let found_children_for_external_chain = get_derived_addresses_for_derivation_path(
            &bip44_derivation_path_for_external_chain,
            master_keys.clone(),
            children_count,
            should_harden,
        );
        println!("{:#?}", found_children_for_external_chain);

        let mut found_childrenn = found_children_for_external_chain.clone();
        if should_include_change_addresses {
            let found_children_for_internal_chain = get_derived_addresses_for_derivation_path(
                &bip44_derivation_path_for_internal_chain,
                master_keys.clone(),
                children_count,
                should_harden,
            );
            for (key, value) in found_children_for_internal_chain {
                found_childrenn.insert(key, value);
            }
        }
        found_childrenn
    }

    // TODO: Create a function to get the Account Extended private/public keys and the bip32 extended
    // private/public keys. See BIP44 section of: https://iancoleman.io/bip39/
    fn get_bip44_derived_addresses(
        account: i32,
        should_include_change_addresses: bool,
        master_keys: &MasterKeys,
        children_count: i32,
        should_harden: bool,
    ) -> HashMap<String, Keys> {
        // Source: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
        // External chain is used for addresses that are meant to be visible outside of the wallet (e.g. for receiving payments). Internal chain is used for addresses which are not meant to be visible outside of the wallet and is used for return transaction change.
        // internal chain is also known as a change address
        let purpose = 44;
        let cointype = 0;
        get_derived_addresses_from_5_levels(
            purpose,
            cointype,
            account,
            should_include_change_addresses,
            master_keys,
            children_count,
            should_harden,
        )
    }
    // TODO: Create a function to get the Account Extended private/public keys and the bip32 extended
    // private/public keys. See BIP49 section of: https://iancoleman.io/bip39/
    fn get_bip49_derived_addresses(
        account: i32,
        should_include_change_addresses: bool,
        master_keys: &MasterKeys,
        children_count: i32,
        should_harden: bool,
    ) -> HashMap<String, Keys> {
        // Source: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
        // External chain is used for addresses that are meant to be visible outside of the wallet (e.g. for receiving payments). Internal chain is used for addresses which are not meant to be visible outside of the wallet and is used for return transaction change.
        // internal chain is also known as a change address
        let purpose = 49;
        let cointype = 0;
        get_derived_addresses_from_5_levels(
            purpose,
            cointype,
            account,
            should_include_change_addresses,
            master_keys,
            children_count,
            should_harden,
        )
    }
    // TODO: Create a function to get the Account Extended private/public keys and the bip32 extended
    // private/public keys. See BIP49 section of: https://iancoleman.io/bip39/
    fn get_bip84_derived_addresses(
        account: i32,
        should_include_change_addresses: bool,
        master_keys: &MasterKeys,
        children_count: i32,
        should_harden: bool,
    ) -> HashMap<String, Keys> {
        // Source: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
        // External chain is used for addresses that are meant to be visible outside of the wallet (e.g. for receiving payments). Internal chain is used for addresses which are not meant to be visible outside of the wallet and is used for return transaction change.
        // internal chain is also known as a change address
        let purpose = 84;
        let cointype = 0;
        get_derived_addresses_from_5_levels(
            purpose,
            cointype,
            account,
            should_include_change_addresses,
            master_keys,
            children_count,
            should_harden,
        )
    }

    #[derive(Debug)]
    struct Bip44DerivationPathInfo {
        account_extended_private_key: String,
        account_extended_public_key: String,
    }
    fn get_bip44_derivation_path_info(
        account: i32,
        master_keys: &MasterKeys,
        network: Network,
    ) -> Bip44DerivationPathInfo {
        let purpose = 44;
        let cointype = 0;
        let account_derivation_path = format!("m/{}'/{}'/{}'", purpose, cointype, account);
        let bip32_extended_keys_for_account = get_bip32_extended_keys_from_derivation_path(
            &account_derivation_path.to_string(),
            &Keys::Master(master_keys.clone()),
            network,
            Bip::Bip44,
        );

        Bip44DerivationPathInfo {
            account_extended_private_key: bip32_extended_keys_for_account.xpriv,
            account_extended_public_key: bip32_extended_keys_for_account.xpub,
        }
    }
    #[derive(Debug)]
    struct Bip49DerivationPathInfo {
        account_extended_private_key: String,
        account_extended_public_key: String,
    }
    fn get_bip49_derivation_path_info(
        account: i32,
        master_keys: &MasterKeys,
        network: Network,
    ) -> Bip49DerivationPathInfo {
        let purpose = 49;
        let cointype = 0;
        let account_derivation_path = format!("m/{}'/{}'/{}'", purpose, cointype, account);
        let bip32_extended_keys_for_account = get_bip32_extended_keys_from_derivation_path(
            &account_derivation_path.to_string(),
            &Keys::Master(master_keys.clone()),
            network,
            Bip::Bip49,
        );

        Bip49DerivationPathInfo {
            account_extended_private_key: bip32_extended_keys_for_account.xpriv,
            account_extended_public_key: bip32_extended_keys_for_account.xpub,
        }
    }
    #[derive(Debug)]
    struct Bip84DerivationPathInfo {
        account_extended_private_key: String,
        account_extended_public_key: String,
    }
    fn get_bip84_derivation_path_info(
        account: i32,
        master_keys: &MasterKeys,
        network: Network,
    ) -> Bip84DerivationPathInfo {
        let purpose = 84;
        let cointype = 0;
        let account_derivation_path = format!("m/{}'/{}'/{}'", purpose, cointype, account);
        let bip32_extended_keys_for_account = get_bip32_extended_keys_from_derivation_path(
            &account_derivation_path.to_string(),
            &Keys::Master(master_keys.clone()),
            network,
            Bip::Bip84,
        );

        Bip84DerivationPathInfo {
            account_extended_private_key: bip32_extended_keys_for_account.xpriv,
            account_extended_public_key: bip32_extended_keys_for_account.xpub,
        }
    }

    let should_harden = true;
    let children_count = 5;
    let account = 0;
    let should_include_change_addresses = true;
    // let found_children = get_bip32_derived_addresses(&derivation_path, master_keys, children_count, should_harden)
    // let found_children = get_bip44_derived_addresses(
    //     account,
    //     should_include_change_addresses,
    //     &master_keys,
    //     children_count,
    //     should_harden,
    // );
    // let bip44_derivation_path_info = get_bip44_derivation_path_info(account, &master_keys.clone(), NETWORK);
    // let found_children = get_bip49_derived_addresses(
    //     account,
    //     should_include_change_addresses,
    //     &master_keys,
    //     children_count,
    //     should_harden,
    // );
    // let bip49_derivation_path_info = get_bip49_derivation_path_info(account, &master_keys.clone(), NETWORK);
    // println!("{:#?}", bip49_derivation_path_info);
    // let bip32_extended_keys = get_bip32_extended_keys_from_derivation_path(
    //     &"m/44'/0'/0'/0".to_string(),
    //     &Keys::Master(master_keys.clone()),
    //     NETWORK,
    // );
    // let xpriv = &bip32_extended_keys.xpriv;
    // let xpub = &bip32_extended_keys.xpub;
    // println!("{:#?}", bip32_extended_keys);
    // let found_children = get_bip49_derived_addresses(1, false, master_keys, children_count, should_harden);

    #[derive(Debug)]
    struct HDWalletBip32 {
        network: Network,
        bip39_seed: String,
        bip32_root_key: String,
        bip32_derivation_path: String,
        bip32_extended_private_key: String,
        bip32_extended_public_key: String,
        derived_addresses: HashMap<String, Keys>,
    }
    impl HDWalletBip32 {
        fn pretty_print_derived_addressed(
            &self,
            network: Network,
            address_type: AddressType,
        ) -> () {
            for (key, value) in self.derived_addresses.clone() {
                let should_compress = true;
                let public_key_hex = match &value {
                    Keys::NonMaster(non_master_keys) => non_master_keys.public_key_hex.clone(),
                    Keys::Master(master_keys) => master_keys.public_key_hex.clone(),
                };
                println!(
                    "{} {}     {}          {}",
                    key,
                    value.get_address(network, address_type),
                    public_key_hex,
                    value.get_wif(network, should_compress)
                )
            }
        }
    }
    // 1) Use some cryptographically secure entropy generator to generate 128 bits of entropy.
    // Create array of length 32 and fill with a random u8;
    // let mnemonic_words = vec![
    //     "couch".to_string(),
    //     "wink".to_string(),
    //     "dizzy".to_string(),
    //     "net".to_string(),
    //     "prison".to_string(),
    //     "smile".to_string(),
    //     "total".to_string(),
    //     "zone".to_string(),
    //     "orphan".to_string(),
    //     "snake".to_string(),
    //     "utility".to_string(),
    //     "nerve".to_string(),
    // ];

    fn generate_bip32_hd_wallet_from_mnemonic_words(
        mnemonic_words: Vec<String>,
        password: Option<String>,
        derivation_path: String,
        children_count: i32,
        should_harden: bool,
        network: Network,
    ) -> HDWalletBip32 {
        let bip = Bip::Bip32;
        let should_compress_wif = true;
        // println!("MNEMONIC WORDS: {:?}", mnemonic_words);

        let mnemonic_sentence = get_mnemonic_sentence(&mnemonic_words);

        println!("MNEMONIC SENTENCE: {}", mnemonic_sentence);

        // HARDCODED FOR TESTING
        // let bip39_seed = "67f93560761e20617de26e0cb84f7234aaf373ed2e66295c3d7397e6d7ebe882ea396d5d293808b0defd7edd2babd4c091ad942e6a9351e6d075a29d4df872af".to_string();
        // let bip39_seed = "c4f5d3f03269fe18101b4ba87810e07bdf63a67660c1467ff146836cd6772e092a9a10d6f6d65212085a0443b18d833721c7cb64bddef54c555ef2fdb48101a6".to_string();
        let passphrase = "".to_string();
        let bip39_seed = get_bip38_512_bit_private_key(mnemonic_words, Some(passphrase));
        println!("BIP39 SEED: {}", bip39_seed);
        //
        let bip32_root_key = get_bip32_root_key_from_seed(&bip39_seed, NETWORK, bip);
        println!("BIP39 Root Key: {}", bip32_root_key);

        // ==========MASTER KEYS===============================
        // TWO WAYS TO GET MASTER KEYS:
        // 1) from bip39 seed
        let master_keys = get_master_keys_from_seed(&bip39_seed);
        // 2) from xpriv (root key)
        let master_keys =
            get_master_keys_from_serialized_extended_private_master_key(&bip32_root_key);
        // or use the wrapper
        let master_keys = get_master_keys_from_bip32_root_key(&bip32_root_key);
        //
        // println!("MASTER KEYS: {:#?}", &master_keys);
        // println!(
        //     "MASTER WIF: {}",
        //     &master_keys.get_wif(NETWORK, should_compress_wif)
        // );
        // println!(
        //     "MASTER ADDRESS: {}",
        //     master_keys.get_address(NETWORK, ADDRESS_TYPE),
        // );

        // println!("WIF: {}", master_keys.get_wif(NETWORK, should_compress_wif));
        let bip32_root_key = get_bip32_root_key_from_master_keys(&master_keys, NETWORK, bip);
        println!("BIP39 Root Key: {}", bip32_root_key);
        // -------------------------------------------------

        // ======================================================

        // let bip32_derivation_path = "m/0'/0'".to_string(); // Must use with P2PKH
        // let bip44_derivation_path = "m/44'/0'/0'/0".to_string(); // Must use with P2PKH
        // let bip49_derivation_path = "m/49'/0'/0'/0".to_string(); // Must use with P2SH
        // let bip84_derivation_path = "m/84'/0'/0'/0".to_string(); // Must use with Bech32
        // let bip141_derivation_path = "m/0".to_string(); // Must use with P2SH
        // let derivation_path = bip141_derivation_path;

        let bip32_extended_keys = get_bip32_extended_keys_from_derivation_path(
            &derivation_path,
            &Keys::Master(master_keys.clone()),
            NETWORK,
            bip,
        );
        let xpriv = &bip32_extended_keys.xpriv;
        let xpub = &bip32_extended_keys.xpub;

        // let decoded_serialized_extended_key = decode_serialized_extended_key(&xpriv);
        // println!("{:#?}", &decoded_serialized_extended_key);
        // println!(
        //     "bip32_extended_public_key!: {:#?}",
        //     bip32_extended_keys.xpub
        // );
        // println!(
        //     "bip32_extended_private_key: {:#?}",
        //     bip32_extended_keys.xpriv
        // );
        // let found_children = get_bip84_derived_addresses(1, false, &master_keys, children_count, should_harden);
        // let bip84_derivation_path_info = get_bip84_derivation_path_info(account, &master_keys.clone(), NETWORK);
        // println!("{:#?}", bip84_derivation_path_info);
        let found_children = get_bip32_derived_addresses(
            &derivation_path,
            master_keys,
            children_count,
            should_harden,
        );

        HDWalletBip32 {
            network: network,
            bip39_seed,
            bip32_root_key,
            bip32_derivation_path: derivation_path,
            bip32_extended_private_key: xpriv.to_string(),
            bip32_extended_public_key: xpub.to_string(),
            derived_addresses: found_children,
        }
    }
    #[derive(Debug)]
    struct HDWalletBip44 {
        network: Network,
        bip39_seed: String,
        bip32_root_key: String,
        purpose: i32,
        coin: i32,
        account: i32,
        // internal: bool,
        account_extended_private_key: String,
        account_extended_public_key: String,
        derivation_path_external: String,
        bip32_extended_private_key_for_external: String,
        bip32_extended_public_key_for_external: String,
        derivation_path_internal: String,
        bip32_extended_private_key_for_internal: String,
        bip32_extended_public_key_for_internal: String,
        derived_addresses: HashMap<String, Keys>,
    }
    impl HDWalletBip44 {
        fn pretty_print_derived_addressed(
            &self,
            network: Network,
            address_type: AddressType,
        ) -> () {
            for (key, value) in self.derived_addresses.clone() {
                let should_compress = true;
                let public_key_hex = match &value {
                    Keys::NonMaster(non_master_keys) => non_master_keys.public_key_hex.clone(),
                    Keys::Master(master_keys) => master_keys.public_key_hex.clone(),
                };
                println!(
                    "{} {}     {}          {}",
                    key,
                    value.get_address(network, address_type),
                    public_key_hex,
                    value.get_wif(network, should_compress)
                )
            }
        }
    }
    fn generate_bip44_hd_wallet_from_mnemonic_words(
        mnemonic_words: Vec<String>,
        password: Option<String>,
        account: i32,
        children_count: i32,
        should_harden: bool,
        network: Network,
    ) -> HDWalletBip44 {
        let bip = Bip::Bip44;
        let purpose = 44;
        let coin = 0;
        let should_compress_wif = true;
        // println!("MNEMONIC WORDS: {:?}", mnemonic_words);

        let mnemonic_sentence = get_mnemonic_sentence(&mnemonic_words);

        println!("MNEMONIC SENTENCE: {}", mnemonic_sentence);

        // HARDCODED FOR TESTING
        // let bip39_seed = "67f93560761e20617de26e0cb84f7234aaf373ed2e66295c3d7397e6d7ebe882ea396d5d293808b0defd7edd2babd4c091ad942e6a9351e6d075a29d4df872af".to_string();
        // let bip39_seed = "c4f5d3f03269fe18101b4ba87810e07bdf63a67660c1467ff146836cd6772e092a9a10d6f6d65212085a0443b18d833721c7cb64bddef54c555ef2fdb48101a6".to_string();
        let passphrase = "".to_string();
        let bip39_seed = get_bip38_512_bit_private_key(mnemonic_words, Some(passphrase));
        println!("BIP39 SEED: {}", bip39_seed);
        //
        let bip32_root_key = get_bip32_root_key_from_seed(&bip39_seed, NETWORK, bip);
        println!("BIP39 Root Key: {}", bip32_root_key);

        // ==========MASTER KEYS===============================
        // TWO WAYS TO GET MASTER KEYS:
        // 1) from bip39 seed
        let master_keys = get_master_keys_from_seed(&bip39_seed);
        // 2) from xpriv (root key)
        let master_keys =
            get_master_keys_from_serialized_extended_private_master_key(&bip32_root_key);
        // or use the wrapper
        let master_keys = get_master_keys_from_bip32_root_key(&bip32_root_key);
        //
        // println!("MASTER KEYS: {:#?}", &master_keys);
        // println!(
        //     "MASTER WIF: {}",
        //     &master_keys.get_wif(NETWORK, should_compress_wif)
        // );
        // println!(
        //     "MASTER ADDRESS: {}",
        //     master_keys.get_address(NETWORK, ADDRESS_TYPE),
        // );

        // println!("WIF: {}", master_keys.get_wif(NETWORK, should_compress_wif));
        let bip32_root_key = get_bip32_root_key_from_master_keys(&master_keys, NETWORK, bip);
        println!("BIP39 Root Key: {}", bip32_root_key);
        // -------------------------------------------------

        // ======================================================
        // Not Change
        let derivation_path_external = format!("m/{}'/{}'/{}'/0", purpose, coin, account);
        let bip32_extended_keys_for_external = get_bip32_extended_keys_from_derivation_path(
            &derivation_path_external,
            &Keys::Master(master_keys.clone()),
            NETWORK,
            bip,
        );
        let bip32_extended_private_key_for_external = bip32_extended_keys_for_external.xpriv;
        let bip32_extended_public_key_for_external = bip32_extended_keys_for_external.xpub;
        // Change
        let derivation_path_internal = format!("m/{}'/{}'/{}'/1", purpose, coin, account);
        let bip32_extended_keys_for_internal = get_bip32_extended_keys_from_derivation_path(
            &derivation_path_internal,
            &Keys::Master(master_keys.clone()),
            NETWORK,
            bip,
        );
        let bip32_extended_private_key_for_internal = bip32_extended_keys_for_internal.xpriv;
        let bip32_extended_public_key_for_internal = bip32_extended_keys_for_internal.xpub;

        // let bip32_derivation_path = "m/0'/0'".to_string(); // Must use with P2PKH
        // let bip44_derivation_path = "m/44'/0'/0'/0".to_string(); // Must use with P2PKH
        // let bip49_derivation_path = "m/49'/0'/0'/0".to_string(); // Must use with P2SH
        // let bip84_derivation_path = "m/84'/0'/0'/0".to_string(); // Must use with Bech32
        // let bip141_derivation_path = "m/0".to_string(); // Must use with P2SH
        // let derivation_path = bip141_derivation_path;

        // let xpriv = &bip32_extended_keys.xpriv;
        // let xpub = &bip32_extended_keys.xpub;

        // let decoded_serialized_extended_key = decode_serialized_extended_key(&xpriv);
        // println!("{:#?}", &decoded_serialized_extended_key);
        // println!(
        //     "bip32_extended_public_key!: {:#?}",
        //     bip32_extended_keys.xpub
        // );
        // println!(
        //     "bip32_extended_private_key: {:#?}",
        //     bip32_extended_keys.xpriv
        // );

        let should_include_change_addresses = true;
        let found_children = get_bip44_derived_addresses(
            account,
            should_include_change_addresses,
            &master_keys,
            children_count,
            should_harden,
        );
        let bip44_derivation_path_info =
            get_bip44_derivation_path_info(account, &master_keys.clone(), NETWORK);
        // println!("{:#?}", bip84_derivation_path_info);

        HDWalletBip44 {
            network,
            bip39_seed,
            bip32_root_key,
            purpose,
            coin,
            account,
            // internal: bool,
            account_extended_private_key: bip44_derivation_path_info.account_extended_private_key,
            account_extended_public_key: bip44_derivation_path_info.account_extended_public_key,
            derivation_path_external,
            bip32_extended_private_key_for_external,
            bip32_extended_public_key_for_external,
            derivation_path_internal,
            bip32_extended_private_key_for_internal,
            bip32_extended_public_key_for_internal,
            derived_addresses: found_children,
        }
    }
    #[derive(Debug)]
    struct HDWalletBip49 {
        network: Network,
        bip39_seed: String,
        bip32_root_key: String,
        purpose: i32,
        coin: i32,
        account: i32,
        // internal: bool,
        account_extended_private_key: String,
        account_extended_public_key: String,
        derivation_path_external: String,
        bip32_extended_private_key_for_external: String,
        bip32_extended_public_key_for_external: String,
        derivation_path_internal: String,
        bip32_extended_private_key_for_internal: String,
        bip32_extended_public_key_for_internal: String,
        derived_addresses: HashMap<String, Keys>,
    }
    impl HDWalletBip49 {
        fn pretty_print_derived_addressed(
            &self,
            network: Network,
            address_type: AddressType,
        ) -> () {
            for (key, value) in self.derived_addresses.clone() {
                let should_compress = true;
                let public_key_hex = match &value {
                    Keys::NonMaster(non_master_keys) => non_master_keys.public_key_hex.clone(),
                    Keys::Master(master_keys) => master_keys.public_key_hex.clone(),
                };
                println!(
                    "{} {}     {}          {}",
                    key,
                    value.get_address(network, address_type),
                    public_key_hex,
                    value.get_wif(network, should_compress)
                )
            }
        }
    }
    fn generate_bip49_hd_wallet_from_mnemonic_words(
        mnemonic_words: Vec<String>,
        password: Option<String>,
        account: i32,
        children_count: i32,
        should_harden: bool,
        network: Network,
    ) -> HDWalletBip49 {
        let bip = Bip::Bip49;
        let purpose = 49;
        let coin = 0;
        let should_compress_wif = true;
        // println!("MNEMONIC WORDS: {:?}", mnemonic_words);

        let mnemonic_sentence = get_mnemonic_sentence(&mnemonic_words);

        println!("MNEMONIC SENTENCE: {}", mnemonic_sentence);

        // HARDCODED FOR TESTING
        // let bip39_seed = "67f93560761e20617de26e0cb84f7234aaf373ed2e66295c3d7397e6d7ebe882ea396d5d293808b0defd7edd2babd4c091ad942e6a9351e6d075a29d4df872af".to_string();
        // let bip39_seed = "c4f5d3f03269fe18101b4ba87810e07bdf63a67660c1467ff146836cd6772e092a9a10d6f6d65212085a0443b18d833721c7cb64bddef54c555ef2fdb48101a6".to_string();
        let passphrase = "".to_string();
        let bip39_seed = get_bip38_512_bit_private_key(mnemonic_words, Some(passphrase));
        println!("BIP39 SEED: {}", bip39_seed);
        //
        let bip32_root_key = get_bip32_root_key_from_seed(&bip39_seed, NETWORK, bip);
        println!("BIP39 Root Key: {}", bip32_root_key);

        // ==========MASTER KEYS===============================
        // TWO WAYS TO GET MASTER KEYS:
        // 1) from bip39 seed
        let master_keys = get_master_keys_from_seed(&bip39_seed);
        // 2) from xpriv (root key)
        let master_keys =
            get_master_keys_from_serialized_extended_private_master_key(&bip32_root_key);
        // or use the wrapper
        let master_keys = get_master_keys_from_bip32_root_key(&bip32_root_key);
        //
        // println!("MASTER KEYS: {:#?}", &master_keys);
        // println!(
        //     "MASTER WIF: {}",
        //     &master_keys.get_wif(NETWORK, should_compress_wif)
        // );
        // println!(
        //     "MASTER ADDRESS: {}",
        //     master_keys.get_address(NETWORK, ADDRESS_TYPE),
        // );

        // println!("WIF: {}", master_keys.get_wif(NETWORK, should_compress_wif));
        let bip32_root_key = get_bip32_root_key_from_master_keys(&master_keys, NETWORK, bip);
        println!("BIP39 Root Key: {}", bip32_root_key);
        // -------------------------------------------------

        // ======================================================
        // Not Change
        let derivation_path_external = format!("m/{}'/{}'/{}'/0", purpose, coin, account);
        let bip32_extended_keys_for_external = get_bip32_extended_keys_from_derivation_path(
            &derivation_path_external,
            &Keys::Master(master_keys.clone()),
            NETWORK,
            bip,
        );
        let bip32_extended_private_key_for_external = bip32_extended_keys_for_external.xpriv;
        let bip32_extended_public_key_for_external = bip32_extended_keys_for_external.xpub;
        // Change
        let derivation_path_internal = format!("m/{}'/{}'/{}'/1", purpose, coin, account);
        let bip32_extended_keys_for_internal = get_bip32_extended_keys_from_derivation_path(
            &derivation_path_internal,
            &Keys::Master(master_keys.clone()),
            NETWORK,
            bip,
        );
        let bip32_extended_private_key_for_internal = bip32_extended_keys_for_internal.xpriv;
        let bip32_extended_public_key_for_internal = bip32_extended_keys_for_internal.xpub;

        // let bip32_derivation_path = "m/0'/0'".to_string(); // Must use with P2PKH
        // let bip44_derivation_path = "m/44'/0'/0'/0".to_string(); // Must use with P2PKH
        // let bip49_derivation_path = "m/49'/0'/0'/0".to_string(); // Must use with P2SH
        // let bip84_derivation_path = "m/84'/0'/0'/0".to_string(); // Must use with Bech32
        // let bip141_derivation_path = "m/0".to_string(); // Must use with P2SH
        // let derivation_path = bip141_derivation_path;

        // let xpriv = &bip32_extended_keys.xpriv;
        // let xpub = &bip32_extended_keys.xpub;

        // let decoded_serialized_extended_key = decode_serialized_extended_key(&xpriv);
        // println!("{:#?}", &decoded_serialized_extended_key);
        // println!(
        //     "bip32_extended_public_key!: {:#?}",
        //     bip32_extended_keys.xpub
        // );
        // println!(
        //     "bip32_extended_private_key: {:#?}",
        //     bip32_extended_keys.xpriv
        // );

        let should_include_change_addresses = true;
        let found_children = get_bip49_derived_addresses(
            account,
            should_include_change_addresses,
            &master_keys,
            children_count,
            should_harden,
        );
        let bip49_derivation_path_info =
            get_bip49_derivation_path_info(account, &master_keys.clone(), NETWORK);
        // println!("{:#?}", bip84_derivation_path_info);

        HDWalletBip49 {
            network,
            bip39_seed,
            bip32_root_key,
            purpose,
            coin,
            account,
            // internal: bool,
            account_extended_private_key: bip49_derivation_path_info.account_extended_private_key,
            account_extended_public_key: bip49_derivation_path_info.account_extended_public_key,
            derivation_path_external,
            bip32_extended_private_key_for_external,
            bip32_extended_public_key_for_external,
            derivation_path_internal,
            bip32_extended_private_key_for_internal,
            bip32_extended_public_key_for_internal,
            derived_addresses: found_children,
        }
    }
    #[derive(Debug)]
    struct HDWalletBip84 {
        network: Network,
        bip39_seed: String,
        bip32_root_key: String,
        purpose: i32,
        coin: i32,
        account: i32,
        // internal: bool,
        account_extended_private_key: String,
        account_extended_public_key: String,
        derivation_path_external: String,
        bip32_extended_private_key_for_external: String,
        bip32_extended_public_key_for_external: String,
        derivation_path_internal: String,
        bip32_extended_private_key_for_internal: String,
        bip32_extended_public_key_for_internal: String,
        derived_addresses: HashMap<String, Keys>,
    }
    impl HDWalletBip84 {
        fn pretty_print_derived_addressed(
            &self,
            network: Network,
            address_type: AddressType,
        ) -> () {
            for (key, value) in self.derived_addresses.clone() {
                let should_compress = true;
                let public_key_hex = match &value {
                    Keys::NonMaster(non_master_keys) => non_master_keys.public_key_hex.clone(),
                    Keys::Master(master_keys) => master_keys.public_key_hex.clone(),
                };
                println!(
                    "{} {}     {}          {}",
                    key,
                    value.get_address(network, address_type),
                    public_key_hex,
                    value.get_wif(network, should_compress)
                )
            }
        }
    }
    fn generate_bip84_hd_wallet_from_mnemonic_words(
        mnemonic_words: Vec<String>,
        password: Option<String>,
        account: i32,
        children_count: i32,
        should_harden: bool,
        network: Network,
    ) -> HDWalletBip84 {
        let bip = Bip::Bip84;
        let purpose = 84;
        let coin = 0;
        let should_compress_wif = true;
        // println!("MNEMONIC WORDS: {:?}", mnemonic_words);

        let mnemonic_sentence = get_mnemonic_sentence(&mnemonic_words);

        println!("MNEMONIC SENTENCE: {}", mnemonic_sentence);

        // HARDCODED FOR TESTING
        // let bip39_seed = "67f93560761e20617de26e0cb84f7234aaf373ed2e66295c3d7397e6d7ebe882ea396d5d293808b0defd7edd2babd4c091ad942e6a9351e6d075a29d4df872af".to_string();
        // let bip39_seed = "c4f5d3f03269fe18101b4ba87810e07bdf63a67660c1467ff146836cd6772e092a9a10d6f6d65212085a0443b18d833721c7cb64bddef54c555ef2fdb48101a6".to_string();
        let passphrase = "".to_string();
        let bip39_seed = get_bip38_512_bit_private_key(mnemonic_words, Some(passphrase));
        println!("BIP39 SEED: {}", bip39_seed);
        //
        let bip32_root_key = get_bip32_root_key_from_seed(&bip39_seed, NETWORK, bip);
        println!("BIP39 Root Key: {}", bip32_root_key);

        // ==========MASTER KEYS===============================
        // TWO WAYS TO GET MASTER KEYS:
        // 1) from bip39 seed
        let master_keys = get_master_keys_from_seed(&bip39_seed);
        // 2) from xpriv (root key)
        let master_keys =
            get_master_keys_from_serialized_extended_private_master_key(&bip32_root_key);
        // or use the wrapper
        let master_keys = get_master_keys_from_bip32_root_key(&bip32_root_key);
        //
        // println!("MASTER KEYS: {:#?}", &master_keys);
        // println!(
        //     "MASTER WIF: {}",
        //     &master_keys.get_wif(NETWORK, should_compress_wif)
        // );
        // println!(
        //     "MASTER ADDRESS: {}",
        //     master_keys.get_address(NETWORK, ADDRESS_TYPE),
        // );

        // println!("WIF: {}", master_keys.get_wif(NETWORK, should_compress_wif));
        let bip32_root_key = get_bip32_root_key_from_master_keys(&master_keys, NETWORK, bip);
        println!("BIP39 Root Key: {}", bip32_root_key);
        // -------------------------------------------------

        // ======================================================
        // Not Change
        let derivation_path_external = format!("m/{}'/{}'/{}'/0", purpose, coin, account);
        let bip32_extended_keys_for_external = get_bip32_extended_keys_from_derivation_path(
            &derivation_path_external,
            &Keys::Master(master_keys.clone()),
            NETWORK,
            bip,
        );
        let bip32_extended_private_key_for_external = bip32_extended_keys_for_external.xpriv;
        let bip32_extended_public_key_for_external = bip32_extended_keys_for_external.xpub;
        // Change
        let derivation_path_internal = format!("m/{}'/{}'/{}'/1", purpose, coin, account);
        let bip32_extended_keys_for_internal = get_bip32_extended_keys_from_derivation_path(
            &derivation_path_internal,
            &Keys::Master(master_keys.clone()),
            NETWORK,
            bip,
        );
        let bip32_extended_private_key_for_internal = bip32_extended_keys_for_internal.xpriv;
        let bip32_extended_public_key_for_internal = bip32_extended_keys_for_internal.xpub;

        // let bip32_derivation_path = "m/0'/0'".to_string(); // Must use with P2PKH
        // let bip44_derivation_path = "m/44'/0'/0'/0".to_string(); // Must use with P2PKH
        // let bip49_derivation_path = "m/49'/0'/0'/0".to_string(); // Must use with P2SH
        // let bip84_derivation_path = "m/84'/0'/0'/0".to_string(); // Must use with Bech32
        // let bip141_derivation_path = "m/0".to_string(); // Must use with P2SH
        // let derivation_path = bip141_derivation_path;

        // let xpriv = &bip32_extended_keys.xpriv;
        // let xpub = &bip32_extended_keys.xpub;

        // let decoded_serialized_extended_key = decode_serialized_extended_key(&xpriv);
        // println!("{:#?}", &decoded_serialized_extended_key);
        // println!(
        //     "bip32_extended_public_key!: {:#?}",
        //     bip32_extended_keys.xpub
        // );
        // println!(
        //     "bip32_extended_private_key: {:#?}",
        //     bip32_extended_keys.xpriv
        // );

        let should_include_change_addresses = true;
        let found_children = get_bip84_derived_addresses(
            account,
            should_include_change_addresses,
            &master_keys,
            children_count,
            should_harden,
        );
        let bip84_derivation_path_info =
            get_bip84_derivation_path_info(account, &master_keys.clone(), NETWORK);
        // println!("{:#?}", bip84_derivation_path_info);

        HDWalletBip84 {
            network,
            bip39_seed,
            bip32_root_key,
            purpose,
            coin,
            account,
            // internal: bool,
            account_extended_private_key: bip84_derivation_path_info.account_extended_private_key,
            account_extended_public_key: bip84_derivation_path_info.account_extended_public_key,
            derivation_path_external,
            bip32_extended_private_key_for_external,
            bip32_extended_public_key_for_external,
            derivation_path_internal,
            bip32_extended_private_key_for_internal,
            bip32_extended_public_key_for_internal,
            derived_addresses: found_children,
        }
    }
    fn generate_bip141_hd_wallet_from_mnemonic_words() {
        todo!("Need to implement: https://iancoleman.io/bip39/");
    }
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
