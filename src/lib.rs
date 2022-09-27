use std::collections::HashMap;
use std::fmt::Write;
use std::num::{NonZeroU32, ParseIntError};
use std::str::FromStr;
mod bip39;

use binary_utils::*;
use bip39::WORDS;
use bitcoin::hashes::{ripemd160, Hash};
use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::util::base58::check_encode_slice;
use bitcoin::util::base58::from_check;
use bitcoin::util::taproot::TapTweakHash;
use bitcoin_bech32::{u5, WitnessProgram};
use bitcoin_utils::*;
use hmac_sha512::HMAC;
use num_bigint::BigUint;
use rand::{thread_rng, RngCore};
use ring::{digest, pbkdf2};
use secp256k1::{Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use hex_utilities::{
    convert_decimal_to_32_byte_hex, convert_decimal_to_8_byte_hex, convert_hex_to_decimal,
    decode_hex, encode_hex, get_hex_string_from_byte_array,
};

// TODO: Maybe also incorporate 'h' in addition to '
const HARDENED_DERIVATION_CHARACTER: &str = "'";

#[derive(Debug, Clone)]
pub struct SerializedExtendedKeys {
    pub xpub: String,
    pub xpriv: String,
}

#[derive(Debug, Clone)]
pub struct NonMasterKeys {
    pub private_key_hex: String,
    pub public_key_hex: String,
    pub chain_code_hex: String,
    pub is_hardened: bool,
}
impl NonMasterKeys {
    pub fn get_wif(&self, network: Network, should_compress: bool) -> String {
        get_wif_from_private_key(&self.private_key_hex, network, should_compress)
    }
    pub fn get_address(&self, network: Network, address_type: AddressType) -> String {
        get_address_from_pub_key(&self.public_key_hex, network, address_type)
    }
    pub fn serialize(
        &self,
        parent_public_key: String,
        depth: u8,
        child_index: u32,
        network: Network,
        bip: Bip,
    ) -> SerializedExtendedKeys {
        serialize_non_master_key(&self, parent_public_key, depth, child_index, network, bip)
    }
}
#[derive(Debug, Clone)]
pub struct MasterKeys {
    pub private_key_hex: String,
    pub public_key_hex: String,
    pub chain_code_hex: String,
}
impl MasterKeys {
    pub fn get_wif(&self, network: Network, should_compress: bool) -> String {
        get_wif_from_private_key(&self.private_key_hex, network, should_compress)
    }
    pub fn get_address(&self, network: Network, address_type: AddressType) -> String {
        get_address_from_pub_key(&self.public_key_hex, network, address_type)
    }
    pub fn serialize(&self, network: Network, bip: Bip) -> SerializedExtendedKeys {
        serialize_master_key(self, network, bip)
    }
}

#[derive(Debug, Clone)]
pub enum Keys {
    Master(MasterKeys),
    NonMaster(NonMasterKeys),
}

impl Keys {
    pub fn get_wif(&self, network: Network, should_compress: bool) -> String {
        match &self {
            Keys::Master(master_keys) => master_keys.get_wif(network, should_compress),
            Keys::NonMaster(non_master_keys) => non_master_keys.get_wif(network, should_compress),
        }
    }
    pub fn get_address(&self, network: Network, address_type: AddressType) -> String {
        match &self {
            Keys::Master(master_keys) => master_keys.get_address(network, address_type),
            Keys::NonMaster(non_master_keys) => non_master_keys.get_address(network, address_type),
        }
    }
}
#[derive(Debug)]
enum DerivationChild {
    NonHardened(u32),
    Hardened(u32),
}

#[derive(Debug, Clone)]
pub struct DecodedExtendedSerializedPrivateKey {
    pub version_hex: String,
    pub depth: u8,
    pub parent_fingerprint: String,
    pub child_index: u32,
    pub network: Network,
    pub depth_fingerprint_child_index_hex: String,
    pub chain_code_hex: String,
    pub private_key_hex: String,
    pub wif_compressed: String,
    pub wif_uncompressed: String,
    pub public_key_hex_uncompressed: String,
    pub public_key_hex_compressed: String,
}
#[derive(Debug, Clone)]
pub struct DecodedExtendedSerializedPublicKey {
    pub version_hex: String,
    pub depth: u8,
    pub parent_fingerprint: String,
    pub child_index: u32,
    pub network: Network,
    pub depth_fingerprint_child_index_hex: String,
    pub chain_code_hex: String,
    pub public_key_hex_uncompressed: String,
}

#[derive(Debug, Clone)]
pub enum DecodedExtendedKeySerialized {
    PrivateKey(DecodedExtendedSerializedPrivateKey),
    PublicKey(DecodedExtendedSerializedPublicKey),
}

// Notes
// - A hexidecimal is represetnted by only 4 bits (one byte). We use u8 here because we can't use a
// u4.
// - Check work here: https://iancoleman.io/bip39/
// - https://bitcoin.stackexchange.com/questions/89814/how-does-bip-39-mnemonic-work

// TODO: Use utilties from bitcoin-utils package instead
fn sha256_entropy_hex_byte_array(hex_byte_array: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(&hex_byte_array);
    // read hash digest and consume hasher
    let sha256_result = hasher.finalize();
    sha256_result.to_vec()
}
fn serialize_master_key(
    master_keys: &MasterKeys,
    network: Network,
    bip: Bip,
) -> SerializedExtendedKeys {
    let master_xprv = serialize_key(SerializeKeyArgs {
        keys_to_serialize: Keys::Master(master_keys.clone()).clone(),
        parent_public_key: None,
        is_public: false,
        network: network,
        depth: Some(0),
        child_index: 0,
        bip,
        // Note: always false for master key
    });
    let master_xpub = serialize_key(SerializeKeyArgs {
        keys_to_serialize: Keys::Master(master_keys.clone()).clone(),
        parent_public_key: None,
        is_public: true,
        network: network,
        depth: Some(0),
        child_index: 0,
        bip,
        // Note: always false for master key
    });
    SerializedExtendedKeys {
        xpub: master_xpub,
        xpriv: master_xprv,
    }
}
fn serialize_non_master_key(
    non_master_keys: &NonMasterKeys,
    parent_public_key: String,
    depth: u8,
    child_index: u32,
    network: Network,
    bip: Bip,
) -> SerializedExtendedKeys {
    let bip32_extended_public_key = serialize_key(SerializeKeyArgs {
        keys_to_serialize: Keys::NonMaster(non_master_keys.clone()).clone(),
        parent_public_key: Some(parent_public_key.clone()),
        is_public: true,
        network,
        depth: Some(depth),
        child_index: child_index as u32,
        bip,
    });
    let bip32_extended_private_key = serialize_key(SerializeKeyArgs {
        keys_to_serialize: Keys::NonMaster(non_master_keys.clone()).clone(),
        parent_public_key: Some(parent_public_key.clone()),
        is_public: false,
        network,
        depth: Some(depth),
        child_index: child_index as u32,
        bip,
    });
    SerializedExtendedKeys {
        xpub: bip32_extended_public_key,
        xpriv: bip32_extended_private_key,
    }
}
struct SerializeKeyArgs {
    pub keys_to_serialize: Keys,
    pub parent_public_key: Option<String>,
    pub is_public: bool,
    pub network: Network,
    pub depth: Option<u8>,
    pub child_index: u32,
    pub bip: Bip,
}

#[derive(Copy, Clone)]
pub enum Bip {
    Bip32,
    Bip44,
    Bip49,
    Bip84,
    Bip86,
}

pub fn create_fingerprint(public_key_hex: &String) -> String {
    let sha256_result_hex = sha256_hex(public_key_hex);
    let sha256_result_array = decode_hex(&sha256_result_hex).unwrap();
    let ripemd160_result = ripemd160::Hash::hash(&sha256_result_array);
    let first_four_bytes = &ripemd160_result[..4];
    let first_four_hex = encode_hex(&first_four_bytes);
    first_four_hex
}

fn serialize_key(args: SerializeKeyArgs) -> String {
    let SerializeKeyArgs {
        keys_to_serialize,
        parent_public_key,
        is_public,
        network,
        depth,
        child_index,
        bip,
    } = args;

    fn checksum(hex: &String) -> String {
        let hash = double_sha256_hex(&hex);
        let hash_byte_array = decode_hex(&hash).unwrap();
        let first_four_bytes = &hash_byte_array[0..=3];
        encode_hex(first_four_bytes)
    }

    fn base58_encode(hex_byte_array: Vec<u8>) -> String {
        let encoded = bitcoin::util::base58::encode_slice(&hex_byte_array);
        encoded
    }
    let public_key_hex = match &keys_to_serialize {
        Keys::NonMaster(non_master_keys) => non_master_keys.public_key_hex.clone(),
        Keys::Master(master_keys) => master_keys.public_key_hex.clone(),
    };
    let private_key_hex = match &keys_to_serialize {
        Keys::NonMaster(non_master_keys) => non_master_keys.private_key_hex.clone(),
        Keys::Master(master_keys) => master_keys.private_key_hex.clone(),
    };
    let chain_code_hex = match &keys_to_serialize {
        Keys::NonMaster(non_master_keys) => non_master_keys.chain_code_hex.clone(),
        Keys::Master(master_keys) => master_keys.chain_code_hex.clone(),
    };
    let is_hardened = match &keys_to_serialize {
        Keys::NonMaster(non_master_keys) => non_master_keys.is_hardened.clone(),
        Keys::Master(_master_keys) => false,
    };

    // TODO: Add all versions!
    // List of all the version possibilities: https://electrum.readthedocs.io/en/latest/xpub_version_bytes.html
    let version = match bip {
        Bip::Bip32 | Bip::Bip44 => {
            if is_public {
                match network {
                    Network::Mainnet => "0488b21e",
                    Network::Testnet => "043587cf",
                }
            } else {
                match network {
                    Network::Mainnet => "0488ade4",
                    Network::Testnet => "04358394",
                }
            }
        }
        Bip::Bip49 => {
            // Source: https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
            if is_public {
                match network {
                    Network::Mainnet => "049d7cb2",
                    Network::Testnet => "044a5262",
                }
            } else {
                match network {
                    Network::Mainnet => "049d7878",
                    Network::Testnet => "044a4e28",
                }
            }
        }
        Bip::Bip84 | Bip::Bip86 => {
            // Source: https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
            if is_public {
                match network {
                    Network::Mainnet => "04b24746",
                    Network::Testnet => "045f1cf6",
                }
            } else {
                match network {
                    Network::Mainnet => "04b2430c",
                    Network::Testnet => "045f18bc",
                }
            }
        }
    };
    let key = if is_public {
        format!("{}", public_key_hex)
    } else {
        format!("{}{}", "00", private_key_hex)
    };

    let depth = convert_decimal_to_8_byte_hex(depth.unwrap_or(0));
    let parent_fingerprint = match &parent_public_key {
        Some(parent_public_key) => create_fingerprint(&parent_public_key.to_string()),
        None => "00000000".to_string(),
    };
    // for child
    // let parent_fingerprint = create_fingerprint(parent_public_key.to_string());
    // TODO: How do we do children at other indexes other than 0. Like 1.
    let child_index_with_hardened_factored_in = if is_hardened {
        child_index + 2147483648 // # child index number (must between 2**31 and 2**32-1)
    } else {
        child_index
    };
    let child_number = convert_decimal_to_32_byte_hex(child_index_with_hardened_factored_in);
    let chain_code = chain_code_hex;
    // let key = format!("{}{}", "00", private_key);
    let serialized = format!(
        "{}{}{}{}{}{}",
        version, depth, parent_fingerprint, child_number, chain_code, key
    );

    let serialized_bytes = decode_hex(&serialized).unwrap();
    let checksum = checksum(&serialized);
    let checksum_bytes = decode_hex(&checksum).unwrap();
    let serialized_with_checksum = format!("{}{}", serialized, checksum);
    let serialized_with_checksum_bytes = concat_u8(&serialized_bytes, &checksum_bytes);
    let base58_encoded_serialized_with_checksum = base58_encode(serialized_with_checksum_bytes);
    base58_encoded_serialized_with_checksum
    // checksum: 7a2a2640
    // serialized: 0488ade401018c12590000000005aae71d7c080474efaab01fa79e96f4c6cfe243237780b0df4bc36106228e310039f329fedba2a68e2a804fcd9aeea4104ace9080212a52ce8b52c1fb89850c72
}

fn get_child_extended_public_key(
    parent_chain_code: &[u8],
    parent_public_key: &String,
    child_index: i32,
) -> (String, String) {
    let parent_chain_code = parent_chain_code;
    let key = parent_chain_code;
    let index: i32 = child_index;
    let index_as_bytes = index.to_be_bytes();
    let parent_public_key_hex = parent_public_key.clone();
    let parent_public_key_as_bytes = decode_hex(&parent_public_key).unwrap();
    let parent_public_key_with_index_as_bytes =
        concat_u8(&parent_public_key_as_bytes, &index_as_bytes);

    let h = HMAC::mac(parent_public_key_with_index_as_bytes, key);
    let left = &h[0..=31];
    let right = &h[32..];
    // let sk = secp256k1::SecretKey::from_slice(left).expect("statistically impossible to hit");
    // let parent_private_secret_key = SecretKey::from_str(&encode_hex(parent_private_key)).unwrap();

    // let tweaked = sk
    //     .add_tweak(&parent_private_secret_key.into())
    //     .expect("statistically impossible to hit");

    // Source: "ckd_pub" function here: https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/bip32.rs
    let secp = Secp256k1::new();
    let sk = secp256k1::SecretKey::from_str(&encode_hex(left)).unwrap();
    let pk = secp256k1::PublicKey::from_str(&parent_public_key_hex)
        .expect("statistically impossible to hit");
    let tweaked = pk.add_exp_tweak(&secp, &sk.into()).unwrap();

    let child_public_key: String = tweaked.to_string();
    let child_chain_code: String = encode_hex(right);

    return (child_public_key, child_chain_code);
}
fn get_hardened_child_extended_private_key(
    master_chain_code: &[u8],
    master_private_key: &[u8],
    child_index: u32,
) -> Keys {
    let key = master_chain_code;
    let index: u32 = child_index + 2147483648; // # child index number (must between 2**31 and 2**32-1)
    let index_as_bytes = index.to_be_bytes();
    let master_private_key_as_bytes = master_private_key;
    let prefix_bytes = decode_hex("00").unwrap();
    let master_private_key_with_index_as_bytes =
        concat_u8(master_private_key_as_bytes, &index_as_bytes);
    let master_private_key_with_index_and_prefix_as_bytes =
        concat_u8(&prefix_bytes, &master_private_key_with_index_as_bytes);

    let h = HMAC::mac(master_private_key_with_index_and_prefix_as_bytes, key);
    let left = &h[0..=31];
    let right = &h[32..];
    //  Source: 'ckd_priv" function here: https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/bip32.rs
    let sk = secp256k1::SecretKey::from_slice(left).expect("statistically impossible to hit");
    let master_private_secret_key = SecretKey::from_str(&encode_hex(master_private_key)).unwrap();

    let tweaked = sk
        .add_tweak(&master_private_secret_key.into())
        .expect("statistically impossible to hit");
    let hardened_child_private_key: String = tweaked.display_secret().to_string();
    let child_public_key = get_compressed_public_key_from_private_key(&hardened_child_private_key);

    let child_private_key = hardened_child_private_key;
    let child_chain_code = encode_hex(right);
    let child_public_key = child_public_key;
    let keys = Keys::NonMaster(NonMasterKeys {
        private_key_hex: child_private_key,
        public_key_hex: child_public_key,
        chain_code_hex: child_chain_code,
        is_hardened: true,
    });
    keys
}
fn get_child_extended_private_key(
    master_chain_code: &[u8],
    master_public_key: &String,
    master_private_key: &[u8],
    child_index: i32,
) -> Keys {
    //
    let key = master_chain_code;
    // TODO: This is the child index !
    let index: i32 = child_index;
    let index_as_bytes = index.to_be_bytes();
    let master_public_key_as_bytes = master_public_key.as_bytes();
    let master_public_key_as_bytes = decode_hex(&master_public_key).unwrap();
    let master_public_key_with_index_as_bytes =
        concat_u8(&master_public_key_as_bytes, &index_as_bytes);
    let h = HMAC::mac(master_public_key_with_index_as_bytes, key);
    let left = &h[0..=31];
    let right = &h[32..];
    //  Source: 'ckd_priv" function here: https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/bip32.rs
    let sk = secp256k1::SecretKey::from_slice(left).expect("statistically impossible to hit");
    // let secp = Secp256k1::new();
    let master_private_secret_key = SecretKey::from_str(&encode_hex(master_private_key)).unwrap();

    let tweaked = sk
        .add_tweak(&master_private_secret_key.into())
        .expect("statistically impossible to hit");
    let child_private_key: String = tweaked.display_secret().to_string();
    let child_public_key = get_compressed_public_key_from_private_key(&child_private_key);

    let child_private_key = child_private_key;
    let child_chain_code = encode_hex(right);
    let child_public_key = child_public_key;
    let keys = Keys::NonMaster(NonMasterKeys {
        private_key_hex: child_private_key,
        public_key_hex: child_public_key,
        chain_code_hex: child_chain_code,
        is_hardened: false,
    });
    keys
}

fn parse_derivation_path_child(derivation_path_child: &String) -> DerivationChild {
    let child_split_into_hardened_key: Vec<&str> = derivation_path_child
        .split(HARDENED_DERIVATION_CHARACTER)
        .collect();
    let is_hardened = child_split_into_hardened_key.len() == 2;
    let child_index = child_split_into_hardened_key
        .get(0)
        .unwrap()
        .parse()
        .unwrap();
    if is_hardened {
        DerivationChild::Hardened(child_index)
    } else {
        DerivationChild::NonHardened(child_index)
    }
}
fn get_child_index_from_derivation_path(derivation_path: &String) -> DerivationChild {
    let derivation_path_split_by_dash: Vec<&str> = derivation_path.split('/').collect();
    let first = derivation_path_split_by_dash.first().unwrap();
    if first.to_string() != "m" {
        panic!("derivation must start with m")
    } else {
        let last_item = derivation_path_split_by_dash.last().unwrap().to_string();
        parse_derivation_path_child(&last_item)
    }
}

fn split_derivation_path(derivation_path: String) -> Vec<String> {
    let derivation_path_split_by_dash: Vec<&str> = derivation_path.split('/').collect();
    let first = derivation_path_split_by_dash.first().unwrap();
    if first.to_string() != "m" {
        panic!("derivation must start with m")
    } else {
        // TODO: factor in hardened vs non-hardened keys here
        let derivation_path_indexes: Vec<String> = derivation_path_split_by_dash[1..]
            .iter()
            .map(|s| s.to_string())
            .collect();
        derivation_path_indexes
    }
}

fn get_child_key_from_derivation_path(derivation_path: String, master_keys: Keys) -> Keys {
    let derivation_path_indexes = split_derivation_path(derivation_path);
    let mut current_parent_keys = master_keys;
    // TODO: factor in hardened vs non-hardened keys here
    for derivation_path_item in derivation_path_indexes {
        let derivation_child = parse_derivation_path_child(&derivation_path_item);

        let child_keys = match derivation_child {
            DerivationChild::NonHardened(child_index) => {
                let should_harden = false;
                get_child_key(&current_parent_keys, child_index as i32, should_harden)
            }
            DerivationChild::Hardened(child_index) => {
                let should_harden = true;
                get_child_key(&current_parent_keys, child_index as i32, should_harden)
            }
        };
        //get_child_key(&current_parent_keys, i as i32, false);
        current_parent_keys = child_keys;
    }

    current_parent_keys
}
fn get_children_keys_from_derivation_path(
    derivation_path: &String,
    master_keys: Keys,
    children_count: i32,
    should_be_hardened: bool,
) -> HashMap<String, Keys> {
    let child_key = get_child_key_from_derivation_path(derivation_path.to_string(), master_keys);
    let child_keys = get_child_keys(&child_key, children_count, should_be_hardened);
    child_keys
}
fn get_child_key(parent_keys: &Keys, child_index: i32, should_harden: bool) -> Keys {
    let parent_chain_code_hex = match &parent_keys {
        Keys::NonMaster(non_master_keys) => non_master_keys.chain_code_hex.clone(),
        Keys::Master(master_keys) => master_keys.chain_code_hex.clone(),
    };
    let parent_private_key_hex = match parent_keys {
        Keys::NonMaster(non_master_keys) => non_master_keys.private_key_hex.clone(),
        Keys::Master(master_keys) => master_keys.private_key_hex.clone(),
    };
    let parent_public_key_hex = match parent_keys {
        Keys::NonMaster(non_master_keys) => non_master_keys.public_key_hex.clone(),
        Keys::Master(master_keys) => master_keys.public_key_hex.clone(),
    };
    let parent_chain_code_bytes = decode_hex(&parent_chain_code_hex).unwrap();
    let parent_private_key_bytes = decode_hex(&parent_private_key_hex).unwrap();
    if should_harden {
        get_hardened_child_extended_private_key(
            &parent_chain_code_bytes,
            &parent_private_key_bytes,
            child_index as u32,
        )
    } else {
        get_child_extended_private_key(
            &parent_chain_code_bytes,
            &parent_public_key_hex.clone(),
            &parent_private_key_bytes,
            child_index as i32,
        )
    }
}
fn get_child_keys(
    parent_keys: &Keys,
    children_count: i32,
    should_be_hardened: bool,
) -> HashMap<String, Keys> {
    let mut children = HashMap::new();
    for child_index in 0..=children_count {
        if should_be_hardened {
            let child_keys_hardened = get_child_key(parent_keys, child_index as i32, true);
            let hash_key = format!("{}'", child_index);
            children.insert(hash_key, child_keys_hardened);
        } else {
            let child_keys = get_child_key(parent_keys, child_index as i32, false);
            let hash_key = format!("{}", child_index);
            children.insert(hash_key, child_keys);
        }
    }
    children
}

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

// PUBLICCCC
// Use this many bits when you want to have 12 words
pub fn get_128_bits_of_entropy() -> [u8; 32] {
    let mut data = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

// Use this many bits when you want to have 24 words
pub fn get_256_bits_of_entropy() -> [u8; 64] {
    let mut data = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut data);
    data
}
pub fn get_mnemonic_words(entropy: Vec<u8>) -> Vec<String> {
    //let hex_string = "a4b836c41875815e8b153bc89091f1d85dd1ae47287289f5a50ff23cf41b8d21";
    //let hex_string = "da490f7254f80aa2f7e8dcb3c63a8404";
    let entropy_hex_string = get_hex_string_from_byte_array(&entropy);

    // let entropy_hex_string = "731180c4b776f6b961da802ff55b153f".to_string();
    let entropy_hex_byte_array = decode_hex(&entropy_hex_string).unwrap();

    // 2) Calculate the SHA256 of the entropy.
    let sha256_result = sha256_entropy_hex_byte_array(&entropy_hex_byte_array);
    // 3) Append the first entropy_length/32 bits of the SHA256 of the entropy at the end of the entropy. For example, in our case we will append the first 4 bits of the SHA256(entropy) to the entropy since our entropy is 128 bits.
    let entropy_hex_binary_string = get_binary_string_for_byte_array(&entropy_hex_byte_array);
    let bits_to_append_count = (&entropy_hex_binary_string.len()) / 32;
    let sha256_result_binary_string = get_binary_string_for_byte_array(&sha256_result);
    let checksum_binary_string = &sha256_result_binary_string[0..bits_to_append_count];

    // 4) Each word of the mnemonic represents 11 bits. Hence, if you check the wordlist you will find 2048 unique words. Now, divide the entropy + checksum into parts of 11 bits each.
    let entropy_plus_checksum_binary =
        format!("{}{}", entropy_hex_binary_string, checksum_binary_string);

    let word_binary = split_binary_string_into_framents_of_11_bits(&entropy_plus_checksum_binary);

    let words: Vec<String> = word_binary
        .iter()
        .map(|word_binary_string| {
            let word_num = convert_binary_to_int(word_binary_string);
            WORDS.get(word_num as usize).unwrap().to_string()
        })
        .collect();
    words
}
fn get_mnemonic_sentence(mnemonic_words: &Vec<String>) -> String {
    mnemonic_words.join(" ")
}

fn get_bip38_512_bit_private_key(words: Vec<String>, passphrase: Option<String>) -> String {
    let mnemonic_sentence = words.join(" ");

    // ===== CREATE A PRIVATE KEY (512 bit seed) ==========================
    const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
    let n_iter = NonZeroU32::new(2048).unwrap();
    let rng = thread_rng();
    // let rng = SystemRandom::new();

    // Optional passphase
    let passphrase = match passphrase {
        Some(passphrase) => passphrase,
        None => "".to_string(),
    };
    let salt = format!("{}{}", "mnemonic", passphrase);
    let mut salt_as_bytes = salt.as_bytes().to_owned();
    // rand::thread_rng().fill_bytes(&mut salt);

    let password = mnemonic_sentence.clone();
    let mut password_as_bytes = password.as_bytes().to_owned();
    let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        &salt_as_bytes,
        password.as_bytes(),
        &mut pbkdf2_hash,
    );

    let bip39_seed = encode_hex(&pbkdf2_hash);

    // TODO: This should probably be extracted into a teest
    let wrong_password = "Definitely not the correct password";
    let should_fail = pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        &salt.as_bytes(),
        wrong_password.as_bytes(),
        &pbkdf2_hash,
    );
    match should_fail {
        Err(err) => {}
        _ => panic!("SOULD HAVE ERRORERED"),
    }

    bip39_seed
}
fn get_master_keys_from_seed(bip39_seed: &String) -> MasterKeys {
    let pbkdf2_hash = decode_hex(&bip39_seed).unwrap();
    let key = "Bitcoin seed";
    let h = HMAC::mac(pbkdf2_hash.to_vec(), key.as_bytes());
    let left = &h[0..=31];
    let master_private_key = left;
    let master_private_key_hex = encode_hex(master_private_key);
    let right = &h[32..];
    let master_chain_code = right;

    // How do I get master public key:
    // https://learnmeabitcoin.com/technical/extended-keys
    // https://learnmeabitcoin.com/technical/hd-wallets
    let master_public_key = get_compressed_public_key_from_private_key(&master_private_key_hex);
    let keys = MasterKeys {
        public_key_hex: master_public_key,
        private_key_hex: master_private_key_hex,
        chain_code_hex: encode_hex(master_chain_code),
    };
    keys
}
fn get_bip32_root_key_from_seed(bip39_seed: &String, network: Network, bip: Bip) -> String {
    let master_keys = get_master_keys_from_seed(&bip39_seed.to_string());
    let serialized_extended_master_keys = master_keys.serialize(network, bip);

    let master_xprv = serialized_extended_master_keys.xpriv;
    master_xprv
}
fn get_bip32_root_key_from_master_keys(
    master_keys: &MasterKeys,
    network: Network,
    bip: Bip,
) -> String {
    let serialized_extended_master_keys = master_keys.serialize(network, bip);

    let master_xprv = serialized_extended_master_keys.xpriv;
    master_xprv
}
fn get_bip32_extended_keys_from_derivation_path(
    derivation_path: &String,
    master_keys: &Keys,
    network: Network,
    bip: Bip,
) -> SerializedExtendedKeys {
    let parent_deviation_path = get_parent_derivation_path(derivation_path);
    let derivation_child = get_child_index_from_derivation_path(derivation_path);
    let derivation_child_index = match derivation_child {
        DerivationChild::NonHardened(child_index) => child_index,
        DerivationChild::Hardened(child_index) => child_index,
    };
    let found_child =
        get_child_key_from_derivation_path(derivation_path.to_string(), master_keys.clone());
    let parent_keys =
        get_child_key_from_derivation_path(parent_deviation_path, master_keys.clone());
    let depth = get_depth_from_derivation_path(&derivation_path.to_string());

    let parent_public_key_hex = match parent_keys {
        Keys::NonMaster(non_master_keys) => non_master_keys.public_key_hex,
        Keys::Master(master_keys) => master_keys.public_key_hex,
    };

    let bip32_extended_keys = match found_child {
        Keys::NonMaster(non_master_keys) => non_master_keys.serialize(
            parent_public_key_hex,
            depth,
            derivation_child_index,
            network,
            bip,
        ),
        Keys::Master(master_keys) => master_keys.serialize(network, bip),
    };

    bip32_extended_keys
}

fn get_derived_addresses_for_derivation_path(
    derivation_path: &String,
    master_keys: &MasterKeys,
    child_count: i32,
    should_use_hardened_addresses: bool,
) -> HashMap<String, Keys> {
    let found_children = get_children_keys_from_derivation_path(
        &derivation_path,
        Keys::Master(master_keys.clone()),
        child_count,
        should_use_hardened_addresses,
    );
    let mut found_children_with_full_derivation_path_as_key: HashMap<String, Keys> = HashMap::new();
    for (key, value) in found_children {
        let full_derivation_path_with_child = format!("{}/{}", derivation_path, key);
        found_children_with_full_derivation_path_as_key
            .insert(full_derivation_path_with_child, value);
    }
    found_children_with_full_derivation_path_as_key
}

fn decode_serialized_extended_key(extended_key_serialized: &str) -> DecodedExtendedKeySerialized {
    // Source (to check work): http://bip32.org/
    let decoded_result = from_check(extended_key_serialized).unwrap();
    let index_of_last_byte_of_version = 3;
    let version_bytes = decoded_result
        .get(0..=index_of_last_byte_of_version)
        .unwrap();
    let version_hex = encode_hex(version_bytes);
    let (network, is_public) = match version_hex.as_str() {
        // bip32 version keys
        "0488b21e" => (Network::Mainnet, true),
        "043587cf" => (Network::Testnet, true),
        "0488ade4" => (Network::Mainnet, false),
        "04358394" => (Network::Testnet, false),
        // bip49 version keys
        "049d7cb2" => (Network::Mainnet, true),
        "044a5262" => (Network::Testnet, true),
        "049d7878" => (Network::Mainnet, false),
        "044a4e28" => (Network::Testnet, false),
        // bip84 version keys
        "04b24746" => (Network::Mainnet, true),
        "045f1cf6" => (Network::Testnet, true),
        "04b2430c" => (Network::Mainnet, false),
        "045f18bc" => (Network::Testnet, false),
        _ => panic!("Version  not recognized: {}", version_hex),
    };

    // Check: https://coinb.in/#verify
    // Source:https://en.bitcoin.it/wiki/Wallet_import_format
    // 1. decode the base58check
    // private key is 64 characters long, and each byte is 2 characters (4 bytes each).
    let index_where_private_key_starts = decoded_result.len() - (64 / 2);
    let index_where_chain_code_starts = index_where_private_key_starts - (64 / 2) - 1;
    let key_bytes = decoded_result
        .get(index_where_private_key_starts..)
        .unwrap();
    // There is a byte between chain code and private key, that's why we subtract 1 here from the
    // index where the private key starts
    let chain_code_bytes = decoded_result
        .get(
            index_where_chain_code_starts
                ..(index_where_private_key_starts - (if is_public { 0 } else { 1 })),
        )
        .unwrap();
    let key_hex = encode_hex(&key_bytes);
    let chain_code_hex = encode_hex(&chain_code_bytes);

    let depth_fingerprint_child_index_bytes = decoded_result
        .get((index_of_last_byte_of_version + 1)..index_where_chain_code_starts)
        .unwrap();
    let depth_fingerprint_child_index_hex = encode_hex(&depth_fingerprint_child_index_bytes);
    let depth_byte = depth_fingerprint_child_index_bytes.get(0).unwrap().clone();
    let depth_hex = encode_hex(&[depth_byte]);
    let depth_decimal = convert_hex_to_decimal(&depth_hex).unwrap() as u8;
    let depth = depth_fingerprint_child_index_bytes.get(0..=1).unwrap();
    let depth_hex = encode_hex(&depth);

    let parent_fingerprint_bytes = depth_fingerprint_child_index_bytes.get(1..=4).unwrap();
    let parent_fingerprint_hex = encode_hex(parent_fingerprint_bytes);

    let child_index_bytes = depth_fingerprint_child_index_bytes.get(5..).unwrap();
    let child_index_hex = encode_hex(&child_index_bytes);
    let child_index_decimal = convert_hex_to_decimal(&child_index_hex).unwrap() as u32;
    if is_public {
        DecodedExtendedKeySerialized::PublicKey(DecodedExtendedSerializedPublicKey {
            version_hex,
            network,
            depth_fingerprint_child_index_hex,
            depth: depth_decimal,
            parent_fingerprint: parent_fingerprint_hex,
            child_index: child_index_decimal,
            chain_code_hex,
            public_key_hex_uncompressed: key_hex,
        })
    } else {
        DecodedExtendedKeySerialized::PrivateKey(DecodedExtendedSerializedPrivateKey {
            version_hex,
            network,
            depth_fingerprint_child_index_hex,
            depth: depth_decimal,
            parent_fingerprint: parent_fingerprint_hex,
            child_index: child_index_decimal,
            chain_code_hex,
            private_key_hex: key_hex.clone(),
            wif_compressed: get_wif_from_private_key(&key_hex, network, true),
            wif_uncompressed: get_wif_from_private_key(&key_hex, network, false),
            public_key_hex_uncompressed: get_public_key_from_private_key(&key_hex, false),
            public_key_hex_compressed: get_public_key_from_private_key(&key_hex, true),
        })
    }
}
fn get_master_keys_from_serialized_extended_private_master_key(
    serialized_extended_private_key: &String,
) -> MasterKeys {
    let decoded_serialized_extended_key =
        decode_serialized_extended_key(serialized_extended_private_key);
    let decoded_xpriv_keys = match decoded_serialized_extended_key.clone() {
        DecodedExtendedKeySerialized::PrivateKey(decoded_extended_serialized_private_key) => {
            decoded_extended_serialized_private_key
        }
        DecodedExtendedKeySerialized::PublicKey(_) => panic!("shouldn happen"),
    };
    if decoded_xpriv_keys.depth == 0 && decoded_xpriv_keys.child_index == 0 {
        let master_keys = MasterKeys {
            private_key_hex: decoded_xpriv_keys.private_key_hex,
            public_key_hex: decoded_xpriv_keys.public_key_hex_uncompressed,
            chain_code_hex: decoded_xpriv_keys.chain_code_hex,
        };
        master_keys
    } else {
        panic!("must pass a master extended key here, not a child");
    }
}
// Just a wapper for more specific naming
fn get_master_keys_from_bip32_root_key(bip32_root_key: &String) -> MasterKeys {
    get_master_keys_from_serialized_extended_private_master_key(bip32_root_key)
}
fn get_bip32_derived_addresses(
    bip32_derivation_path: &String,
    master_keys: &MasterKeys,
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
    cointype: i32,
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
        &master_keys,
        children_count,
        should_harden,
    );

    let mut found_childrenn = found_children_for_external_chain.clone();
    if should_include_change_addresses {
        let found_children_for_internal_chain = get_derived_addresses_for_derivation_path(
            &bip44_derivation_path_for_internal_chain,
            &master_keys,
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
    coin_type: i32,
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
    get_derived_addresses_from_5_levels(
        purpose,
        coin_type,
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
    coin_type: i32,
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
    get_derived_addresses_from_5_levels(
        purpose,
        coin_type,
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
    coin_type: i32,
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
    get_derived_addresses_from_5_levels(
        purpose,
        coin_type,
        account,
        should_include_change_addresses,
        master_keys,
        children_count,
        should_harden,
    )
}
// TODO: Create a function to get the Account Extended private/public keys and the bip32 extended
// private/public keys. See BIP49 section of: https://iancoleman.io/bip39/
fn get_bip86_derived_addresses(
    coin_type: i32,
    account: i32,
    should_include_change_addresses: bool,
    master_keys: &MasterKeys,
    children_count: i32,
    should_harden: bool,
) -> HashMap<String, Keys> {
    // Source: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
    // External chain is used for addresses that are meant to be visible outside of the wallet (e.g. for receiving payments). Internal chain is used for addresses which are not meant to be visible outside of the wallet and is used for return transaction change.
    // internal chain is also known as a change address
    let purpose = 86;
    get_derived_addresses_from_5_levels(
        purpose,
        coin_type,
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
    cointype: i32,
    account: i32,
    master_keys: &MasterKeys,
    network: Network,
) -> Bip44DerivationPathInfo {
    let purpose = 44;
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
    coin_type: i32,
    account: i32,
    master_keys: &MasterKeys,
    network: Network,
) -> Bip49DerivationPathInfo {
    let purpose = 49;
    let account_derivation_path = format!("m/{}'/{}'/{}'", purpose, coin_type, account);
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
    coin_type: i32,
    account: i32,
    master_keys: &MasterKeys,
    network: Network,
) -> Bip84DerivationPathInfo {
    let purpose = 84;
    let account_derivation_path = format!("m/{}'/{}'/{}'", purpose, coin_type, account);
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
#[derive(Debug)]
struct Bip86DerivationPathInfo {
    account_extended_private_key: String,
    account_extended_public_key: String,
}
fn get_bip86_derivation_path_info(
    coin_type: i32,
    account: i32,
    master_keys: &MasterKeys,
    network: Network,
) -> Bip86DerivationPathInfo {
    let purpose = 86;
    let account_derivation_path = format!("m/{}'/{}'/{}'", purpose, coin_type, account);
    let bip32_extended_keys_for_account = get_bip32_extended_keys_from_derivation_path(
        &account_derivation_path.to_string(),
        &Keys::Master(master_keys.clone()),
        network,
        Bip::Bip84,
    );

    Bip86DerivationPathInfo {
        account_extended_private_key: bip32_extended_keys_for_account.xpriv,
        account_extended_public_key: bip32_extended_keys_for_account.xpub,
    }
}

#[derive(Debug)]
pub struct HDWalletBip32 {
    network: Network,
    bip39_seed: String,
    master_keys: MasterKeys,
    bip32_root_key: String,
    bip32_root_pub_key: String,
    bip32_derivation_path: String,
    bip32_extended_private_key: String,
    bip32_extended_public_key: String,
    master_fingerprint: String,
    derived_addresses: HashMap<String, Keys>,
}
impl HDWalletBip32 {
    pub fn pretty_print_derived_addressed(
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
            let address = value.get_address(network, address_type);
            println!(
                "{} {}  {}   {}    {}      {}",
                key,
                address,
                get_public_key_hash_from_address(&address),
                get_public_key_hash_from_public_key(&public_key_hex),
                public_key_hex,
                value.get_wif(network, should_compress)
            )
        }
    }
}

pub fn generate_bip32_hd_wallet_from_mnemonic_words(
    mnemonic_words: Vec<String>,
    password: Option<String>,
    derivation_path: String,
    children_count: i32,
    should_harden: bool,
    network: Network,
) -> HDWalletBip32 {
    let bip = Bip::Bip32;
    let passphrase = match password {
        Some(password) => password,
        None => "".to_string(),
    };
    let bip39_seed = get_bip38_512_bit_private_key(mnemonic_words, Some(passphrase));
    let bip32_root_key = get_bip32_root_key_from_seed(&bip39_seed, network, bip);
    // Notice we have two ways to get the master keys: -------------------------
    // 1) using seed
    let master_keys_generated_from_seed = get_master_keys_from_seed(&bip39_seed);
    // 2) using bip32 root key (extended private master key)
    let master_keys_generated_from_bip32_root_key =
        get_master_keys_from_bip32_root_key(&bip32_root_key);
    let master_keys = master_keys_generated_from_seed;
    // ---------------------------------------------------------------------------
    // Can also get bip32 root key from masterkeys;
    let bip32_root_key = get_bip32_root_key_from_master_keys(&master_keys, network, bip);
    let master_fingerprint = create_fingerprint(&master_keys.public_key_hex);
    //
    let serialized_extended_master_keys = master_keys.serialize(network, bip);

    let bip32_root_pub_key = serialized_extended_master_keys.xpub;

    let bip32_extended_keys = get_bip32_extended_keys_from_derivation_path(
        &derivation_path,
        &Keys::Master(master_keys.clone()),
        network,
        bip,
    );
    let xpriv = &bip32_extended_keys.xpriv;
    let xpub = &bip32_extended_keys.xpub;

    let found_children = get_bip32_derived_addresses(
        &derivation_path,
        &master_keys,
        children_count,
        should_harden,
    );

    HDWalletBip32 {
        network,
        master_keys,
        bip39_seed,
        bip32_root_key,
        bip32_root_pub_key,
        master_fingerprint,
        bip32_derivation_path: derivation_path,
        bip32_extended_private_key: xpriv.to_string(),
        bip32_extended_public_key: xpub.to_string(),
        derived_addresses: found_children,
    }
}
#[derive(Debug)]
pub struct HDWalletBip44 {
    network: Network,
    bip39_seed: String,
    master_keys: MasterKeys,
    bip32_root_key: String,
    bip32_root_pub_key: String,
    master_fingerprint: String,
    purpose: i32,
    coin_type: i32,
    account: i32,
    // internal: bool,
    account_derivation_path: String,
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
    pub fn pretty_print_derived_addressed(&self, network: Network) -> () {
        let address_type = AddressType::P2PKH;
        for (key, value) in self.derived_addresses.clone() {
            let should_compress = true;
            let public_key_hex = match &value {
                Keys::NonMaster(non_master_keys) => non_master_keys.public_key_hex.clone(),
                Keys::Master(master_keys) => master_keys.public_key_hex.clone(),
            };
            let address = value.get_address(network, address_type);
            println!(
                "{} {}  {}   {}    {}      {}",
                key,
                address,
                get_public_key_hash_from_address(&address),
                get_public_key_hash_from_public_key(&public_key_hex),
                public_key_hex,
                value.get_wif(network, should_compress)
            )
        }
    }
}
pub fn generate_bip44_hd_wallet_from_mnemonic_words(
    mnemonic_words: Vec<String>,
    password: Option<String>,
    coin_type: i32,
    account: i32,
    children_count: i32,
    should_harden: bool,
    network: Network,
) -> HDWalletBip44 {
    let bip = Bip::Bip44;
    let purpose = 44;

    let passphrase = match password {
        Some(password) => password,
        None => "".to_string(),
    };
    let bip39_seed = get_bip38_512_bit_private_key(mnemonic_words, Some(passphrase));
    let bip32_root_key = get_bip32_root_key_from_seed(&bip39_seed, network, bip);
    // Notice we have two ways to get the master keys: -------------------------
    // 1) using seed
    let master_keys_generated_from_seed = get_master_keys_from_seed(&bip39_seed);
    // 2) using bip32 root key (extended private master key)
    let master_keys_generated_from_bip32_root_key =
        get_master_keys_from_bip32_root_key(&bip32_root_key);
    let master_keys = master_keys_generated_from_seed;
    // ---------------------------------------------------------------------------
    // Can also get bip32 root key from masterkeys;
    let bip32_root_key = get_bip32_root_key_from_master_keys(&master_keys, network, bip);
    //
    let master_fingerprint = create_fingerprint(&master_keys.public_key_hex);
    let serialized_extended_master_keys = master_keys.serialize(network, bip);

    let bip32_root_pub_key = serialized_extended_master_keys.xpub;
    let account_derivation_path = format!("m/{}'/{}'/{}'", purpose, coin_type, account);
    let derivation_path_external = format!("{}/0", account_derivation_path);
    let bip32_extended_keys_for_external = get_bip32_extended_keys_from_derivation_path(
        &derivation_path_external,
        &Keys::Master(master_keys.clone()),
        network,
        bip,
    );
    let bip32_extended_private_key_for_external = bip32_extended_keys_for_external.xpriv;
    let bip32_extended_public_key_for_external = bip32_extended_keys_for_external.xpub;
    // Change
    let derivation_path_internal = format!("{}/1", account_derivation_path);
    let bip32_extended_keys_for_internal = get_bip32_extended_keys_from_derivation_path(
        &derivation_path_internal,
        &Keys::Master(master_keys.clone()),
        network,
        bip,
    );
    let bip32_extended_private_key_for_internal = bip32_extended_keys_for_internal.xpriv;
    let bip32_extended_public_key_for_internal = bip32_extended_keys_for_internal.xpub;

    let should_include_change_addresses = true;
    let found_children = get_bip44_derived_addresses(
        coin_type,
        account,
        should_include_change_addresses,
        &master_keys,
        children_count,
        should_harden,
    );
    let bip44_derivation_path_info =
        get_bip44_derivation_path_info(coin_type, account, &master_keys.clone(), network);
    // println!("{:#?}", bip84_derivation_path_info);

    HDWalletBip44 {
        network,
        bip39_seed,
        master_keys,
        bip32_root_key,
        bip32_root_pub_key,
        master_fingerprint,
        purpose,
        coin_type,
        account,
        // internal: bool,
        account_derivation_path,
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
pub struct HDWalletBip49 {
    network: Network,
    master_keys: MasterKeys,
    bip39_seed: String,
    bip32_root_key: String,
    bip32_root_pub_key: String,
    master_fingerprint: String,
    purpose: i32,
    coin_type: i32,
    account: i32,
    // internal: bool,
    account_derivation_path: String,
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
    pub fn pretty_print_derived_addressed(&self, network: Network) -> () {
        let address_type = AddressType::P2SH;
        for (key, value) in self.derived_addresses.clone() {
            let should_compress = true;
            let public_key_hex = match &value {
                Keys::NonMaster(non_master_keys) => non_master_keys.public_key_hex.clone(),
                Keys::Master(master_keys) => master_keys.public_key_hex.clone(),
            };
            let address = value.get_address(network, address_type);
            println!(
                "{} {}  {}   {}      {}",
                key,
                address,
                //get_public_key_hash_from_address(&address),
                get_public_key_hash_from_public_key(&public_key_hex),
                public_key_hex,
                value.get_wif(network, should_compress)
            )
        }
    }
}
pub fn generate_bip49_hd_wallet_from_mnemonic_words(
    mnemonic_words: Vec<String>,
    password: Option<String>,
    coin_type: i32,
    account: i32,
    children_count: i32,
    should_harden: bool,
    network: Network,
) -> HDWalletBip49 {
    let bip = Bip::Bip49;
    let purpose = 49;

    let passphrase = match password {
        Some(password) => password,
        None => "".to_string(),
    };
    let bip39_seed = get_bip38_512_bit_private_key(mnemonic_words, Some(passphrase));
    let bip32_root_key = get_bip32_root_key_from_seed(&bip39_seed, network, bip);
    // Notice we have two ways to get the master keys: -------------------------
    // 1) using seed
    let master_keys_generated_from_seed = get_master_keys_from_seed(&bip39_seed);
    // 2) using bip32 root key (extended private master key)
    let master_keys_generated_from_bip32_root_key =
        get_master_keys_from_bip32_root_key(&bip32_root_key);
    let master_keys = master_keys_generated_from_seed;
    // ---------------------------------------------------------------------------
    // Can also get bip32 root key from masterkeys;
    let bip32_root_key = get_bip32_root_key_from_master_keys(&master_keys, network, bip);
    //
    let serialized_extended_master_keys = master_keys.serialize(network, bip);

    let bip32_root_pub_key = serialized_extended_master_keys.xpub;
    let master_fingerprint = create_fingerprint(&master_keys.public_key_hex);

    let account_derivation_path = format!("m/{}'/{}'/{}'", purpose, coin_type, account);
    let derivation_path_external = format!("{}/0", account_derivation_path);
    let bip32_extended_keys_for_external = get_bip32_extended_keys_from_derivation_path(
        &derivation_path_external,
        &Keys::Master(master_keys.clone()),
        network,
        bip,
    );
    let bip32_extended_private_key_for_external = bip32_extended_keys_for_external.xpriv;
    let bip32_extended_public_key_for_external = bip32_extended_keys_for_external.xpub;
    // Change
    let derivation_path_internal = format!("{}/1", account_derivation_path);
    let bip32_extended_keys_for_internal = get_bip32_extended_keys_from_derivation_path(
        &derivation_path_internal,
        &Keys::Master(master_keys.clone()),
        network,
        bip,
    );
    let bip32_extended_private_key_for_internal = bip32_extended_keys_for_internal.xpriv;
    let bip32_extended_public_key_for_internal = bip32_extended_keys_for_internal.xpub;

    let should_include_change_addresses = true;
    let found_children = get_bip49_derived_addresses(
        coin_type,
        account,
        should_include_change_addresses,
        &master_keys,
        children_count,
        should_harden,
    );
    let bip49_derivation_path_info =
        get_bip49_derivation_path_info(coin_type, account, &master_keys.clone(), network);

    HDWalletBip49 {
        network,
        bip39_seed,
        master_keys,
        bip32_root_key,
        bip32_root_pub_key,
        master_fingerprint,
        purpose,
        coin_type,
        account,
        // internal: bool,
        account_derivation_path,
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
pub struct HDWalletBip84 {
    network: Network,
    bip39_seed: String,
    master_keys: MasterKeys,
    bip32_root_key: String,
    bip32_root_pub_key: String,
    master_fingerprint: String,
    purpose: i32,
    coin_type: i32,
    account: i32,
    // internal: bool,
    account_derivation_path: String,
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
    pub fn pretty_print_derived_addressed(&self, network: Network) -> () {
        let address_type = AddressType::P2WPKH;
        for (key, value) in self.derived_addresses.clone() {
            let should_compress = true;
            let public_key_hex = match &value {
                Keys::NonMaster(non_master_keys) => non_master_keys.public_key_hex.clone(),
                Keys::Master(master_keys) => master_keys.public_key_hex.clone(),
            };
            let address = value.get_address(network, address_type);
            println!(
                "{} {}  {}   {}    {}      {}",
                key,
                address,
                get_public_key_hash_from_address(&address),
                get_public_key_hash_from_public_key(&public_key_hex),
                public_key_hex,
                value.get_wif(network, should_compress)
            )
        }
    }
}
pub fn generate_bip84_hd_wallet_from_mnemonic_words(
    mnemonic_words: Vec<String>,
    password: Option<String>,
    coin_type: i32,
    account: i32,
    children_count: i32,
    should_harden: bool,
    network: Network,
) -> HDWalletBip84 {
    let bip = Bip::Bip84;
    let purpose = 84;

    let passphrase = match password {
        Some(password) => password,
        None => "".to_string(),
    };
    let bip39_seed = get_bip38_512_bit_private_key(mnemonic_words, Some(passphrase));
    let bip32_root_key = get_bip32_root_key_from_seed(&bip39_seed, network, bip);
    // Notice we have two ways to get the master keys: -------------------------
    // 1) using seed
    let master_keys_generated_from_seed = get_master_keys_from_seed(&bip39_seed);
    // 2) using bip32 root key (extended private master key)
    let master_keys_generated_from_bip32_root_key =
        get_master_keys_from_bip32_root_key(&bip32_root_key);
    let master_keys = master_keys_generated_from_seed;
    // ---------------------------------------------------------------------------
    // Can also get bip32 root key from masterkeys;
    let bip32_root_key = get_bip32_root_key_from_master_keys(&master_keys, network, bip);
    //
    let serialized_extended_master_keys = master_keys.serialize(network, bip);
    let master_fingerprint = create_fingerprint(&master_keys.public_key_hex);

    let bip32_root_pub_key = serialized_extended_master_keys.xpub;
    let account_derivation_path = format!("m/{}'/{}'/{}'", purpose, coin_type, account);
    let derivation_path_external = format!("{}/0", account_derivation_path);
    let bip32_extended_keys_for_external = get_bip32_extended_keys_from_derivation_path(
        &derivation_path_external,
        &Keys::Master(master_keys.clone()),
        network,
        bip,
    );
    let bip32_extended_private_key_for_external = bip32_extended_keys_for_external.xpriv;
    let bip32_extended_public_key_for_external = bip32_extended_keys_for_external.xpub;
    // Change
    let derivation_path_internal = format!("{}/1", account_derivation_path);
    let bip32_extended_keys_for_internal = get_bip32_extended_keys_from_derivation_path(
        &derivation_path_internal,
        &Keys::Master(master_keys.clone()),
        network,
        bip,
    );
    let bip32_extended_private_key_for_internal = bip32_extended_keys_for_internal.xpriv;
    let bip32_extended_public_key_for_internal = bip32_extended_keys_for_internal.xpub;

    let should_include_change_addresses = true;
    let found_children = get_bip84_derived_addresses(
        coin_type,
        account,
        should_include_change_addresses,
        &master_keys,
        children_count,
        should_harden,
    );
    let bip84_derivation_path_info =
        get_bip84_derivation_path_info(coin_type, account, &master_keys.clone(), network);

    HDWalletBip84 {
        network,
        bip39_seed,
        master_keys,
        bip32_root_key,
        bip32_root_pub_key,
        master_fingerprint,
        purpose,
        coin_type,
        account,
        // internal: bool,
        account_derivation_path,
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
#[derive(Debug)]
pub struct HDWalletBip86 {
    network: Network,
    bip39_seed: String,
    master_keys: MasterKeys,
    bip32_root_key: String,
    bip32_root_pub_key: String,
    master_fingerprint: String,
    purpose: i32,
    coin_type: i32,
    account: i32,
    // internal: bool,
    account_derivation_path: String,
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
impl HDWalletBip86 {
    pub fn pretty_print_derived_addressed(&self, network: Network) -> () {
        let address_type = AddressType::P2TR;
        for (key, value) in self.derived_addresses.clone() {
            let should_compress = true;
            let public_key_hex = match &value {
                Keys::NonMaster(non_master_keys) => non_master_keys.public_key_hex.clone(),
                Keys::Master(master_keys) => master_keys.public_key_hex.clone(),
            };
            let address = value.get_address(network, address_type);
            println!(
                "{} {}  {}    {}      {}",
                key,
                address,
                // get_public_key_hash_from_address(&address),
                get_public_key_hash_from_public_key(&public_key_hex),
                public_key_hex,
                value.get_wif(network, should_compress)
            )
        }
    }
}
pub fn generate_bip86_hd_wallet_from_mnemonic_words(
    mnemonic_words: Vec<String>,
    password: Option<String>,
    coin_type: i32,
    account: i32,
    children_count: i32,
    should_harden: bool,
    network: Network,
) -> HDWalletBip86 {
    let bip = Bip::Bip86;
    let purpose = 86;

    let passphrase = match password {
        Some(password) => password,
        None => "".to_string(),
    };
    let bip39_seed = get_bip38_512_bit_private_key(mnemonic_words, Some(passphrase));
    let bip32_root_key = get_bip32_root_key_from_seed(&bip39_seed, network, bip);
    // Notice we have two ways to get the master keys: -------------------------
    // 1) using seed
    let master_keys_generated_from_seed = get_master_keys_from_seed(&bip39_seed);
    // 2) using bip32 root key (extended private master key)
    let master_keys_generated_from_bip32_root_key =
        get_master_keys_from_bip32_root_key(&bip32_root_key);
    let master_keys = master_keys_generated_from_seed;
    // ---------------------------------------------------------------------------
    // Can also get bip32 root key from masterkeys;
    let bip32_root_key = get_bip32_root_key_from_master_keys(&master_keys, network, bip);
    //
    let serialized_extended_master_keys = master_keys.serialize(network, bip);
    let master_fingerprint = create_fingerprint(&master_keys.public_key_hex);

    let bip32_root_pub_key = serialized_extended_master_keys.xpub;
    let account_derivation_path = format!("m/{}'/{}'/{}'", purpose, coin_type, account);
    let derivation_path_external = format!("{}/0", account_derivation_path);
    let bip32_extended_keys_for_external = get_bip32_extended_keys_from_derivation_path(
        &derivation_path_external,
        &Keys::Master(master_keys.clone()),
        network,
        bip,
    );
    let bip32_extended_private_key_for_external = bip32_extended_keys_for_external.xpriv;
    let bip32_extended_public_key_for_external = bip32_extended_keys_for_external.xpub;
    // Change
    let derivation_path_internal = format!("{}/1", account_derivation_path);
    let bip32_extended_keys_for_internal = get_bip32_extended_keys_from_derivation_path(
        &derivation_path_internal,
        &Keys::Master(master_keys.clone()),
        network,
        bip,
    );
    let bip32_extended_private_key_for_internal = bip32_extended_keys_for_internal.xpriv;
    let bip32_extended_public_key_for_internal = bip32_extended_keys_for_internal.xpub;

    let should_include_change_addresses = true;
    let found_children = get_bip86_derived_addresses(
        coin_type,
        account,
        should_include_change_addresses,
        &master_keys,
        children_count,
        should_harden,
    );
    let bip86_derivation_path_info =
        get_bip86_derivation_path_info(coin_type, account, &master_keys.clone(), network);

    HDWalletBip86 {
        network,
        bip39_seed,
        master_keys,
        bip32_root_key,
        bip32_root_pub_key,
        master_fingerprint,
        purpose,
        coin_type,
        account,
        // internal: bool,
        account_derivation_path,
        account_extended_private_key: bip86_derivation_path_info.account_extended_private_key,
        account_extended_public_key: bip86_derivation_path_info.account_extended_public_key,
        derivation_path_external,
        bip32_extended_private_key_for_external,
        bip32_extended_public_key_for_external,
        derivation_path_internal,
        bip32_extended_private_key_for_internal,
        bip32_extended_public_key_for_internal,
        derived_addresses: found_children,
    }
}
pub fn generate_bip141_hd_wallet_from_mnemonic_words() {
    todo!("Need to implement: https://iancoleman.io/bip39/");
}
