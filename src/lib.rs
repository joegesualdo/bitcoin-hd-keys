use std::collections::HashMap;
use std::fmt::Write;
use std::num::{NonZeroU32, ParseIntError};
use std::str::FromStr;
mod bip39;

use bip39::WORDS;
use bitcoin::hashes::{ripemd160, Hash};
use bitcoin::util::base58::check_encode_slice;
use bitcoin::util::base58::from_check;
use bitcoin_bech32::{u5, WitnessProgram};
use hmac_sha512::HMAC;
use num_bigint::BigUint;
use rand::{thread_rng, RngCore};
use ring::{digest, pbkdf2};
use secp256k1::{Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

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
#[derive(Debug, Clone, Copy)]
pub enum Network {
    Mainnet,
    Testnet,
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

fn convert_decimal_to_32_byte_hex_with(num: u32) -> String {
    format!("{:08x}", num)
}
fn convert_decimal_to_8_byte_hex_with(num: u8) -> String {
    format!("{:02x}", num)
}
fn convert_hex_to_decimal(hex: &str) -> Result<i64, ParseIntError> {
    let z = i64::from_str_radix(hex, 16);
    z
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn concat_u8(first: &[u8], second: &[u8]) -> Vec<u8> {
    [first, second].concat()
}

// Notes
// - A hexidecimal is represetnted by only 4 bits (one byte). We use u8 here because we can't use a
// u4.
// - Check work here: https://iancoleman.io/bip39/
// - https://bitcoin.stackexchange.com/questions/89814/how-does-bip-39-mnemonic-work

fn get_hex_string_from_entropy_byte_array(entropy_byte_array: &[u8]) -> String {
    // Use that array to then create a length 32 array but with hexidecimal values, since we want
    // each item of the array to represent only 4 bits, which is how many bits a hex represents
    let entropy_array_with_base_16_numbers: Vec<u8> =
        entropy_byte_array.iter().map(|num| num % 16).collect();
    // turn hex byte array into hex string
    let hex_string = entropy_array_with_base_16_numbers
        .iter()
        .map(|byte| format!("{:x}", byte))
        .collect::<String>();
    hex_string
}

fn sha256_entropy_hex_byte_array(hex_byte_array: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(&hex_byte_array);
    // read hash digest and consume hasher
    let sha256_result = hasher.finalize();
    sha256_result.to_vec()
}
fn convert_to_binary_string(num: u8, bits_to_show_count: u64) -> String {
    fn crop_letters(s: &str, pos: usize) -> &str {
        match s.char_indices().skip(pos).next() {
            Some((pos, _)) => &s[pos..],
            None => "",
        }
    }
    fn format_binary_with_4_bits(num: u8) -> String {
        // The 06 pads with zeros to a width of 6. That width includes 0b (length=2)
        format!("{:#06b}", num)
    }
    fn format_binary_with_8_bits(num: u8) -> String {
        // The 10 pads with zeros to a width of 10. That width includes 0b (length=2)
        format!("{:#010b}", num)
    }
    let binary_string_with_prefix = match bits_to_show_count {
        4 => format_binary_with_4_bits(num),
        8 => format_binary_with_8_bits(num),
        _ => panic!(
            "binary_string_without_prefix: bits_to_show_count of {} not supported",
            bits_to_show_count
        ),
    };
    let binary_string_without_prefix = crop_letters(&binary_string_with_prefix, 2);
    binary_string_without_prefix.to_string()
}

fn get_binary_string_for_byte_array(byte_array: &Vec<u8>) -> String {
    let mut binary_string = String::new();
    for i in byte_array {
        let binary_str = convert_to_binary_string(*i, 8);
        binary_string.push_str(binary_str.as_str())
    }
    binary_string
}
fn split_string_with_spaces_for_substrings_with_length(s: &str, length: u64) -> String {
    let string_with_spaces_seperating_substrings =
        s.chars().enumerate().fold(String::new(), |acc, (i, c)| {
            //if i != 0 && i == 11 {
            if i != 0 && (i % length as usize == 0) {
                format!("{} {}", acc, c)
            } else {
                format!("{}{}", acc, c)
            }
        });
    string_with_spaces_seperating_substrings
}

fn split_binary_string_into_framents_of_11_bits(binary_string: &str) -> Vec<String> {
    let entropy_plus_checksum_binary_with_spaces_seperating =
        split_string_with_spaces_for_substrings_with_length(&binary_string, 11);
    let word_binary: Vec<&str> = entropy_plus_checksum_binary_with_spaces_seperating
        .split(" ")
        .collect();
    word_binary.iter().map(|&s| s.to_string()).collect()
}
fn split_binary_string_into_framents_of_5_bits(binary_string: &str) -> Vec<String> {
    let entropy_plus_checksum_binary_with_spaces_seperating =
        split_string_with_spaces_for_substrings_with_length(&binary_string, 5);
    let word_binary: Vec<&str> = entropy_plus_checksum_binary_with_spaces_seperating
        .split(" ")
        .collect();
    word_binary.iter().map(|&s| s.to_string()).collect()
}

fn convert_binary_to_int(binary_string: &str) -> isize {
    let bin_idx = binary_string;
    let intval = isize::from_str_radix(bin_idx, 2).unwrap();
    intval
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
}
pub fn create_fingerprint(public_key_hex: &String) -> String {
    let hex_byte_array = decode_hex(&public_key_hex).unwrap();
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(&hex_byte_array);
    // read hash digest and consume hasher
    let sha256_result = hasher.finalize();
    let sha256_result_array = sha256_result.to_vec();

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

    fn hash256(hex: &String) -> String {
        let hex_byte_array = decode_hex(&hex).unwrap();
        let mut hasher = Sha256::new();
        // write input message
        hasher.update(&hex_byte_array);
        // read hash digest and consume hasher
        let sha256_result = hasher.finalize();
        let sha256_result_array = sha256_result.to_vec();

        let hex_byte_array_2 = sha256_result_array;
        let mut hasher_2 = Sha256::new();
        // write input message
        hasher_2.update(&hex_byte_array_2);
        // read hash digest and consume hasher
        let sha256_result_2 = hasher_2.finalize();
        let sha256_result_array_2 = sha256_result_2.to_vec();
        encode_hex(&sha256_result_array_2)
    }
    fn checksum(hex: &String) -> String {
        let hash = hash256(&hex);
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
        Bip::Bip84 => {
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

    let depth = convert_decimal_to_8_byte_hex_with(depth.unwrap_or(0));
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
    let child_number = convert_decimal_to_32_byte_hex_with(child_index_with_hardened_factored_in);
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
    parent_private_key: &[u8],
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
    let sk = secp256k1::SecretKey::from_slice(left).expect("statistically impossible to hit");
    let parent_private_secret_key = SecretKey::from_str(&encode_hex(parent_private_key)).unwrap();

    let tweaked = sk
        .add_tweak(&parent_private_secret_key.into())
        .expect("statistically impossible to hit");

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
fn get_compressed_public_key_from_private_key(private_key: &str) -> String {
    // Create 512 bit public key
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_str(private_key).unwrap();
    // We're getting the NEWER compressed version of the public key:
    //    Source: https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    let public_key_uncompressed = secret_key.public_key(&secp).serialize();
    encode_hex(&public_key_uncompressed)
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

fn get_wif_from_private_key(
    private_key: &String,
    network: Network,
    should_compress: bool,
) -> String {
    // 0x80 is used for the version/application byte
    // https://river.com/learn/terms/w/wallet-import-format-wif/#:~:text=WIF%20format%20adds%20a%20prefix,should%20use%20compressed%20SEC%20format.
    let version_application_byte_for_mainnet = "80";
    let version_application_byte_for_testnet = "ef";

    let version_application_byte = match network {
        Network::Mainnet => version_application_byte_for_mainnet,
        Network::Testnet => version_application_byte_for_testnet,
    };

    let private_key_hex = decode_hex(&private_key).unwrap();
    let version_array = decode_hex(version_application_byte).unwrap();
    // What does check encodings do?
    //   - does a sha25 twice, then gets the first 4 bytes of that Result
    //   - takes those first four bites and appends them to the original (version + hex array)
    //   - Read "Ecoding a private key" section here: https://en.bitcoin.it/wiki/Base58Check_encoding
    let end = "01";
    let end_array = decode_hex(end).unwrap();
    let combined_version_and_private_key_hex = concat_u8(&version_array, &private_key_hex);
    let combined_version_and_private_key_hex_with_end_array = if should_compress {
        concat_u8(&combined_version_and_private_key_hex, &end_array)
    } else {
        combined_version_and_private_key_hex
    };
    // TODO: THIS IS ONLY FOR COMPRESSED. How would we do uncompressed?
    let wif_private_key = check_encode_slice(&combined_version_and_private_key_hex_with_end_array);
    wif_private_key
}

#[derive(Copy, Clone)]
pub enum AddressType {
    P2PKH,
    P2SH,
    Bech32,
}

fn get_p2sh_address_from_pubkey_hash(public_key_hash: &String, network: Network) -> String {
    // https://bitcoin.stackexchange.com/questions/75910/how-to-generate-a-native-segwit-address-and-p2sh-segwit-address-from-a-standard
    let prefix_bytes = decode_hex("0014").unwrap();
    let public_key_hash_bytes = decode_hex(public_key_hash).unwrap();
    let redeem_script = concat_u8(&prefix_bytes, &public_key_hash_bytes);
    let redeem_script_sha256 = sha256::digest_bytes(&redeem_script);
    let redeem_script_sha256_as_hex_array = decode_hex(&redeem_script_sha256).unwrap();
    let redeem_script_ripemd160 = ripemd160::Hash::hash(&redeem_script_sha256_as_hex_array);
    let hash160 = redeem_script_ripemd160.to_string();
    let hash160_bytes = decode_hex(&hash160).unwrap();
    let p2sh_version_application_byte = "05";
    let p2sh_testnet_version_application_byte = "c4";
    let version_byte = match network {
        Network::Mainnet => decode_hex(p2sh_version_application_byte).unwrap(),
        Network::Testnet => decode_hex(p2sh_testnet_version_application_byte).unwrap(),
    };
    let hash160_with_version_byte = concat_u8(&version_byte, &hash160_bytes);
    let address = check_encode_slice(&hash160_with_version_byte);
    address
}
fn get_p2pkh_address_from_pubkey_hash(public_key_hash: &String, network: Network) -> String {
    // SEE ALL VERSION APPLICATION CODES HERE: https://en.bitcoin.it/wiki/List_of_address_prefixes
    // TODO: ALL ALL TYPES OF ADDRESSES
    let p2pkh_version_application_byte = "00";
    let p2pkh_testnet_version_application_byte = "6f";

    let version_application_byte = match network {
        Network::Mainnet => p2pkh_version_application_byte,
        Network::Testnet => p2pkh_testnet_version_application_byte,
    };
    // AddressType::P2SH => match network {
    //     Network::Mainnet => p2sh_version_application_byte,
    //     Network::Testnet => p2sh_testnet_version_application_byte,
    // },

    // let hex_array = Vec::from_hex(public_key_hash).unwrap();
    let hex_array = decode_hex(&public_key_hash).unwrap();
    let version_array = decode_hex(version_application_byte).unwrap();
    let a = concat_u8(&version_array, &hex_array);
    // What does check encodings do?
    //   - does a sha25 twice, then gets the first 4 bytes of that Result
    //   - takes those first four bites and appends them to the original (version + hex array)
    //   - Read "Encoding a bitcoin address": https://en.bitcoin.it/wiki/Base58Check_encoding
    let address = check_encode_slice(&a);
    address
}
fn get_address_from_pub_key_hash(
    public_key_hash: &String,
    network: Network,
    address_type: AddressType,
) -> String {
    match address_type {
        AddressType::P2PKH => get_p2pkh_address_from_pubkey_hash(public_key_hash, network),
        AddressType::P2SH => get_p2sh_address_from_pubkey_hash(public_key_hash, network),
        AddressType::Bech32 => get_bech_32_address_from_pubkey_hash(public_key_hash, network),
    }
}

fn get_bech_32_address_from_pubkey_hash(pub_key_hash: &String, network: Network) -> String {
    // Helpful to check: https://slowli.github.io/bech32-buffer/
    // Current version is 00
    // Source: https://en.bitcoin.it/wiki/Bech32
    let witness_version = 0;
    let byte_array = decode_hex(&pub_key_hash).unwrap();
    // TODO: Implement the conversion from public_key to bech32 myself
    // We're using an external library
    let network_for_bech32_library = match network {
        Network::Mainnet => bitcoin_bech32::constants::Network::Bitcoin,
        Network::Testnet => bitcoin_bech32::constants::Network::Testnet,
    };
    let witness_program = WitnessProgram::new(
        u5::try_from_u8(witness_version).unwrap(),
        byte_array,
        network_for_bech32_library,
    )
    .unwrap();

    let address = witness_program.to_address();
    address
}

fn get_address_from_pub_key(
    pub_key: &String,
    network: Network,
    address_type: AddressType,
) -> String {
    let pub_key_hash = get_public_key_hash(&pub_key);

    let address = get_address_from_pub_key_hash(&pub_key_hash, network, address_type);
    return address;
}

fn get_public_key_from_wif(wif: &String) -> String {
    // Check: https://coinb.in/#verify
    let private_key = convert_wif_to_private_key(&wif);
    let public_key = get_public_key_from_private_key(&private_key, is_wif_compressed(&wif));
    public_key
}

fn binary_to_hex(b: &str) -> Option<&str> {
    match b {
        "0000" => Some("0"),
        "0001" => Some("1"),
        "0010" => Some("2"),
        "0011" => Some("3"),
        "0100" => Some("4"),
        "0101" => Some("5"),
        "0110" => Some("6"),
        "0111" => Some("7"),
        "1000" => Some("8"),
        "1001" => Some("9"),
        "1010" => Some("A"),
        "1011" => Some("B"),
        "1100" => Some("C"),
        "1101" => Some("D"),
        "1110" => Some("E"),
        "1111" => Some("F"),
        _ => None,
    }
}
fn convert_string_to_hex(s: &String) -> String {
    let wif_bytes = s.as_bytes();
    let binary = get_binary_string_for_byte_array(&wif_bytes.to_vec());

    let mut s = String::new();
    let mut b = String::new();
    for byte in wif_bytes {
        let binary_string = convert_to_binary_string(*byte, 8);

        let first_4_binary = &binary_string[0..=3];
        let first_4_hex = binary_to_hex(first_4_binary).unwrap();
        let last_4_binary = &binary_string[4..=7];
        let last_4_hex = binary_to_hex(last_4_binary).unwrap();
        let to_p = format!("{}{}", first_4_hex, last_4_hex);

        s.push_str(&to_p);
    }
    s
}
fn decode_binary(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(9)
        .map(|i| u8::from_str_radix(&s[i..i + 8], 2))
        .collect()
}
fn is_wif_compressed(wif: &String) -> bool {
    // Source:https://en.bitcoin.it/wiki/Wallet_import_format
    let first_char_of_wif = wif.chars().nth(0).unwrap();
    let is_compressed_wif = first_char_of_wif == 'K'
        || first_char_of_wif == 'L'
        || first_char_of_wif == 'M'
        || first_char_of_wif == 'c';
    is_compressed_wif
}
fn get_public_key_from_private_key(private_key: &String, is_compressed: bool) -> String {
    // Create 512 bit public key
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_str(private_key).unwrap();
    // We're getting the OLDER uncompressed version of the public key:
    //    Source: https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    let public_key = if is_compressed {
        secret_key.public_key(&secp).serialize().to_vec()
    } else {
        secret_key
            .public_key(&secp)
            .serialize_uncompressed()
            .to_vec()
    };
    encode_hex(&public_key)
}
fn get_public_key_hash(public_key: &String) -> String {
    let hex_array = decode_hex(public_key).unwrap();
    let public_key_sha256 = sha256::digest_bytes(&hex_array);
    let public_key_sha256_as_hex_array = decode_hex(&public_key_sha256).unwrap();
    let public_key_ripemd160 = ripemd160::Hash::hash(&public_key_sha256_as_hex_array);
    public_key_ripemd160.to_string()
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
    let entropy_hex_string = get_hex_string_from_entropy_byte_array(&entropy);

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
pub fn convert_wif_to_private_key(wif: &String) -> String {
    // Check: https://coinb.in/#verify
    // Source:https://en.bitcoin.it/wiki/Wallet_import_format
    // 1. decode the base58check

    let is_compressed_wif = is_wif_compressed(wif);
    let wif_base58check_decoded_result = from_check(&wif);
    let wif_base58check_decoded = from_check(&wif).unwrap();
    // 2. drop the fist byte
    // TODO: It's more complicated than this: "Drop the first byte (it should be 0x80, however
    // legacy Electrum[1][2] or some SegWit vanity address generators[3] may use 0x81-0x87). If
    // the private key corresponded to a compressed public key, also drop the last byte (it
    // should be 0x01). If it corresponded to a compressed public key, the WIF string will have
    // started with K or L (or M, if it's exported from legacy Electrum[1][2] etc[3]) instead
    // of 5 (or c instead of 9 on testnet). This is the private key."
    // Source: https://en.bitcoin.it/wiki/Wallet_import_format
    let wif_base58check_decoded_without_first_byte = wif_base58check_decoded.get(1..).unwrap();
    let wif_base58check_decoded_without_first_byte_and_adjusted_for_compression =
        if is_compressed_wif {
            wif_base58check_decoded_without_first_byte
                .get(..=(wif_base58check_decoded_without_first_byte.len() - 2))
                .unwrap()
        } else {
            wif_base58check_decoded_without_first_byte
        };
    let wif_base58check_decoded_without_first_byte_and_adjusted_for_compression_hex =
        encode_hex(wif_base58check_decoded_without_first_byte_and_adjusted_for_compression);
    wif_base58check_decoded_without_first_byte_and_adjusted_for_compression_hex
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
            println!(
                "{} {}     {}          {}",
                key,
                value.get_address(network, address_type),
                get_public_key_hash(&public_key_hex),
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
        let address_type = AddressType::Bech32;
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
pub fn generate_bip141_hd_wallet_from_mnemonic_words() {
    todo!("Need to implement: https://iancoleman.io/bip39/");
}
