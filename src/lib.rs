use std::collections::HashMap;
// Resources:
// - https://bitcoin.stackexchange.com/questions/89814/how-does&-bip-39-mnemonic-work
// - https://learnmeabitcoin.com/technical/extended-keys
// - https://learnmeabitcoin.com/technical/hd-wallets
// - https://learnmeabitcoin.com/technical/mnemonic
// - https://iancoleman.io/bip39/
// - https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
// - https://bitcoinbriefly.com/ultimate-guide-to-bitcoin-wallets-seeds-private-keys-public-keys-and-addresses/
// - https://rust-lang-nursery.github.io/rust-cookbook/cryptography/encryption.html
// - https://www.liavaag.org/English/SHA-Generator/HMAC/
// - https://bitcointalk.org/index.php?topic=5288888.0
// - https://medium.com/mycrypto/the-journey-from-mnemonic-phrase-to-address-6c5e86e11e14
// - https://academy.bit2me.com/en/que-es-la-master-private-key/
// - https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/bip32.rs
// - https://docs.rs/secp256k1/latest/secp256k1/#functions
// - https://bitcoin.stackexchange.com/questions/61660/how-can-extended-public-keys-generate-child-public-keys-without-generating-the-c
// - https://medium.com/@robbiehanson15/the-math-behind-bip-32-child-key-derivation-7d85f61a6681
// - https://andrea.corbellini.name/ecc/interactive/modk-add.html
// - https://en.bitcoin.it/wiki/Secp256k2
// - https://www.rapidtables.com/convert/number/binary-to-hex.html
// - https://privatekeys.pw/calc
// SOURCES GOOD FOR TESTING:
// - https://iancoleman.io/bip39/
// - http://bip32.org/
use std::fmt::Write;
use std::num::{NonZeroU32, ParseIntError};
use std::str::FromStr;
pub mod bip39;

use bip39::WORDS;
use bitcoin::hashes::{ripemd160, Hash};
use bitcoin::util::base58::check_encode_slice;
use bitcoin::util::base58::from_check;
use hmac_sha512::HMAC;
use num_bigint::BigUint;
use rand::{thread_rng, RngCore};
use ring::{digest, pbkdf2};
use secp256k1::{Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

pub const IS_TESTNET: bool = true;
pub const HARDENED_DERIVATION_CHARACTER: &str = "'";

#[derive(Debug, Clone)]
pub struct Keys {
    pub private_key_hex: String,
    pub public_key_hex: String,
    pub chain_code_hex: String,
    pub is_hardened: bool,
}
impl Keys {
    pub fn get_wif(&self) -> String {
        get_wif_from_private_key(&self.private_key_hex, IS_TESTNET, true)
    }
    pub fn get_address(&self) -> String {
        get_address_from_pub_key(&self.public_key_hex, IS_TESTNET)
    }
}

pub fn convert_decimal_to_32_byte_hex_with(num: u32) -> String {
    format!("{:08x}", num)
}
pub fn convert_decimal_to_8_byte_hex_with(num: u8) -> String {
    format!("{:02x}", num)
}
pub fn convert_hex_to_decimal(hex: String) -> BigUint {
    let hex = "f9cf43a313496a007fe4fc1c4fb996238b4ace646d7ada0c1ffbf37653b991e9";
    // let hex = "7e48c5ab7f43e4d9c17bd9712627dcc76d4df2099af7c8e5";
    // let a: BigInt = 13083591726159223555551223938753535127604258367126228576140903598401097365714201702017529413442114868104244686915389844693808367317716621188940830798420643;
    let z = hex.parse::<BigUint>().unwrap();

    // let z = BigUint::from_str(&hex, 16);
    z
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn concat_u8(first: &[u8], second: &[u8]) -> Vec<u8> {
    [first, second].concat()
}

// Notes
// - A hexidecimal is represetnted by only 4 bits (one byte). We use u8 here because we can't use a
// u4.
// - Check work here: https://iancoleman.io/bip39/
// - https://bitcoin.stackexchange.com/questions/89814/how-does-bip-39-mnemonic-work

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

pub fn get_hex_string_from_entropy_byte_array(entropy_byte_array: &[u8]) -> String {
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

pub fn sha256_entropy_hex_byte_array(hex_byte_array: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(&hex_byte_array);
    // read hash digest and consume hasher
    let sha256_result = hasher.finalize();
    sha256_result.to_vec()
}
pub fn convert_to_binary_string(num: u8, bits_to_show_count: u64) -> String {
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

pub fn get_binary_string_for_byte_array(byte_array: &Vec<u8>) -> String {
    let mut binary_string = String::new();
    for i in byte_array {
        let binary_str = convert_to_binary_string(*i, 8);
        binary_string.push_str(binary_str.as_str())
    }
    binary_string
}
pub fn split_string_with_spaces_for_substrings_with_length(s: &str, length: u64) -> String {
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

pub fn split_binary_string_into_framents_of_11_bits(binary_string: &str) -> Vec<String> {
    let entropy_plus_checksum_binary_with_spaces_seperating =
        split_string_with_spaces_for_substrings_with_length(&binary_string, 11);
    let word_binary: Vec<&str> = entropy_plus_checksum_binary_with_spaces_seperating
        .split(" ")
        .collect();
    word_binary.iter().map(|&s| s.to_string()).collect()
}

pub fn convert_binary_to_int(binary_string: &str) -> isize {
    let bin_idx = binary_string;
    let intval = isize::from_str_radix(bin_idx, 2).unwrap();
    intval
}

pub struct SerializeKeyArgs {
    pub child_keys: Keys,
    pub parent_public_key: Option<String>,
    pub is_public: bool,
    pub is_testnet: bool,
    pub depth: Option<u8>,
    pub child_index: u32,
}

pub fn serialize_key(args: SerializeKeyArgs) -> String {
    let SerializeKeyArgs {
        child_keys,
        parent_public_key,
        is_public,
        is_testnet,
        depth,
        child_index,
    } = args;
    fn create_fingerprint(parent_public_key_hex: String) -> String {
        let hex_byte_array = decode_hex(&parent_public_key_hex).unwrap();
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

    // TODO: Add all versions!
    // List of all the version possibilities: https://electrum.readthedocs.io/en/latest/xpub_version_bytes.html
    let version = if is_public {
        if is_testnet {
            "043587cf"
        } else {
            "0488b21e"
        }
    } else {
        if is_testnet {
            "04358394"
        } else {
            "0488ade4"
        }
    };
    let key = if is_public {
        format!("{}", child_keys.public_key_hex)
    } else {
        format!("{}{}", "00", child_keys.private_key_hex)
    };

    let depth = convert_decimal_to_8_byte_hex_with(depth.unwrap_or(0));
    let parent_fingerprint = match &parent_public_key {
        Some(parent_public_key) => create_fingerprint(parent_public_key.to_string()),
        None => "00000000".to_string(),
    };
    // for child
    // let parent_fingerprint = create_fingerprint(parent_public_key.to_string());
    // TODO: How do we do children at other indexes other than 0. Like 1.
    let child_index_with_hardened_factored_in = if child_keys.is_hardened {
        child_index + 2147483648 // # child index number (must between 2**31 and 2**32-1)
    } else {
        child_index
    };
    let child_number = convert_decimal_to_32_byte_hex_with(child_index_with_hardened_factored_in);
    let chain_code = child_keys.chain_code_hex;
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

pub fn get_child_extended_public_key(
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
pub fn get_compressed_public_key_from_private_key(private_key: &str) -> String {
    // Create 512 bit public key
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_str(private_key).unwrap();
    // We're getting the NEWER compressed version of the public key:
    //    Source: https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    let public_key_uncompressed = secret_key.public_key(&secp).serialize();
    encode_hex(&public_key_uncompressed)
}
pub fn get_hardened_child_extended_private_key(
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
    let keys = Keys {
        private_key_hex: child_private_key,
        public_key_hex: child_public_key,
        chain_code_hex: child_chain_code,
        is_hardened: true,
    };
    keys
}
pub fn get_child_extended_private_key(
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
    let keys = Keys {
        private_key_hex: child_private_key,
        public_key_hex: child_public_key,
        chain_code_hex: child_chain_code,
        is_hardened: false,
    };
    keys
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
pub fn get_bip38_512_bit_private_key(words: Vec<String>, passphrase: Option<String>) -> String {
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
pub fn get_master_keys_from_seed(bip39_seed: String) -> Keys {
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
    let keys = Keys {
        public_key_hex: master_public_key,
        private_key_hex: master_private_key_hex,
        chain_code_hex: encode_hex(master_chain_code),
        // TODO: Is this correct? Is there a way to harden master keys?
        is_hardened: false,
    };
    keys
}

#[derive(Debug)]
pub enum DerivationChild {
    NonHardened(u32),
    Hardened(u32),
}

pub fn parse_derivation_path_child(derivation_path_child: &String) -> DerivationChild {
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
pub fn get_child_index_from_derivation_path(derivation_path: &String) -> DerivationChild {
    let derivation_path_split_by_dash: Vec<&str> = derivation_path.split('/').collect();
    let first = derivation_path_split_by_dash.first().unwrap();
    if first.to_string() != "m" {
        panic!("derivation must start with m")
    } else {
        let last_item = derivation_path_split_by_dash.last().unwrap().to_string();
        parse_derivation_path_child(&last_item)
    }
}

pub fn split_derivation_path(derivation_path: String) -> Vec<String> {
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

pub fn get_child_key_from_derivation_path(derivation_path: String, master_keys: Keys) -> Keys {
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
pub fn get_children_keys_from_derivation_path(
    derivation_path: &String,
    master_keys: Keys,
    children_count: i32,
    should_be_hardened: bool,
) -> HashMap<String, Keys> {
    let child_key = get_child_key_from_derivation_path(derivation_path.to_string(), master_keys);
    let child_keys = get_child_keys(&child_key, children_count, should_be_hardened);
    child_keys
}
pub fn get_child_key(parent_keys: &Keys, child_index: i32, should_harden: bool) -> Keys {
    let parent_chain_code_bytes = decode_hex(&parent_keys.chain_code_hex).unwrap();
    let parent_private_key_bytes = decode_hex(&parent_keys.private_key_hex).unwrap();
    if should_harden {
        get_hardened_child_extended_private_key(
            &parent_chain_code_bytes,
            &parent_private_key_bytes,
            child_index as u32,
        )
    } else {
        get_child_extended_private_key(
            &parent_chain_code_bytes,
            &parent_keys.public_key_hex.clone(),
            &parent_private_key_bytes,
            child_index as i32,
        )
    }
}
pub fn get_child_keys(
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

pub fn print_child_keys(parent_keys: Keys, children_count: i32) {
    // ============================= Normal Child extended private key ====================
    let parent_chain_code_bytes = decode_hex(&parent_keys.chain_code_hex).unwrap();
    let parent_private_key_bytes = decode_hex(&parent_keys.private_key_hex).unwrap();
    for child_index in 0..=children_count {
        let child_keys = get_child_extended_private_key(
            &parent_chain_code_bytes,
            &parent_keys.public_key_hex.clone(),
            &parent_private_key_bytes,
            child_index,
        );

        println!("{} wif!!: {}", child_index, child_keys.get_wif(),);

        println!("{} address: {}", child_index, child_keys.get_address(),);
        let parent_public_key = parent_keys.public_key_hex.clone();

        let xpub = serialize_key(SerializeKeyArgs {
            child_keys: child_keys.clone(),
            parent_public_key: Some(parent_public_key.clone()),
            is_public: true,
            is_testnet: IS_TESTNET,
            depth: Some(1),
            child_index: child_index as u32,
        });
        let xprv = serialize_key(SerializeKeyArgs {
            child_keys: child_keys.clone(),
            parent_public_key: Some(parent_public_key),
            is_public: false,
            is_testnet: IS_TESTNET,
            depth: Some(1),
            child_index: child_index as u32,
        });
        println!("{} xpub: {}", child_index, xpub);
        println!("{} xprv: {}", child_index, xprv);
        println!("-------------------------------");
    }

    println!("===============================================");

    for child_index in 0..=children_count {
        // ============================= HARDENED Child extended private key ====================
        let child_keys_hardened = get_hardened_child_extended_private_key(
            &parent_chain_code_bytes,
            &parent_private_key_bytes,
            child_index as u32,
        );
        println!("{}': {:#?}", child_index, child_keys_hardened);
        println!("{}' wif!!: {}", child_index, child_keys_hardened.get_wif());

        println!(
            "{}' address: {}",
            child_index,
            child_keys_hardened.get_address()
        );
        let parent_public_key = parent_keys.public_key_hex.clone();

        let xpub = serialize_key(SerializeKeyArgs {
            child_keys: child_keys_hardened.clone(),
            parent_public_key: Some(parent_public_key.clone()),
            is_public: true,
            is_testnet: IS_TESTNET,
            depth: Some(1),
            child_index: child_index as u32,
        });
        let xprv = serialize_key(SerializeKeyArgs {
            child_keys: child_keys_hardened.clone(),
            parent_public_key: Some(parent_public_key),
            is_public: false,
            is_testnet: IS_TESTNET,
            depth: Some(1),
            child_index: child_index as u32,
        });
        println!("{}' xpub: {}", child_index, xpub);
        println!("{}' xprv: {}", child_index, xprv);
        println!("-------------------------------");

        // ============================= NORMAL Child extended public key ====================
    }
}
pub fn get_wif_from_private_key(
    private_key: &String,
    testnet: bool,
    should_compress: bool,
) -> String {
    // 0x80 is used for the version/application byte
    // https://river.com/learn/terms/w/wallet-import-format-wif/#:~:text=WIF%20format%20adds%20a%20prefix,should%20use%20compressed%20SEC%20format.
    let version_application_byte_for_mainnet = "80";
    let version_application_byte_for_testnet = "ef";

    let version_application_byte = if testnet {
        version_application_byte_for_testnet
    } else {
        version_application_byte_for_mainnet
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
pub fn get_address_from_pub_key_hash(public_key_hash: &String, is_testnet: bool) -> String {
    // SEE ALL VERSION APPLICATION CODES HERE: https://en.bitcoin.it/wiki/List_of_address_prefixes
    let p2pkh_version_application_byte = "00";
    let p2pkh_testnet_version_application_byte = "6f";
    let p2sh_version_application_byte = "05";

    let version_application_byte = if is_testnet {
        p2pkh_testnet_version_application_byte
    } else {
        p2pkh_version_application_byte
    };
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

pub fn get_address_from_pub_key(pub_key: &String, is_testnet: bool) -> String {
    let pub_key_hash = get_public_key_hash(pub_key);
    let address = get_address_from_pub_key_hash(&pub_key_hash, is_testnet);
    return address;
}

pub fn get_public_key_from_wif(wif: &String) -> String {
    // Check: https://coinb.in/#verify
    let private_key = convert_wif_to_private_key(&wif);
    let public_key = get_public_key_from_private_key(&private_key, is_wif_compressed(&wif));
    public_key
}

pub fn binary_to_hex(b: &str) -> Option<&str> {
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
pub fn convert_string_to_hex(s: &String) -> String {
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
pub fn decode_binary(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(9)
        .map(|i| u8::from_str_radix(&s[i..i + 8], 2))
        .collect()
}
pub fn is_wif_compressed(wif: &String) -> bool {
    // Source:https://en.bitcoin.it/wiki/Wallet_import_format
    let first_char_of_wif = wif.chars().nth(0).unwrap();
    let is_compressed_wif = first_char_of_wif == 'K'
        || first_char_of_wif == 'L'
        || first_char_of_wif == 'M'
        || first_char_of_wif == 'c';
    is_compressed_wif
}
pub fn convert_wif_to_private_key(wif: &String) -> String {
    // Check: https://coinb.in/#verify
    // Source:https://en.bitcoin.it/wiki/Wallet_import_format
    // 1. decode the base58check

    let is_compressed_wif = is_wif_compressed(wif);
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
pub fn get_public_key_from_private_key(private_key: &String, is_compressed: bool) -> String {
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
pub fn get_public_key_hash(public_key: &String) -> String {
    let hex_array = decode_hex(public_key).unwrap();
    let public_key_sha256 = sha256::digest_bytes(&hex_array);
    let public_key_sha256_as_hex_array = decode_hex(&public_key_sha256).unwrap();
    let public_key_ripemd160 = ripemd160::Hash::hash(&public_key_sha256_as_hex_array);
    public_key_ripemd160.to_string()
}

pub fn get_depth_from_derivation_path(derivation_path: &String) -> u8 {
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
pub fn get_parent_derivation_path(derivation_path: &String) -> String {
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

pub fn get_extended_keys_from_derivation_path(
    derivation_path: &String,
    master_keys: &Keys,
) -> (String, String) {
    let parent_deviation_path = get_parent_derivation_path(derivation_path);
    let derivation_child = get_child_index_from_derivation_path(derivation_path);
    println!("parent_deviation_path: {:?}", parent_deviation_path);
    println!("derivation_child: {:#?}", derivation_child);
    let derivation_child_index = match derivation_child {
        DerivationChild::NonHardened(child_index) => child_index,
        DerivationChild::Hardened(child_index) => child_index,
    };
    println!("derivation_child_index: {:#?}", derivation_child_index);
    let found_child =
        get_child_key_from_derivation_path(derivation_path.to_string(), master_keys.clone());
    println!("found_child: {:?}", found_child);
    println!("wif: {:#?}", found_child.get_wif());
    println!("address: {:#?}", found_child.get_address());
    let parent_keys =
        get_child_key_from_derivation_path(parent_deviation_path, master_keys.clone());
    println!("parent: {:?}", parent_keys);
    println!("wif: {:#?}", parent_keys.get_wif());
    println!("address: {:#?}", parent_keys.get_address());
    let depth = get_depth_from_derivation_path(&derivation_path.to_string());
    println!("depth: {:#?}", depth);

    let bip32_extended_public_key = serialize_key(SerializeKeyArgs {
        child_keys: found_child.clone(),
        parent_public_key: Some(parent_keys.public_key_hex.clone()),
        is_public: true,
        is_testnet: IS_TESTNET,
        depth: Some(depth),
        child_index: derivation_child_index as u32,
    });
    let bip32_extended_private_key = serialize_key(SerializeKeyArgs {
        child_keys: found_child.clone(),
        parent_public_key: Some(parent_keys.public_key_hex.clone()),
        is_public: false,
        is_testnet: IS_TESTNET,
        depth: Some(depth),
        child_index: derivation_child_index as u32,
    });
    (bip32_extended_public_key, bip32_extended_private_key)
}
