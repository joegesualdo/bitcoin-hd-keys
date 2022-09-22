☠️⚠️ Work In Progress ⚠️☠️
# Bitcoin HD Keys 
> Key generation for Hierarchical-Deterministic (HD) Wallets

## Install
> Add package to Cargo.toml file
```rust
[dependencies]
bitcoin-hd-keys= "0.1.12"
```

## Usage:
```rust
use bitcoin_hd_keys::{
    generate_bip32_hd_wallet_from_mnemonic_words, generate_bip44_hd_wallet_from_mnemonic_words,
    generate_bip49_hd_wallet_from_mnemonic_words, generate_bip84_hd_wallet_from_mnemonic_words,
    get_128_bits_of_entropy, get_mnemonic_words, AddressType, Network,
};

// Generate entropy
let entropy_array = get_128_bits_of_entropy();

// Get mnemonic words from entropy
let mnemonic_words = get_mnemonic_words(entropy_array.to_vec());

// Generate HD Wallet Keys (bip32) from mnemonic words
let bip32_hd_wallet = generate_bip32_hd_wallet_from_mnemonic_words(
	mnemonic_words.clone(),
	None,
	"m/0'/0'".to_string(),
	5,
	true,
	Network::Testnet,
);
println!("{:#?}", bip32_hd_wallet);
bip32_hd_wallet.pretty_print_derived_addressed(Network::Testnet, AddressType::P2PKH);

// Generate Multi-Account Hierarchy HD Keys (bip44) from mnemonic words.
let bip44_hd_wallet = generate_bip44_hd_wallet_from_mnemonic_words(
	mnemonic_words.clone(),
	None,
	0,
	5,
	true,
	Network::Testnet,
);
println!("{:#?}", bip44_hd_wallet);
bip44_hd_wallet.pretty_print_derived_addressed(Network::Testnet, AddressType::P2PKH);

// Generate Derivation scheme for P2WPKH-nested-in-P2SH based accounts HD Keys (bip49) from mnemonic words.
let bip49_hd_wallet = generate_bip49_hd_wallet_from_mnemonic_words(
	mnemonic_words.clone(),
	None,
	0,
	5,
	true,
	Network::Testnet,
);
println!("{:#?}", bip49_hd_wallet);
bip49_hd_wallet.pretty_print_derived_addressed(Network::Testnet, AddressType::P2SH);

// Generate HD Keys using Deterministic Entropy From BIP32 Keychains (bip85) from mnemonic words.
let bip84_hd_wallet = generate_bip84_hd_wallet_from_mnemonic_words(
	mnemonic_words.clone(),
	None,
	0,
	5,
	true,
	Network::Testnet,
);
println!("{:#?}", bip84_hd_wallet);
bip84_hd_wallet.pretty_print_derived_addressed(Network::Testnet, AddressType::Bech32);

```

## Related
- [bitcoin-node-query](https://github.com/joegesualdo/bitcoin-node-query) - Query Bitcoin Node for information
- [bitcoind-request](https://github.com/joegesualdo/bitcoind-request) - Type-safe wrapper around bitcoind RPC commands
- [bitcoin-terminal-dashboard](https://github.com/joegesualdo/bitcoin-terminal-dashboard) - Bitcoin Dashboard in the terminal

## Learn about HD Wallets

To learn more about HD Wallets and explore the resource material that was used to create this packacge, see [Resources.md](./Resources.md)

## License
MIT © [Joe Gesualdo]()
