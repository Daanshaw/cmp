# Multi-Party Threshold Signature Benchmarking

This repository contains a modified version of the multi-party threshold signing implementation in Go, originally developed by Adrian Hamelink and Taurus SA, for benchmarking purposes.

The original implementation supports:

- **ECDSA**: Using the "CGGMP" protocol by Canetti et al. for threshold ECDSA signing. The implementation includes both the 4-round "online" and the 7-round "presigning" protocols from the paper. The latter also supports identifiable aborts. Implementation details are documented in `docs/Threshold.pdf`. The original implementation supports ECDSA with secp256k1, with other curves planned for the future.
- **Schnorr signatures**: As integrated in Bitcoin's Taproot, using the FROST protocol. Due to the linear structure of Schnorr signatures, this protocol is less expensive than CMP. The necessary adjustments have been made to make the signatures compatible with Taproot's specific point encoding, as specified in BIP-0340.

## Disclaimer

Use this modified implementation at your own risk, as the original project needs further testing and auditing to be production-ready. The changes made for benchmarking purposes may also affect the behavior or performance of the implementation.

## License

This modified version is based on the code which is copyright (c) Adrian Hamelink and Taurus SA, 2021, and is distributed under the Apache 2.0 license. The original license and copyright notice can be found in the `LICENSE` file in this repository.
