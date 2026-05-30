#ifndef _ADDRESS_UTIL_H
#define _ADDRESS_UTIL_H

#include <string>

#include "secp256k1.h"

namespace Address {
	std::string fromPublicKey(const secp256k1::ecpoint &p, bool compressed = false);
	bool verifyAddress(std::string address);

	// Address kinds that share a RIPEMD160(SHA256(pubkey)) commitment and can
	// therefore be matched by the existing GPU pipeline.
	enum class Kind {
		Unsupported = 0,
		P2PKH       = 1,    // base58 "1..."
		P2WPKH      = 2,    // bech32 "bc1q..." (witness v0, 20-byte program)
	};

	// Detect the encoding and, on success, fill `hash` (big-endian words) with
	// the underlying hash160 commitment. Returns Kind::Unsupported for P2SH
	// ("3..."), taproot ("bc1p..."), bech32m v0+ with non-20 byte programs,
	// invalid input, etc.
	Kind toHash160(const std::string &address, unsigned int hash[5]);
};

namespace Base58 {
	std::string toBase58(const secp256k1::uint256 &x);
	secp256k1::uint256 toBigInt(const std::string &s);
	void getMinMaxFromPrefix(const std::string &prefix, secp256k1::uint256 &minValueOut, secp256k1::uint256 &maxValueOut);

	void toHash160(const std::string &s, unsigned int hash[5]);

	bool isBase58(std::string s);
};

namespace Bech32 {
	// Decode a mainnet "bc1q..." native segwit P2WPKH address into hash160.
	// Returns false for non-bech32 input, wrong HRP, wrong witness version,
	// wrong program length, or an invalid checksum.
	bool decodeP2WPKH(const std::string &address, unsigned int hash[5]);

	// Cheap prefix check used to short-circuit non-bech32 input.
	bool isBech32Address(const std::string &address);
};



namespace Hash {


	void hashPublicKey(const secp256k1::ecpoint &p, unsigned int *digest);
	void hashPublicKeyCompressed(const secp256k1::ecpoint &p, unsigned int *digest);

	void hashPublicKey(const unsigned int *x, const unsigned int *y, unsigned int *digest);
	void hashPublicKeyCompressed(const unsigned int *x, const unsigned int *y, unsigned int *digest);

};


#endif