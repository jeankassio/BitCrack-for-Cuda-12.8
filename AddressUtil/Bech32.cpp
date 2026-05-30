// Bech32.cpp
//
// Minimal Bech32 / Bech32m decoder used by BitCrack to ingest native segwit
// addresses (BIP-0173 P2WPKH "bc1q..." with a 20-byte program).
//
// Only the subset that BitCrack can actually match is supported:
//   * Witness version 0 + 20-byte program  -> P2WPKH (hash160 of pubkey)
//
// Witness version 1 (taproot, "bc1p...") and other versions/lengths are
// rejected because their on-chain commitment is not RIPEMD160(SHA256(pubkey))
// and therefore cannot be checked with the existing GPU pipeline.
//
// Reference algorithm: https://github.com/sipa/bech32 (Pieter Wuille, MIT).

#include <cstdint>
#include <string>
#include <vector>

#include "AddressUtil.h"

namespace {

const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

int charsetRev(char c)
{
    switch(c) {
        case 'q': return  0; case 'p': return  1; case 'z': return  2; case 'r': return  3;
        case 'y': return  4; case '9': return  5; case 'x': return  6; case '8': return  7;
        case 'g': return  8; case 'f': return  9; case '2': return 10; case 't': return 11;
        case 'v': return 12; case 'd': return 13; case 'w': return 14; case '0': return 15;
        case 's': return 16; case '3': return 17; case 'j': return 18; case 'n': return 19;
        case '5': return 20; case '4': return 21; case 'k': return 22; case 'h': return 23;
        case 'c': return 24; case 'e': return 25; case '6': return 26; case 'm': return 27;
        case 'u': return 28; case 'a': return 29; case '7': return 30; case 'l': return 31;
        default: return -1;
    }
}

uint32_t polymodStep(uint32_t pre)
{
    static const uint32_t G[5] = {
        0x3b6a57b2UL, 0x26508e6dUL, 0x1ea119faUL, 0x3d4233ddUL, 0x2a1462b3UL
    };
    uint8_t b = pre >> 25;
    uint32_t out = (pre & 0x1ffffffUL) << 5;
    for(int i = 0; i < 5; i++) {
        if((b >> i) & 1) out ^= G[i];
    }
    return out;
}

bool decodeBech32(const std::string &str,
                  std::string &hrp,
                  std::vector<uint8_t> &data,
                  bool &isBech32m)
{
    // Length / case rules (BIP-0173).
    if(str.size() < 8 || str.size() > 90) return false;

    bool hasLower = false, hasUpper = false;
    for(char c : str) {
        if(c < 33 || c > 126) return false;
        if(c >= 'a' && c <= 'z') hasLower = true;
        if(c >= 'A' && c <= 'Z') hasUpper = true;
    }
    if(hasLower && hasUpper) return false;

    std::string s;
    s.reserve(str.size());
    for(char c : str) s.push_back((c >= 'A' && c <= 'Z') ? char(c + 32) : c);

    size_t sep = s.rfind('1');
    if(sep == std::string::npos || sep == 0 || sep + 7 > s.size()) return false;

    hrp.assign(s.begin(), s.begin() + sep);

    uint32_t chk = 1;
    for(char c : hrp) chk = polymodStep(chk) ^ (uint8_t(c) >> 5);
    chk = polymodStep(chk);
    for(char c : hrp) chk = polymodStep(chk) ^ (uint8_t(c) & 0x1f);

    data.clear();
    data.reserve(s.size() - sep - 1);
    for(size_t i = sep + 1; i < s.size(); i++) {
        int v = charsetRev(s[i]);
        if(v < 0) return false;
        chk = polymodStep(chk) ^ uint8_t(v);
        if(i + 6 < s.size()) data.push_back(uint8_t(v));
    }

    if(chk == 1) {
        isBech32m = false;
        return true;
    }
    if(chk == 0x2bc830a3UL) {
        isBech32m = true;
        return true;
    }
    return false;
}

// 5-bit -> 8-bit regrouping used to recover the witness program.
bool convert5to8(const std::vector<uint8_t> &in, std::vector<uint8_t> &out)
{
    uint32_t acc = 0;
    int bits = 0;
    out.clear();
    out.reserve((in.size() * 5 + 7) / 8);
    for(uint8_t v : in) {
        if(v >> 5) return false;
        acc = (acc << 5) | v;
        bits += 5;
        while(bits >= 8) {
            bits -= 8;
            out.push_back(uint8_t((acc >> bits) & 0xff));
        }
    }
    // Remaining bits must be zero-padded and shorter than a full group.
    if(bits >= 5) return false;
    if((acc << (8 - bits)) & 0xff) return false;
    return true;
}

} // anonymous namespace

namespace Bech32 {

bool decodeP2WPKH(const std::string &address, unsigned int hash[5])
{
    std::string hrp;
    std::vector<uint8_t> data;
    bool isBech32m = false;

    if(!decodeBech32(address, hrp, data, isBech32m)) return false;

    // Mainnet only. Reject testnet/regtest/signet to avoid false positives in
    // the puzzle/lookup workflow.
    if(hrp != "bc") return false;

    if(data.empty()) return false;

    uint8_t witver = data[0];
    std::vector<uint8_t> prog5(data.begin() + 1, data.end());
    std::vector<uint8_t> prog;
    if(!convert5to8(prog5, prog)) return false;

    // Witness program length / encoding rules (BIP-0350).
    if(witver > 16) return false;
    if(prog.size() < 2 || prog.size() > 40) return false;
    if(witver == 0) {
        if(isBech32m) return false;          // v0 must be plain bech32
        if(prog.size() != 20 && prog.size() != 32) return false;
    } else {
        if(!isBech32m) return false;         // v1+ must be bech32m
    }

    // Only P2WPKH (v0 + 20-byte program) carries a hash160(pubkey) we can
    // brute force with the existing ECDSA/RIPEMD160 kernel.
    if(witver != 0 || prog.size() != 20) return false;

    for(int i = 0; i < 5; i++) {
        hash[i] = (uint32_t(prog[i * 4 + 0]) << 24)
                | (uint32_t(prog[i * 4 + 1]) << 16)
                | (uint32_t(prog[i * 4 + 2]) <<  8)
                | (uint32_t(prog[i * 4 + 3])      );
    }
    return true;
}

bool isBech32Address(const std::string &address)
{
    if(address.size() < 4) return false;
    // Cheap prefix check before running the full decoder.
    char c0 = address[0], c1 = address[1], c2 = address[2], c3 = address[3];
    if((c0 == 'b' || c0 == 'B')
        && (c1 == 'c' || c1 == 'C')
        && c2 == '1'
        && (c3 == 'q' || c3 == 'Q' || c3 == 'p' || c3 == 'P')) {
        return true;
    }
    return false;
}

} // namespace Bech32
