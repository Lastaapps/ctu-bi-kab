#ifndef __PROGTEST__
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

#endif /* __PROGTEST__ */

char bitsToHexaChar(uint8_t bits) {
    if (bits < 10) {
        return '0' + bits;
    } else {
        return 'A' + bits - 10;
    }
}

std::string bitsToHex(const std::vector<uint8_t>& data) {
    std::string hex;
    for (int i = 0; i < data.size(); ++i) {
        const uint8_t byte = data[i];
        hex += bitsToHexaChar(byte / 16);
        hex += bitsToHexaChar(byte % 16);
    }
    return hex;
}

uint8_t hexCharToBin(char ch) {
    if ('0' <= ch && ch <= '9') {
        return ch - '0';
    } else {
        return ch - 'A' + 10;
    }
}
std::vector<uint8_t> hexToBin(char const* hex) {
    std::vector<uint8_t> out;
    bool isOdd = true;
    uint8_t buffer = 0;
    for (;*hex;++hex) {
        if (isOdd) {
            buffer |= hexCharToBin(*hex) << 4;
        } else {
            buffer |= hexCharToBin(*hex);
            out.push_back(buffer);
            buffer = 0;
        }
        isOdd = !isOdd;
    }
    return out;
}

int findHash (int bits, char ** message, char ** hash) {
    /* TODO: Your code here */
}

int findHashEx (int bits, char ** message, char ** hash, const char * hashFunction) {
    if (bits < 0 || bits >= 512) {
        return 0;
    }

    /* TODO or use dummy implementation */
    return 1;
}

#ifndef __PROGTEST__

bool checkHash(int bits, char * hexString) {
    std::vector<uint8_t> data = hexToBin(hexString);

    for (int i = 0; i < bits; ++i) {
        if (data[i / 8] & (1 << (7 - i % 8))) {
            return false;
        }
    }
    return true;
}

int main (void) {

    std::string hex;
    hex = bitsToHex({0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF});
    assert(hex == "0123456789ABCDEF");
    assert(hexToBin("0123456789ABCDEF") == std::vector<uint8_t>({0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}));

    char * message, * hash;
    assert(findHash(0, &message, &hash) == 1);
    assert(message && hash && checkHash(0, hash));
    free(message);
    free(hash);
    assert(findHash(1, &message, &hash) == 1);
    assert(message && hash && checkHash(1, hash));
    free(message);
    free(hash);
    assert(findHash(2, &message, &hash) == 1);
    assert(message && hash && checkHash(2, hash));
    free(message);
    free(hash);
    assert(findHash(3, &message, &hash) == 1);
    assert(message && hash && checkHash(3, hash));
    free(message);
    free(hash);
    assert(findHash(-1, &message, &hash) == 0);
    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */

