#include <cstdlib>
#include <openssl/crypto.h>
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

const char * defaultType = "sha512";

int checkBitsZero(int bits, uint8_t * hash) {
    int bytesToCheck = bits / 8;
    int  bitsToCheck = bits % 8;

    for (int i = 0; i < bytesToCheck; ++i) {
        if (*hash != 0) {
            return 0;
        }
        ++hash;
    }

    if (*hash & ((uint8_t)~0u << (8 - bitsToCheck))) {
        return 0;
    }

    return *hash & ((uint8_t)1u << (7 - bitsToCheck));
}

uint8_t * randomMessage() {
    const int initLength = EVP_MAX_MD_SIZE;
    uint8_t * message = (uint8_t*) malloc(initLength);
    RAND_bytes(message, initLength);
    return message;
}

int hashMessage(uint8_t * bytes, uint32_t bytesSize, uint8_t * hash, uint32_t& length, const EVP_MD * type) {
    // Create context for hashing
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        printf("Failed to create the context");
        return 0;
    }

    // context setup for our hash type
    if (!EVP_DigestInit_ex(ctx, type, NULL)) {
        printf("Failed to setup the context");
        return 0;
    }

    // feed the message in
    if (!EVP_DigestUpdate(ctx, bytes, bytesSize)) {
        printf("Failed to update the context");
        return 0;
    }

    // get the hash
    if (!EVP_DigestFinal_ex(ctx, hash, &length)) {
        printf("Failed to fin the context");
        return 0;
    }

    // destroy the context
    EVP_MD_CTX_free(ctx);

    return 1;
}

char * toHex(uint8_t * bytes, uint32_t length) {
    char* str = (char*) malloc(length * 2 + 1);
    const char mapping[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    for (uint32_t i = 0; i < length; ++i) {
        str[i*2]     = mapping[(((uint8_t)~0u << 4) & bytes[i]) >> 4];
        str[i*2 + 1] = mapping[(((uint8_t)~0u >> 4) & bytes[i]) << 0];
    }
    str[length * 2] = '\0';

    // size_t strLen;
    // OPENSSL_buf2hexstr_ex(str, length * 2 + 1, &strLen, bytes, length, '\0');
    return str;
}

int findHashEx (int bits, char ** message, char ** hash, const char * hashFunction) {
    *message = nullptr;
    *hash = nullptr;

    // Init OpenSSL lib
    OpenSSL_add_all_digests();
    // Hash type
    const EVP_MD* type = EVP_get_digestbyname(hashFunction);

    // Unknown hash function
    if (!type) { 
        printf("Unknown cypher type\n");
        return 0;
    }

    uint8_t* bytes = (uint8_t*) malloc(EVP_MAX_MD_SIZE);
    uint8_t* processing = randomMessage();
    uint32_t length = EVP_MAX_MD_SIZE;
    uint32_t processed;

    while(true) {
        processed = length;

        if (!hashMessage(processing, processed, bytes, length, type)) { 
            free(bytes);
            free(processing); 
            return 0; 
        }

        if (bits < 0 || bits >= (int) length * 8) { 
            free(bytes); 
            free(processing); 
            return 0; 
        }

        if (checkBitsZero(bits, bytes)) { 
            break; 
        }

        std::swap(processing, bytes);

        // printf("Bits %2d, Try:  %s\n", bits, toHex(hashBytes, length));
    }

    *message = toHex(processing, processed);
    *hash = toHex(bytes, length);
    free(bytes);
    free(processing);

    // printf("Bits %2d, Hash: %s\n", bits, *hash);

    return 1;
}

int findHash (int bits, char ** message, char ** hash) {
    return findHashEx(bits, message, hash, defaultType);
}

#ifndef __PROGTEST__

#include <chrono>
using namespace std::chrono;

char * toHexLib(uint8_t * bytes, uint32_t length) {
    char* str = (char*) malloc(length * 2 + 1);
    size_t strLen;
    OPENSSL_buf2hexstr_ex(str, length * 2 + 1, &strLen, bytes, length, '\0');
    return str;
}

void measure() {
    printf("Measuring...\n");

    const int BITS = 12;
    const int INSTANCES = 128;

    char * message, * hash;
    for (int i = 0; i < BITS; ++i) {
        auto start = high_resolution_clock::now();
        for (int j = 0; j < INSTANCES; ++j) {
            findHash(i, &message, &hash);
            free(message);
            free(hash);
        }
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        printf("{%d, %lu},\n", i, duration.count() / INSTANCES);
    }
    printf("Done!\n");
}

void checkSameHash(char * message, char * hash) {
    const EVP_MD* type = EVP_get_digestbyname(defaultType);

    long buffLen;
    uint8_t* messBytes = OPENSSL_hexstr2buf(message, &buffLen);

    uint32_t hashLen;
    uint8_t* bytes = (uint8_t*) malloc(EVP_MAX_MD_SIZE);

    hashMessage(messBytes, buffLen, bytes, hashLen, type);
    char * encoded = toHexLib(bytes, hashLen);
    printf("messg: %s\n", message);
    printf("hash1: %s\n", hash);
    printf("hash2: %s\n", encoded);
    assert(strcmp(hash, encoded) == 0);

    free(messBytes);
    free(bytes);
    free(encoded);
}

int main (void) {

    {
        uint8_t* bytes = randomMessage();
        char* hash1 = toHex   (bytes, EVP_MAX_MD_SIZE);
        char* hash2 = toHexLib(bytes, EVP_MAX_MD_SIZE);
        // printf("%d %d %d %d\n", bytes[0], bytes[1], bytes[2], bytes[4]);
        // printf("hash1: %s\n", hash1);
        // printf("hash2: %s\n", hash2);
        assert(strcmp(hash1, hash2) == 0);
        free(bytes); free(hash1); free(hash2);
    }

    char * message, * hash;
    for (int i = 0; i < 16; ++i) {
        assert(findHash(i, &message, &hash) == 1);
        checkSameHash(message, hash);
        free(message); free(hash);
    }

    measure();

    assert(findHash(-1, &message, &hash) == 0);
    free(message); free(hash);
    assert(findHash(512, &message, &hash) == 0);
    free(message); free(hash);

    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */

