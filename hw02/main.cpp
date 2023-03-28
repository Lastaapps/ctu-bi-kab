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

int checkBitsZero(int bits, uint8_t * hash) {
    int bytesToCheck = bits / 8;
    int  bitsToCheck = bits % 8;

    for (int i = 0; i < bytesToCheck; ++i) {
        if (*hash != 0) {
            return 0;
        }
        ++hash;
    }

    return !(*hash & ((uint8_t)~0 << (8 - bitsToCheck)));
}

char * randomMessage() {
    const int initLength = EVP_MAX_MD_SIZE;
    char * message = (char*) malloc(initLength * 2);
    RAND_bytes((uint8_t*)message, initLength);
    message[initLength] = '\0';
    return message;
}

int hashMessage(char * message, uint8_t * hash, uint32_t& length, const EVP_MD * type) {
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
    if (!EVP_DigestUpdate(ctx, message, EVP_MAX_MD_SIZE)) {
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
    size_t strLen;
    OPENSSL_buf2hexstr_ex(str, length * 2 + 1, &strLen, bytes, length, '\0');
    return str;
}

int findHashEx (int bits, char ** message, char ** hash, const char * hashFunction) {

    // Used hash type
    const EVP_MD * type;
    // Hash buffer setup
    uint8_t * hashBytes = (uint8_t*) malloc(sizeof(*hashBytes) * EVP_MAX_MD_SIZE * 2);
    // Hash length
    uint32_t length;

    // Init OpenSSL lib
    OpenSSL_add_all_digests();
    // Gets hash function type
    type = EVP_get_digestbyname(hashFunction);

    // Unknown hash function
    if (!type) { 
        printf("Unknown cypher type\n");
        return 0;
    }

    *message = randomMessage();
    while(true) {
        if (!hashMessage(*message, hashBytes, length, type)) { return 0; }

        if (bits < 0 || bits >= length) { return 0; }

        if (checkBitsZero(bits, hashBytes)) { break; }
        memcpy(*message, hashBytes, length);
        (*message)[EVP_MAX_MD_SIZE] = '\0';
        // printf("Bits %2d, Try:  %s\n", bits, toHex(hashBytes, length));
    }

    *hash = toHex(hashBytes, length);

    // printf("Bits %2d, Hash: %s\n", bits, *hash);

    return 1;
}

int findHash (int bits, char ** message, char ** hash) {
    return findHashEx(bits, message, hash, "sha512");
}

#ifndef __PROGTEST__

#include <chrono>
using namespace std::chrono;


void measure() {
    printf("Measuring...\n");

    const int BITS = 20;
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

int main (void) {

    char * message, * hash;
    for (int i = 0; i < 16; ++i) {
        assert(findHash(i, &message, &hash) == 1);
        free(message);
        free(hash);
    }

    measure();

    assert(findHash(-1, &message, &hash) == 0);
    assert(findHash(512, &message, &hash) == 0);
    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */

