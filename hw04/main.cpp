#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

using namespace std;

#endif /* __PROGTEST__ */

bool seal(
        const char * inFile,
        const char * outFile,
        const char * publicKeyFile,
        const char * symmetricCipher
        ) {
    //waiting for code...
    return true;
}

bool open(const char * inFile,
        const char * outFile,
        const char * privateKeyFile
        ) {
    //waiting for code...
    return true;
}

#ifndef __PROGTEST__

int main (void) {
    assert(seal("fileToEncrypt", "sealed.bin", "PublicKey.pem", "aes-128-cbc"));
    assert(open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem"));

    assert(open("sealed_sample.bin", "opened_sample.txt", "PrivateKey.pem"));

    return 0;
}

#endif /* __PROGTEST__ */

