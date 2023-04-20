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

#define OUT(expr) if constexpr (true) std::cout << (expr) << std::endl

#else

#define OUT(expr) if constexpr (false) std::cout << (expr) << std::endl

#endif /* __PROGTEST__ */

#define CAT(a,b) CAT2(a,b) // force expand
#define CAT2(a,b) a##b // actually concatenate
#define UNIQUE_ID() CAT(_uid_,__LINE__)

#define bindNamed(out, opt, expr, err) auto opt = (expr); if (!opt.success) { OUT(err); return {}; } auto out = std::move(*UNIQUE_ID());
#define bindCheckNamed(opt, expr, err) auto opt = (expr); if (!opt.success) { OUT(err); return {}; }
#define bind(out, expr, err) bindNamed(out, UNIQUE_ID(), expr, err)
#define bindCheck(expr, err) bindCheckNamed(UNIQUE_ID(), expr, err)

struct Unit {};

template<typename T>
struct Option {
  bool success;
  private:
  T * data;
  public:
  Option() : success(false), data(nullptr) {}
  Option(T& data)  : success(true), data(new T(data)) {}
  Option(T&& data) : success(true), data(new T(std::move(data))) {}
  Option(const Option<T>&) = delete;
  Option operator=(const Option<T>&) = delete;
  Option operator=(Option<T>&& dest) {
    dest.success = success;
    success = false;
    std::swap(data, dest.data);
    return *this;
  };
  ~Option() { delete data; }

  const T& operator* () const { return *data; }
  T& operator* ()       { return *data; }
  const T* operator->() const { return  data; }
  T* operator->()       { return  data; }
};

template<typename T>
Option<T> some(T& t) { return Option<T>(t); }
template<typename T>
Option<T> some(T&& t) { return Option<T>(std::move(t)); }
template<typename T>
Option<T> none() { return Option<T>(); }

Option<Unit> boolToOpt(const bool b) {
  return b ? some(Unit()) : none<Unit>();
}

// --- File management --------------------------------------------------------
[[nodiscard]]
Option<std::ifstream> openFileForReading(const std::string& name) {
  auto f = ifstream(name, std::ifstream::binary);
  f.peek();
  if (!f.is_open() || f.fail()) {
    return {};
  }

  return {std::move(f)};
}

[[nodiscard]]
Option<std::ofstream> openFileForWriting(const std::string& name) {
  auto f = ofstream(name, std::ifstream::binary);
  char arr[] = {0};
  f.write(arr, 1);
  f.seekp(0);
  if (!f.is_open() || f.fail()) {
    return {};
  }
  return {std::move(f)};
}

[[nodiscard]]
Option<size_t> getFileSize(ifstream& in) {
  std::streampos fsize = 0;

  fsize = in.tellg();
  in.seekg(0, std::ios::end);
  fsize = in.tellg() - fsize;
  in.seekg(0);

  if (in.fail()) { return {}; }

  return {(size_t)fsize};
}

[[nodiscard]]
Option<size_t> readBytes(ifstream& in, size_t fileLen, uint8_t * bytes, size_t len) {
  len = min(fileLen - in.tellg(), len);

  in.read((char*) bytes, len);

  if (in.fail()) { return {}; }

  const streamsize read = in.gcount();

  return {(size_t) read};
}

Option<size_t> readBytesPrecise(ifstream& in, size_t fileLen, uint8_t * bytes, size_t len) {
  Option<size_t> res = readBytes(in, fileLen, bytes, len);
  if (!res.success) { return {}; }
  if (*res == len) { return {*res}; } else { return {}; }
}

[[nodiscard]]
Option<Unit> writeBytes(ofstream& out, const uint8_t * array, const size_t len) {
  out.write((char*) array, len);
  if (out.fail()) { return {}; }

  return { Unit() };
}


// --- Files closing ----------------------------------------------------------
struct FileAutoCloser {
  ifstream& in;
  ofstream& out;
  bool shouldClose = true;
  FileAutoCloser(ifstream& in, ofstream& out) : in(in), out(out) {}

  Option<Unit> close() {
    shouldClose = false;
    in.close();
    out.close();
    return boolToOpt(!(in.fail() || out.fail())); 
  }
  ~FileAutoCloser() {
    if (shouldClose) {
      close();
    }
  }
};

/**
 * Deletes the file given unless the trap is disabled
 */
struct FileRemoveTrap {
    FileRemoveTrap(const char * fileName) :fileName(fileName) {}
    ~FileRemoveTrap() {
      if (!hasSucced) {
        std::remove(fileName);
      }
    }
    void disable() { hasSucced = true; }
  private:
    const char * fileName;
    bool hasSucced = false;
};

// --- The Main work, oh no ---------------------------------------------------

Option<Unit> initRandom() {
  return boolToOpt(RAND_load_file("/dev/random", 32) == 32);
}

using PKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;


Option<PKeyPtr> readPubKey(const char * filename) {
  FILE * fp = fopen(filename, "rb");
  if (fp == nullptr) { OUT("Failed to open the file"); return {}; };

  auto ptr = PKeyPtr(PEM_read_PUBKEY(fp, NULL, NULL, NULL), &EVP_PKEY_free);
  if (ptr == nullptr) {
    OUT("Key is broken");
    fclose(fp);
    return {};
  }

  if (fclose(fp) != 0) { OUT("Failed to close the file"); return {}; }

  return { std::move(ptr) };
}

Option<PKeyPtr> readPrivateKey(const char * filename) {
  FILE * fp = fopen(filename, "rb");
  if (fp == nullptr) { OUT("Failed to open the file"); return {}; };

  auto ptr = PKeyPtr(PEM_read_PrivateKey(fp, NULL, NULL, NULL), &EVP_PKEY_free);
  if (ptr == nullptr) {
    OUT("Key is broken");
    fclose(fp);
    return {};
  }

  if (fclose(fp) != 0) { OUT("Failed to close the file"); return {}; }
  return { std::move(ptr) };
}

bool seal(
    const char * inFileName,
    const char * outFileName,
    const char * publicKeyFileName,
    const char * symmetricCipher
    ) {
  OpenSSL_add_all_ciphers();
  bindCheck(initRandom(), "Failed to init random");

  // Open files
  auto trap = FileRemoveTrap(outFileName);
  bind(inFile,   openFileForReading(inFileName), "Failed open file for reading");
  bind(outFile,  openFileForWriting(outFileName), "Failed open file for writing");
  auto closer = FileAutoCloser(inFile, outFile);
  bind(fileSize, getFileSize(inFile), "Failed to get a file size");

  // Read key for the main key encryption
  bind(key, readPubKey(publicKeyFileName), "Failed to load public key");

  // Create a cipher
  const EVP_CIPHER* cipherType = EVP_get_cipherbyname(symmetricCipher);
  if (cipherType == nullptr) { return {}; }
  const int32_t nid = EVP_CIPHER_get_nid(cipherType);

  // Create a cipher context
  auto cipherCtx = CipherCtxPtr(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
  if (cipherCtx == nullptr) { return {}; }
  if (!EVP_CIPHER_CTX_init(cipherCtx.get())) { return {}; };

  // Load cipher info
  size_t ivTypeLen  = EVP_CIPHER_iv_length(cipherType);
  size_t keyTypeLen = EVP_PKEY_size(key.get());
  auto ivBuff = make_unique<uint8_t[]>(ivTypeLen);
  auto keyBuffRaw = new uint8_t[keyTypeLen];
  int keyLen;

  // Init
  auto publicKeyPtr = key.get();
  if (!EVP_SealInit(cipherCtx.get(), cipherType, &keyBuffRaw, &keyLen, ivBuff.get(), &publicKeyPtr, 1)) { delete [] keyBuffRaw; return {}; }
  auto keyBuff = unique_ptr<uint8_t[]>(keyBuffRaw);

  // Store cipher info
  bindCheck(writeBytes(outFile, (uint8_t*)&nid, sizeof(nid)), "Failed to write NID");
  bindCheck(writeBytes(outFile, (uint8_t*)&keyLen, sizeof(keyLen)), "Failed to write key len");
  bindCheck(writeBytes(outFile, keyBuff.get(), keyLen), "Failed to write key");
  bindCheck(writeBytes(outFile, ivBuff.get(), ivTypeLen), "Failed to write key");

  // Encrypt the file
  const size_t blockSize = (size_t) EVP_CIPHER_CTX_block_size(cipherCtx.get());
  const size_t chunkSize = 1024;
  const size_t outBuffSize = chunkSize + blockSize;
  auto  inBuff = make_unique<uint8_t[]>(chunkSize);
  auto outBuff = make_unique<uint8_t[]>(outBuffSize);
  while(true) {
    // Encrypt the file
    bind(readCnt, readBytes(inFile, fileSize, inBuff.get(), chunkSize), ("Failed to read file"));

    int len = outBuffSize;
    if (!EVP_SealUpdate(cipherCtx.get(), outBuff.get(), &len, inBuff.get(), readCnt)) { OUT("Failed to update the context"); return false; }

    bindCheck(writeBytes(outFile, outBuff.get(), (size_t) len), "Failed to write the file")

    // File read, finalize
    if (readCnt != chunkSize) {
      int len = outBuffSize;
      if (!EVP_SealFinal(cipherCtx.get(), outBuff.get(), &len)) { OUT("Failed to finalize the context"); return false; }

      bindCheck(writeBytes(outFile, outBuff.get(), len), "Failed to write the file")
      break; 
    }
  }
  

  // Cleanup
  bindCheck(closer.close(), "Failed to close the files");
  trap.disable();
  return true;
}

bool open(const char * inFileName,
    const char * outFileName,
    const char * privateKeyFileName
    ) {
  OpenSSL_add_all_ciphers();

  // Open files
  auto trap = FileRemoveTrap(outFileName);
  bind(inFile,   openFileForReading(inFileName), "Failed open file for reading");
  bind(outFile,  openFileForWriting(outFileName), "Failed open file for writing");
  auto closer = FileAutoCloser(inFile, outFile);
  bind(fileSize, getFileSize(inFile), "Failed to get a file size");

  // Read a key for the main key decryption
  bind(key, readPrivateKey(privateKeyFileName), "Failed to load perm");

  // Read info from a file
  int nid, keyLen;
  bindCheck(readBytesPrecise(inFile, fileSize, (uint8_t*)&nid, sizeof(nid)), "Failed to read initial NID bytes");
  bindCheck(readBytesPrecise(inFile, fileSize, (uint8_t*)&keyLen, sizeof(keyLen)), "Failed to read key length");

  // Get cipher type
  const EVP_CIPHER* cipherType = EVP_get_cipherbynid(nid);
  if (cipherType == nullptr) { return {}; }

  // Create context
  auto cipherCtx = CipherCtxPtr(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
  if (cipherCtx == nullptr) { return {}; }
  if (!EVP_CIPHER_CTX_init(cipherCtx.get())) { return {}; };

  // Load the remaining data
  size_t ivTypeLen  = EVP_CIPHER_iv_length(cipherType);
  size_t keyTypeLen = EVP_PKEY_size(key.get());
  auto ivBuff = make_unique<uint8_t[]>(ivTypeLen);
  auto keyBuff = make_unique<uint8_t[]>(keyTypeLen);

  bindCheck(readBytesPrecise(inFile, fileSize, keyBuff.get(), keyLen), "Failed to read key");
  bindCheck(readBytesPrecise(inFile, fileSize, ivBuff.get(), ivTypeLen), "Failed to read iv");

  // Init
  if (!EVP_OpenInit(cipherCtx.get(), cipherType, keyBuff.get(), keyLen, ivBuff.get(), key.get())) { return {}; }

  // Decrypt the file
  const size_t blockSize = (size_t) EVP_CIPHER_CTX_block_size(cipherCtx.get());
  const size_t chunkSize = 1024;
  const size_t outBuffSize = chunkSize + blockSize;
  auto  inBuff = make_unique<uint8_t[]>(chunkSize);
  auto outBuff = make_unique<uint8_t[]>(outBuffSize);

  while(true) {
    // Encrypt the file
    bind(readCnt, readBytes(inFile, fileSize, inBuff.get(), chunkSize), ("Failed to read file"));

    int len = outBuffSize;
    if (!EVP_OpenUpdate(cipherCtx.get(), outBuff.get(), &len, inBuff.get(), readCnt)) { OUT("Failed to update the context"); return false; }

    bindCheck(writeBytes(outFile, outBuff.get(), (size_t) len), "Failed to write the file")

    // File read, finalize
    if (readCnt != chunkSize) {
      int len = outBuffSize;
      if (!EVP_OpenFinal(cipherCtx.get(), outBuff.get(), &len)) { OUT("Failed to finalize the context"); return false; }

      bindCheck(writeBytes(outFile, outBuff.get(), len), "Failed to write the file")
      break; 
    }
  }
  
  // Cleanup
  bindCheck(closer.close(), "Failed to close the files");
  trap.disable();
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

