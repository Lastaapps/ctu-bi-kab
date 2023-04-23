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

#define bindNamed(out, opt, expr, err) auto opt = (expr); if (!opt.success) { OUT(err); return {}; } auto out = std::move(*opt);
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
    std::swap(success, dest.success);
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

  if (!f.is_open() || f.fail()) {
    return {};
  }

  return {std::move(f)};
}

[[nodiscard]]
Option<std::ofstream> openFileForWriting(const std::string& name) {
  auto f = ofstream(name, std::ifstream::binary);

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
  private:
    ifstream& in;
    ofstream& out;
    bool shouldClose = true;
  public:
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

Option<Unit> processFile(CipherCtxPtr& cipherCtx, ifstream& inFile, size_t fileSize, ofstream& outFile) {
  const size_t blockSize = (size_t) EVP_CIPHER_CTX_block_size(cipherCtx.get());
  const size_t chunkSize = 1024;
  const size_t outBuffSize = chunkSize + blockSize;
  auto  inBuff = make_unique<uint8_t[]>(chunkSize);
  auto outBuff = make_unique<uint8_t[]>(outBuffSize);

  while(true) {
    bind(readCnt, readBytes(inFile, fileSize, inBuff.get(), chunkSize), ("Failed to read file"));

    int len = outBuffSize;
    if (!EVP_CipherUpdate(cipherCtx.get(), outBuff.get(), &len, inBuff.get(), readCnt)) { OUT("Failed to update the context"); return {}; }

    bindCheck(writeBytes(outFile, outBuff.get(), (size_t) len), "Failed to write the file")

    // File read, finalize
    if (readCnt != chunkSize) {
      int len = outBuffSize;
      if (!EVP_CipherFinal(cipherCtx.get(), outBuff.get(), &len)) { OUT("Failed to finalize the context"); return {}; }

      bindCheck(writeBytes(outFile, outBuff.get(), len), "Failed to write the file")
      break; 
    }
  }

  return some(Unit{});
}

bool seal(
    const char * inFileName,
    const char * outFileName,
    const char * publicKeyFileName,
    const char * symmetricCipher
    ) {

  if (inFileName == nullptr) { return false; }
  if (outFileName == nullptr) { return false; }
  if (publicKeyFileName == nullptr) { return false; }
  if (symmetricCipher == nullptr) { return false; }

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

  // Get the cipher type
  const EVP_CIPHER* cipherType = EVP_get_cipherbyname(symmetricCipher);
  if (cipherType == nullptr) { OUT("Uknown cipher type"); return {}; }
  const int32_t nid = EVP_CIPHER_nid(cipherType);

  // Create a cipher context
  auto cipherCtx = CipherCtxPtr(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
  if (cipherCtx == nullptr) { OUT("Failed to create a context"); return {}; }
  if (!EVP_CIPHER_CTX_init(cipherCtx.get())) { OUT("Failed to init the context"); return {}; };

  // Load cipher info
  size_t keyTypeLen = EVP_PKEY_size(key.get());
  size_t ivTypeLen  = EVP_CIPHER_iv_length(cipherType);
  auto keyBuffRaw = new uint8_t[keyTypeLen];
  auto ivBuff = make_unique<uint8_t[]>(ivTypeLen);
  int keyLen;

  // Init
  auto publicKeyPtr = key.get();
  if (!EVP_SealInit(cipherCtx.get(), cipherType, &keyBuffRaw, &keyLen, ivBuff.get(), &publicKeyPtr, 1)) { delete [] keyBuffRaw; OUT("Failed to init seal"); return {}; }
  auto keyBuff = unique_ptr<uint8_t[]>(keyBuffRaw);

  // Store cipher info
  bindCheck(writeBytes(outFile, (uint8_t*)&nid, sizeof(nid)), "Failed to write NID");
  bindCheck(writeBytes(outFile, (uint8_t*)&keyLen, sizeof(keyLen)), "Failed to write key len");
  bindCheck(writeBytes(outFile, keyBuff.get(), keyLen), "Failed to write key");
  bindCheck(writeBytes(outFile, ivBuff.get(), ivTypeLen), "Failed to write key");
  
  bindCheck(processFile(cipherCtx, inFile, fileSize, outFile), "Failed to encrypt the file");

  // Cleanup
  bindCheck(closer.close(), "Failed to close the files");
  trap.disable();
  return true;
}

bool open(const char * inFileName,
    const char * outFileName,
    const char * privateKeyFileName
    ) {

  if (inFileName == nullptr) { return false; }
  if (outFileName == nullptr) { return false; }
  if (privateKeyFileName == nullptr) { return false; }

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
  if (cipherType == nullptr) { OUT("Unknown cipher type"); return {}; }

  // Create context
  auto cipherCtx = CipherCtxPtr(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
  if (cipherCtx == nullptr) { OUT("Failed to create a context"); return {}; }
  if (!EVP_CIPHER_CTX_init(cipherCtx.get())) { OUT("Failed to init the context"); return {}; };

  // Load the remaining data
  size_t keyTypeLen = EVP_PKEY_size(key.get());
  size_t ivTypeLen  = EVP_CIPHER_iv_length(cipherType);
  auto keyBuff = make_unique<uint8_t[]>(keyLen);
  auto ivBuff = make_unique<uint8_t[]>(ivTypeLen);
  if (keyLen < 0 || (size_t) keyLen > keyTypeLen) { OUT("The key len is not in a valid range"); return {}; }

  bindCheck(readBytesPrecise(inFile, fileSize, keyBuff.get(), keyLen), "Failed to read key");
  bindCheck(readBytesPrecise(inFile, fileSize, ivBuff.get(), ivTypeLen), "Failed to read iv");

  // Init
  if (!EVP_OpenInit(cipherCtx.get(), cipherType, keyBuff.get(), keyLen, ivBuff.get(), key.get())) { return {}; }

  // Decrypt the file
  bindCheck(processFile(cipherCtx, inFile, fileSize, outFile), "Failed to dencrypt the file");
  
  // Cleanup
  bindCheck(closer.close(), "Failed to close the files");
  trap.disable();
  return true;
}

#ifndef __PROGTEST__

// https://stackoverflow.com/questions/12791807/get-file-size-with-stdiosate
bool compare_files ( const char * name1, const char * name2) {
  std::ifstream f1(name1, std::ifstream::binary|std::ifstream::ate);
  std::ifstream f2(name2, std::ifstream::binary|std::ifstream::ate);

  if (f1.fail() || f2.fail()) {
    std::cout << "Failed to open one of the files" << std::endl;
    return false;
  }

  if (f1.tellg() != f2.tellg()) {
    std::cout << "File size differ: " << f1.tellg() << " x " << f2.tellg() << std::endl;
    return false;
  }

  f1.seekg(0, std::ifstream::beg);
  f2.seekg(0, std::ifstream::beg);
  const bool res = std::equal(std::istreambuf_iterator<char>(f1.rdbuf()),
                    std::istreambuf_iterator<char>(),
                    std::istreambuf_iterator<char>(f2.rdbuf()));
  if (!res) {
    std::cout << "Files are not the same" << std::endl;
  }
  return res;
}

int main (void) {
  assert(seal("fileToEncrypt", "sealed.bin", "PublicKey.pem", "aes-128-cbc"));
  assert(open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem"));
  assert(compare_files("fileToEncrypt", "openedFileToEncrypt"));

  assert(seal("fileToEncrypt", "sealed.bin", "PublicKey.pem", "aes-128-ecb"));
  assert(open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem"));
  assert(compare_files("fileToEncrypt", "openedFileToEncrypt"));

  assert(seal("empty", "sealed.bin", "PublicKey.pem", "aes-128-cbc"));
  assert(open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem"));
  assert(compare_files("empty", "openedFileToEncrypt"));

  assert(open("sealed_sample.bin", "opened_sample.txt", "PrivateKey.pem"));

  assert(!seal("idk", "sealed.bin", "PublicKey.pem", "aes-128-cbc"));
  assert(!seal("fileToEncrypt", "sealed.bin", "idk.pem", "aes-128-cbc"));
  assert(!seal("fileToEncrypt", "sealed.bin", "PublicKey.pem", "idk"));
  assert(!open("idk.bin", "opened_sample.txt", "PrivateKey.pem"));
  assert(!open("sealed_sample.bin", "opened_sample.txt", "idk.pem"));

  assert(!open("bytes_00", "opened_sample.txt", "PrivateKey.pem"));
  assert(!open("bytes_04", "opened_sample.txt", "PrivateKey.pem"));
  assert(!open("bytes_08", "opened_sample.txt", "PrivateKey.pem"));
  assert(!open("sealed_sample_broken_id.bin", "opened_sample.txt", "PrivateKey.pem"));
  assert(!open("sealed_sample_broken_key.bin", "opened_sample.txt", "PrivateKey.pem"));
  assert(!open("sealed_sample_broken_len.bin", "opened_sample.txt", "PrivateKey.pem"));

  return 0;
}

#endif /* __PROGTEST__ */

