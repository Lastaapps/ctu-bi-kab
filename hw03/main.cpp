#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

struct crypto_config {
  const char * m_crypto_function;
  std::unique_ptr<uint8_t[]> m_key;
  std::unique_ptr<uint8_t[]> m_IV;
  size_t m_key_len;
  size_t m_IV_len;
};

#define OUT(expr) if constexpr (true) std::cout << (expr) << std::endl

#else

#define OUT(expr) if constexpr (false) std::cout << (expr) << std::endl

#endif /* _PROGTEST_ */

#define CAT(a,b) CAT2(a,b) // force expand
#define CAT2(a,b) a##b // actually concatenate
#define UNIQUE_ID() CAT(_uid_,__LINE__)

#define bindNamed(out, opt, expr, err) auto opt = (expr); if (!opt.success) { OUT(err); return {}; } auto out = std::move(*UNIQUE_ID());
#define bindCheckNamed(opt, expr, err) auto opt = (expr); if (!opt.success) { OUT(err); return {}; }
#define bind(out, expr, err) bindNamed(out, UNIQUE_ID(), expr, err)
#define bindCheck(expr, err) bindCheckNamed(UNIQUE_ID(), expr, err)

struct Unit {};

template<typename T>
using SP = shared_ptr<T>;
const size_t headerSize = 18;

template<typename T>
struct Optional {
    bool success;
  private:
    T * data;
  public:
    Optional() : success(false), data(nullptr) {}
    Optional(T& data)  : success(true), data(new T(data)) {}
    Optional(T&& data) : success(true), data(new T(std::move(data))) {}
    Optional(const Optional<T>&) = delete;
    Optional operator=(const Optional<T>&) = delete;
    ~Optional() {
      delete data;
    }

    const T& operator* () const { return *data; }
          T& operator* ()       { return *data; }
    const T* operator->() const { return  data; }
          T* operator->()       { return  data; }
};

void deleteEVP_CIPHER_CTX(EVP_CIPHER_CTX * ptr) {
  EVP_CIPHER_CTX_free(ptr);
}

template<typename T, typename F>
std::unique_ptr<T, F> with_deleter(T * ptr, F deleter) {
  return std::unique_ptr<T, F>(ptr, deleter);
}

std::unique_ptr<uint8_t[]> randBytes(int len) {
  std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(len);
  RAND_bytes(data.get(), len);
  return data;
}

using context_ptr = unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX *)>;

Optional<context_ptr> createContext(crypto_config& config, const bool encryption) {
  OpenSSL_add_all_ciphers();

  const EVP_CIPHER * cipher = EVP_get_cipherbyname(config.m_crypto_function);
  if (cipher == nullptr) return {};


  context_ptr ctx = with_deleter(EVP_CIPHER_CTX_new(), deleteEVP_CIPHER_CTX);;
  if (ctx == nullptr) return {};

  const int expKeyLength = EVP_CIPHER_key_length(cipher);
  const int expIVLength = EVP_CIPHER_iv_length(cipher);

  if ((int) config.m_key_len < expKeyLength || config.m_key == nullptr) {
    if (!encryption) {
      return {};
    }
    auto rand = randBytes(expKeyLength);
    std::swap(config.m_key, rand);
    config.m_key_len = expKeyLength;
  }

  if (expIVLength != 0 && ((int) config.m_IV_len < expIVLength || config.m_IV == nullptr)) {
    if (!encryption) {
      return {};
    }
    auto rand = randBytes(expIVLength);
    std::swap(config.m_IV, rand);
    config.m_IV_len = expIVLength;
  }

  if (!EVP_CipherInit_ex(ctx.get(), cipher, nullptr, config.m_key.get(), config.m_IV.get(), encryption ? 1 : 0)) {
    return {};
  }

  return {std::move(ctx)};
}

[[nodiscard]]
Optional<std::ifstream> openFileForReading(const std::string& name) {
  auto f = ifstream(name, std::ifstream::binary);
  f.peek();
  if (!f.is_open() || f.fail()) {
    return {};
  }

  return {std::move(f)};
}

[[nodiscard]]
Optional<std::ofstream> openFileForWriting(const std::string& name) {
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
Optional<size_t> getFileSize(ifstream& in) {
    std::streampos fsize = 0;

    fsize = in.tellg();
    in.seekg(0, std::ios::end);
    fsize = in.tellg() - fsize;
    in.seekg(0);

    if (in.fail()) { return {}; }

    return {(size_t)fsize};
}

[[nodiscard]]
Optional<size_t> readBytes(ifstream& in, size_t fileLen, uint8_t * bytes, size_t len) {
  len = min(fileLen - in.tellg(), len);

  in.read((char*) bytes, len);

  if (in.fail()) { return {}; }

  const streamsize read = in.gcount();

  return {(size_t) read};
}

[[nodiscard]]
Optional<Unit> writeBytes(ofstream& out, const uint8_t * array, const size_t len) {
  out.write((char*) array, len);
  if (out.fail()) { return {}; }

  return { Unit() };
}

struct FileAutoCloser {
  ifstream& in;
  ofstream& out;
  bool shouldClose = true;
  FileAutoCloser(ifstream& in, ofstream& out) : in(in), out(out) {}

  bool close() {
    shouldClose = false;
    in.close();
    out.close();
    return !(in.fail() || out.fail());
  }
  ~FileAutoCloser() {
    if (shouldClose) {
      close();
    }
  }
};

bool withOpenedFiles(const std::string & inFilename, const std::string & outFilename, crypto_config & config, bool encrypt) {

  // Resources preparation
  bind(in, openFileForReading(inFilename), "Failed to open the file for reading");
  bind(out, openFileForWriting(outFilename), "Failed to open the file for writing");
  auto fileCloser = FileAutoCloser(in, out);

  bind(fileSize, getFileSize(in), "Failed to create context")


  // OpenSSL init
  bind(ctx, createContext(config, encrypt), "Failed to create context")


  // Move first 18 bytes
  {
    auto bytes = make_unique<uint8_t[]>(headerSize);
    auto readOpt = readBytes(in, fileSize, bytes.get(), headerSize);
    if (readOpt.success == false || *readOpt != headerSize) { OUT("Failed to read the header"); return false; }

    auto resOpt = writeBytes(out, bytes.get(), *readOpt);
    if (resOpt.success == false) { OUT("Failed to write the header"); return false; }
  }


  // The actual encryption/decryption process
  const size_t blockSize = (size_t) EVP_CIPHER_CTX_block_size(ctx.get());
  const size_t chunkSize = 1024;
  const size_t outBuffSize = chunkSize + blockSize;
  auto  inBuff = make_unique<uint8_t[]>(chunkSize);
  auto outBuff = make_unique<uint8_t[]>(outBuffSize);

  while(true) {
    // Encrypt the file
    bind(readCnt, readBytes(in, fileSize, inBuff.get(), chunkSize), ("Failed to read file"));

    int len = outBuffSize;
    if (!EVP_CipherUpdate(ctx.get(), outBuff.get(), &len, inBuff.get(), readCnt)) { OUT("Failed to update the context"); return false; }

    bindCheck(writeBytes(out, outBuff.get(), (size_t) len), "Failed to write the file")

    // File read, finalize
    if (readCnt!= chunkSize) {
      int len = outBuffSize;
      if (!EVP_CipherFinal(ctx.get(), outBuff.get(), &len)) { OUT("Failed to finalize the context"); return false; }

      bindCheck(writeBytes(out, outBuff.get(), len), "Failed to write the file")
      break; 
    }
  }

  // Close files
  if (!fileCloser.close()){ OUT("Failed to close files"); return false; }

  return true;
}

bool encrypt_data ( const std::string & inFilename, const std::string & outFilename, crypto_config & config ) {
  return withOpenedFiles(inFilename, outFilename, config, true);
}

bool decrypt_data ( const std::string & inFilename, const std::string & outFilename, crypto_config & config ) {
  return withOpenedFiles(inFilename, outFilename, config, false);
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

int main ( void )
{
  crypto_config config {nullptr, nullptr, nullptr, 0, 0};

  // ECB mode
  config.m_crypto_function = "AES-128-ECB";
  config.m_key = std::make_unique<uint8_t[]>(16);
  memset(config.m_key.get(), 0, 16);
  config.m_key_len = 16;

  assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
      compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA") );

  assert( decrypt_data  ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
      compare_files ("out_file.TGA", "homer-simpson.TGA") );

  assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
      compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA") );

  assert( decrypt_data  ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
      compare_files ("out_file.TGA", "UCM8.TGA") );

  assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
      compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA") );

  assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
      compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA") );

  assert( decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config)  &&
        compare_files("out_file.TGA", "ref_3_dec_ecb.TGA") );

  assert( decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config)  &&
        compare_files("out_file.TGA", "ref_4_dec_ecb.TGA") );

  // CBC mode
  config.m_crypto_function = "AES-128-CBC";
  config.m_IV = std::make_unique<uint8_t[]>(16);
  config.m_IV_len = 16;
  memset(config.m_IV.get(), 0, 16);

  assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
      compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA") );

  assert( decrypt_data  ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
      compare_files ("out_file.TGA", "UCM8.TGA") );

  assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
      compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA") );

  assert( decrypt_data  ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
      compare_files ("out_file.TGA", "homer-simpson.TGA") );

  assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
      compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA") );

  assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
      compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA") );

  assert( decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config)  &&
        compare_files("out_file.TGA", "ref_7_dec_cbc.TGA") );

  assert( decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config)  &&
        compare_files("out_file.TGA", "ref_8_dec_cbc.TGA") );

  // My tests
  config.m_key_len = 15;
  assert( !decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config) );
  config.m_key_len = 16;

  config.m_IV_len = 15;
  assert( !decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config) );
  config.m_IV_len = 16;

  const char* oldName = config.m_crypto_function;
  config.m_crypto_function = "fdsa";
  assert( !decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config) );
  config.m_crypto_function = oldName;

  assert( !decrypt_data ("image_8_enc_cbc.TGA", "nonwritable", config) );
  assert( !decrypt_data ("nonreadable", "out_file.TGA", config) );
  assert( !decrypt_data ("nonexisting", "out_file.TGA", config) );
  assert( !decrypt_data ("wrongheader", "out_file.TGA", config) );

  return 0;
}

#endif /* _PROGTEST_ */
