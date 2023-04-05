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

template<typename T>
struct Array {
  size_t size;
  T* data = nullptr;
  Array(size_t size = 0) : size(size), data((T*) malloc(size * sizeof(T))) {}
  ~Array() {
    free(data);
    data = nullptr;
  }

  Array(const Array<T>& src) = delete;
  Array operator=(const Array<T>& src) = delete;
  
  Array(Array<T>&& src) {
    free(data);
    size = src.size;
    data = src.data;
    src.size = 0;
    src.data = nullptr;
  };
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

Optional<context_ptr> createContext(crypto_config& config, bool encryption) {
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
  }
  if (expIVLength != 0 && ((int) config.m_IV_len < expIVLength || config.m_IV == nullptr)) {
    if (!encryption) {
      return {};
    }
    auto rand = randBytes(expIVLength);
    std::swap(config.m_IV, rand);
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
    // in.seekg(0, std::ios::beg);
    in.seekg(0);

    if (in.fail()) { return {}; }

    return {(size_t)fsize};
}

[[nodiscard]]
Optional<Array<uint8_t>> readBytes(ifstream& in, size_t fileLen, size_t len) {
  len = min(fileLen - in.tellg(), len);

  Array<uint8_t> bytes(len);
  in.read((char*) bytes.data, len);

  if (in.fail() && !in.eof()) { return {}; }

  streamsize read = in.gcount();
  bytes.size = read;

  return {std::move(bytes)};
}

[[nodiscard]]
Optional<Unit> writeBytes(ofstream& out, const Array<uint8_t>& array) {
  out.write((char*) array.data, array.size);
  if (out.fail()) {
    return {};
  }
  return {Unit()};
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
  auto inOpt  = openFileForReading(inFilename);
  if (! inOpt.success) { OUT("Failed to open the file for reading"); return false; }
  auto& in  = *inOpt;

  auto outOpt = openFileForWriting(outFilename);
  if (!outOpt.success) { inOpt->close(); OUT("Failed to open the file for writing"); return false; }
  auto& out = *outOpt;
  auto fileCloser = FileAutoCloser(in, out);

  auto fileSizeOpt = getFileSize(in);
  if (!fileSizeOpt.success) { OUT("Failed to obtain file size"); return false; }
  auto fileSize = *fileSizeOpt;



  // OpenSSL init
  auto ctxOpt = createContext(config, encrypt);
  if (!ctxOpt.success) { OUT("Failed to create context"); return false; }
  auto& ctx = *ctxOpt;


  // Move first 18 bytes
  {
    auto bytesOpt = readBytes(in, fileSize, headerSize);
    if (bytesOpt.success == false || bytesOpt->size != headerSize) { OUT("Failed to read the header"); return false; }
    auto& bytes = *bytesOpt;

    auto resOpt = writeBytes(out, bytes);
    if (resOpt.success == false) { OUT("Failed to write the header"); return false; }
  }


  // The actual encryption/decryption process
  const int blockSize = EVP_CIPHER_CTX_block_size(ctx.get());
  auto outBuff = Array<uint8_t>(2 * blockSize);

  while(true) {
    // Encrypt the file
    auto readOpt = readBytes(in, fileSize, blockSize);
    {
      if (!readOpt.success) { OUT("Failed to read file"); return false; }

      {
        int len = outBuff.size;
        if (!EVP_CipherUpdate(ctx.get(), outBuff.data, &len, readOpt->data, readOpt->size)) { OUT("Failed to update the context"); return false; }
        outBuff.size = len;
      }

      auto wroteOpt = writeBytes(out, outBuff);
      if (!wroteOpt.success) { OUT("Failed to write the file"); return false; }
    }

    // File read, finalize
    if (readOpt->size != (size_t)blockSize) {
      {
        int len = outBuff.size;
        if (!EVP_CipherFinal(ctx.get(), outBuff.data, &len)) { OUT("Failed to finalize the context"); return false; }
        outBuff.size = len;
      }

      auto wroteOpt = writeBytes(out, outBuff);
      if (!wroteOpt.success) { OUT("Failed to write the file"); return false; }
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
    return false;
  }

  if (f1.tellg() != f2.tellg()) {
    return false;
  }

  f1.seekg(0, std::ifstream::beg);
  f2.seekg(0, std::ifstream::beg);
  return std::equal(std::istreambuf_iterator<char>(f1.rdbuf()),
                    std::istreambuf_iterator<char>(),
                    std::istreambuf_iterator<char>(f2.rdbuf()));
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
  return 0;
}

#endif /* _PROGTEST_ */
