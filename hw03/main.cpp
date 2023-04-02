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

#endif /* _PROGTEST_ */

struct Unit {};

template<typename T>
using SP = shared_ptr<T>;

template<typename T>
struct Optional {
	bool success;
	T data;
	Optional() : success(false) {}
	Optional(T& data)  : success(true), data(data) {}
	Optional(T&& data) : success(true), data(std::move(data)) {}
};

template<typename T>
struct Array {
	size_t size;
	T* data;
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
Optional<Array<uint8_t>> readBytes(ifstream& in, size_t len) {
	Array<uint8_t> bytes(len);
	in.read((char*) bytes.data, len);
	if (in.fail()) {
		return {};
	}
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



bool encrypt_data ( const std::string & inFilename, const std::string & outFilename, crypto_config & config ) {
	auto inOpt  = openFileForReading(inFilename);
	auto outOpt = openFileForWriting(outFilename);
	if (! inOpt.success) { return false; }
	if (!outOpt.success) { return false; }
	auto& in  = inOpt.data;
	auto& out = inOpt.data;


}

bool decrypt_data ( const std::string & inFilename, const std::string & outFilename, crypto_config & config ) {

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
