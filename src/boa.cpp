#include <botan/botan.h>
#include <botan/lookup.h>
#include <botan/cipher_mode.h>

#include <iostream>
#include <fstream>
#include <experimental/filesystem>
#include <cmath>

using namespace Botan;

static constexpr char alphabet_upper [] = { 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z' };
static constexpr char alphabet_lower [] = { 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z' };
static constexpr char numeric [] = { '0','1','2','3','4','5','6','7','8','9' };

static std::string archive_path = "";
static std::string stored_cryptor = "";
static std::string stored_hash = "";
static std::string stored_key = "";

//================================================================
//----------------------------------------------------------------
//================================================================

struct archive_entry {
	std::string site;
	std::string user;
	std::string pwd;
	std::string additional_info;
};

static std::vector<archive_entry> entries {};

static void decompress_entries(std::vector<uint8_t> const & src_buffer) {
	archive_entry cur_ent;
	int state = -3;
	
	entries.clear();
	
	for (uint8_t const & c : src_buffer) {
		switch (state) {
			case -3:
				if (c != 'B') throw std::runtime_error("vault header mismatch (incorrect decryption or corrupted file)");
				state++;
				break;
			case -2:
				if (c != 'O') throw std::runtime_error("vault header mismatch (incorrect decryption or corrupted file)");
				state++;
				break;
			case -1:
				if (c != 'A') throw std::runtime_error("vault header mismatch (incorrect decryption or corrupted file)");
				state++;
				break;
			case 0:
				if (c == 0) { state = 1; continue; }
				cur_ent.site.push_back(c);
				break;
			case 1:
				if (c == 0) { state = 2; continue; }
				cur_ent.user.push_back(c);
				break;
			case 2:
				if (c == 0) { state = 3; continue; }
				cur_ent.pwd.push_back(c);
				break;
			case 3:
				if (c == 0) { state = 0; entries.push_back(cur_ent); cur_ent = {}; continue; }
				cur_ent.additional_info.push_back(c);
				break;
			default:
				throw -1;
		}
	}
	
	if (state != 0 || cur_ent.site.size() > 0) {
		printf("WARNING: vault is very likely corrupted");
	}
}

static std::vector<uint8_t> compress_entries() {
	std::vector<uint8_t> comp {'B', 'O', 'A'};
	for (archive_entry const & entry : entries) {
		for (char cu : entry.site) {
			uint8_t c = *reinterpret_cast<uint8_t *>(&cu);
			comp.push_back(c);
		}
		comp.push_back(0);
		for (char cu : entry.user) {
			uint8_t c = *reinterpret_cast<uint8_t *>(&cu);
			comp.push_back(c);
		}
		comp.push_back(0);
		for (char cu : entry.pwd) {
			uint8_t c = *reinterpret_cast<uint8_t *>(&cu);
			comp.push_back(c);
		}
		comp.push_back(0);
		for (char cu : entry.additional_info) {
			uint8_t c = *reinterpret_cast<uint8_t *>(&cu);
			comp.push_back(c);
		}
		comp.push_back(0);
	}
	return comp;
}

//================================================================
//----------------------------------------------------------------
//================================================================

template <typename V> void print_bytes(V & v) {
	for (auto i : v) {
		printf("%02hhX", *reinterpret_cast<unsigned char *>(&i));
	}
	printf("\n");
}

template <typename V> void print_ascii(V & v) {
	for (auto i : v) {
		printf("%c", *reinterpret_cast<unsigned char *>(&i));
	}
	printf("\n");
}

static void print_entry(size_t index) {
	archive_entry const & entry = entries[index];
	printf( "Index %lu:\n    Site: %s\n    User: %s\n    PWD: %s\n    Info: %s\n\n", index, entry.site.c_str(), entry.user.c_str(), entry.pwd.c_str(), entry.additional_info.c_str() );
}

//================================================================
//----------------------------------------------------------------
//================================================================

static bool input_yn(char const * msg) {
	for (;;) {
		printf("%s (y/n): ", msg);
		std::string inp;
		std::getline(std::cin, inp);
		if (inp == "y" || inp == "yes" || inp == "Y") return true;
		else if (inp == "n" || inp == "no" || inp == "N") return false;
		else {
			printf("Unrecognized input.\n");
		}
	}
}

static std::string input_str(char const * msg) {
	for (;;) {
		printf("%s (string): ", msg);
		std::string inp;
		std::getline(std::cin, inp);
		return inp;
	}
}

static std::string input_strne(char const * msg) { // empty not allowed
	for (;;) {
		printf("%s (string): ", msg);
		std::string inp;
		std::getline(std::cin, inp);
		if (inp.length() > 0) return inp;
		else {
			printf("String cannot be empty.\n");
		}
	}
}

static std::unique_ptr<HashFunction> input_hash(char const * msg) {
	std::string nstr (msg);
	nstr += " (hash function)";
	for (;;) {
		std::string hash_name = input_strne(nstr.c_str());
		auto func = HashFunction::create(hash_name);
		if (func) return func;
		else {
			printf("Could not find that hash function.\n");
		}
	}
}

static unsigned long input_uint(char const * msg) {
	for (;;) {
		printf("%s (unsigned integer >0): ", msg);
		std::string inp;
		std::getline(std::cin, inp);
		unsigned long l = strtoul(inp.c_str(), nullptr, 10);
		if (l > 0) return l;
		else {
			printf("Invalid input.\n");
		}
	}
}

static size_t input_index(char const * msg) {
	printf("%s (index): ", msg);
	std::string inp;
	std::getline(std::cin, inp);
	return strtoul(inp.c_str(), nullptr, 10);
}

static std::vector<char> input_charmap() {
	std::vector<char> char_map;
	
	if (input_yn("Uppercase Alphabet?")) {
		char_map.insert(char_map.end(), alphabet_upper, &alphabet_upper[sizeof(alphabet_upper)]);
	}
	if (input_yn("Lowercase Alphabet?")) {
		char_map.insert(char_map.end(), alphabet_lower, &alphabet_lower[sizeof(alphabet_lower)]);
	}
	if (input_yn("Numbers?")) {
		char_map.insert(char_map.end(), numeric, &numeric[sizeof(numeric)]);
	}
	if (input_yn("Additional Custom Characters?")) {
		std::string cuchars = input_strne("Additional Map Characters");
		char_map.insert(char_map.end(), cuchars.begin(), cuchars.end());
	}
	
	return char_map;
}

typedef std::unique_ptr<Cipher_Mode> ucmp;
struct cryptor {
	ucmp enc;
	ucmp dec;
	
	operator bool() {return enc && dec;}
};

cryptor get_cypher(char const * cipher) {
	cryptor c;
	c.enc = ucmp(get_cipher_mode(cipher, ENCRYPTION));
	c.dec = ucmp(get_cipher_mode(cipher, DECRYPTION));
	if (c) return c;
	else throw 1;
}

cryptor input_cipher(char const * msg) {
	std::string nstr (msg);
	nstr += " (<block cipher>/<cipher mode>)";
	cryptor c;
	for (;;) {
		std::string cname = input_strne(nstr.c_str());
		c.enc = ucmp(get_cipher_mode(cname, ENCRYPTION));
		c.dec = ucmp(get_cipher_mode(cname, DECRYPTION));
		if (c) return c;
		else {
			if (c.dec != c.enc) {
				printf("Cipher does not support both encryption and decryption.\n");
			} else {
				printf("Could not find that cipher.\n");
			}
		}
	}
	return c;
}

//================================================================
//----------------------------------------------------------------
//================================================================

static secure_vector<uint8_t> randb(unsigned long num) {
	AutoSeeded_RNG rng;
	return rng.random_vec(num);
}

static std::string randy(unsigned long num, std::vector<char> & char_map) {
	secure_vector<uint8_t> rbytes = randb(num);
	std::string chars;
	chars.reserve(rbytes.size());
	for (uint8_t b : rbytes) {
		chars.push_back( char_map[b % char_map.size()] );
	};
	return chars;
}

static std::string guided_randy() {
	unsigned long numc = input_uint("Num Characters");
	std::vector<char> char_map = input_charmap();
	for (;;) {
		std::string pwd = randy(numc, char_map);
		printf("New Password: %s\n", pwd.c_str());
		if (!input_yn("Regenerate?")) return pwd;
	}
}

static std::string passgen() {
	if (input_yn("Generate Password Randomly?")) {
		return guided_randy();
	} else {
		return input_strne("Enter Manual Password");
	}
}

std::vector<uint8_t> encrypt_vector(std::vector<uint8_t> encvec, cryptor & c, std::unique_ptr<HashFunction> & hash_func, std::string & key) {
	
	secure_vector<uint8_t> hash_buf = hash_func->process(key);
	if (!c.enc->key_spec().valid_keylength(hash_func->output_length())) {
		printf("WARNING: Hash output cannot be used as cipher input for this combination, truncation or padding will occur.\n");
		
		size_t 	olen = hash_func->output_length(),
				kmin = c.enc->key_spec().minimum_keylength(),
				kmax = c.enc->key_spec().maximum_keylength(),
				kmult = c.enc->key_spec().keylength_multiple();
		
		size_t ht = olen;
		ht = ht > kmax ? kmax : ht < kmin ? kmin : ht;
		ht = ceil(ht / (double) kmult) * kmult;
		if (!c.enc->key_spec().valid_keylength(ht)) {
			throw std::runtime_error("could not resolve truncate/pad");
		}
		
		printf("hash output size: %zu\ncipher key constraints(min: %zu, max: %zu, multiple: %zu)\nresolved hash output (after trunc/pad): %zu\n", olen, kmin, kmax, kmult, ht);
		
		hash_buf.resize(ht);
	}
	
	secure_vector<uint8_t> decvec {encvec.begin(), encvec.end()};
	
	c.enc->set_key(hash_buf);
	c.enc->start();
	c.enc->finish(decvec);
	
	return {decvec.begin(), decvec.end()};
}

std::vector<uint8_t> decrypt_vector(std::vector<uint8_t> decvec, cryptor & c, std::unique_ptr<HashFunction> & hash_func, std::string & key) {
	
	secure_vector<uint8_t> hash_buf = hash_func->process(key);
	if (!c.enc->key_spec().valid_keylength(hash_func->output_length())) {
		printf("WARNING: Hash output cannot be used as cipher input for this combination, truncation or padding will occur.\n");
		
		size_t 	olen = hash_func->output_length(),
				kmin = c.enc->key_spec().minimum_keylength(),
				kmax = c.enc->key_spec().maximum_keylength(),
				kmult = c.enc->key_spec().keylength_multiple();
		
		size_t ht = olen;
		ht = ht > kmax ? kmax : ht < kmin ? kmin : ht;
		ht = ceil(ht / (double) kmult) * kmult;
		if (!c.enc->key_spec().valid_keylength(ht)) {
			throw std::runtime_error("could not resolve truncate/pad");
		}
		
		printf("hash output size: %zu\ncipher key constraints(min: %zu, max: %zu, multiple: %zu)\nresolved hash output (after trunc/pad): %zu\n", olen, kmin, kmax, kmult, ht);
		
		hash_buf.resize(ht);
	}
	
	secure_vector<uint8_t> encvec {decvec.begin(), decvec.end()};
	
	c.dec->set_key(hash_buf);
	c.dec->start();
	c.dec->finish(encvec);
	
	return {encvec.begin(), encvec.end()};
}

//================================================================
//----------------------------------------------------------------
//================================================================

static void cmd_hash() {
	
	std::unique_ptr<HashFunction> func = input_hash("Hash Function");
	std::string str = input_strne("Hash Text");
	auto vec = func->process(str.c_str());
	print_bytes(vec);
	
}

static void cmd_cipher() {
	
	std::string key = input_strne("Key");
	cryptor c = input_cipher("Cipher");
	std::unique_ptr<HashFunction> hash = input_hash("Key Hash Function");
	secure_vector<uint8_t> hash_buf = hash->process(key);
	
	if (!c.enc->key_spec().valid_keylength(hash->output_length())) {
		printf("WARNING: Hash output cannot be used as cipher input for this combination, truncation or padding will occur.\n");
		
		size_t 	olen = hash->output_length(),
				kmin = c.enc->key_spec().minimum_keylength(),
				kmax = c.enc->key_spec().maximum_keylength(),
				kmult = c.enc->key_spec().keylength_multiple();
		
		size_t ht = olen;
		ht = ht > kmax ? kmax : ht < kmin ? kmin : ht;
		ht = ceil(ht / (double) kmult) * kmult;
		if (!c.enc->key_spec().valid_keylength(ht)) {
			throw std::runtime_error("could not resolve truncate/pad");
		}
		
		printf("hash output size: %zu\ncipher key constraints(min: %zu, max: %zu, multiple: %zu)\nresolved hash output (after trunc/pad): %zu\n", olen, kmin, kmax, kmult, ht);
		
		hash_buf.resize(ht);
	}
	
	printf("key hash: ");
	print_bytes(hash_buf);
	
	std::string ttext = input_strne("Text");
	secure_vector<uint8_t> tbuf;
	tbuf.reserve(ttext.length());
	for (char c : ttext) tbuf.push_back(*reinterpret_cast<unsigned char *>(&c));
	
	c.enc->set_key(hash_buf);
	c.enc->start();
	c.enc->finish(tbuf);
	
	printf("encoded block: ");
	print_bytes(tbuf);
	
	c.dec->set_key(hash_buf);
	c.dec->start();
	c.dec->finish(tbuf);
	
	printf("decoded block: ");
	print_ascii(tbuf);
}

static void cmd_random() {

	std::string chars = guided_randy();
	printf("%s\n", chars.c_str());
}

static void cmd_random_hex() {

	auto vec = randb(input_uint("number of bytes"));
	print_bytes(vec);
}

static void cmd_add() {
	
	archive_entry ent {
		input_strne("Site"),
		input_str("Username"),
		passgen(),
		input_str("Additional Info"),
	};
	entries.push_back( ent );
	
}

static void cmd_list() {
	for (size_t i = 0; i < entries.size(); i++) {
		print_entry(i);
	}
}

static void cmd_remove() {
	size_t index = input_index("Entries Index");
	print_entry(index);
	if (input_yn("Remove This Entry?")) {
		entries.erase(entries.begin() + index);
	}
}

static void cmd_find() {
	std::string findstr = input_strne("Substring");
	printf("\nMatches:\n\n");
	for (size_t i = 0; i < entries.size(); i++) {
		if (entries[i].site.find(findstr) != std::string::npos || entries[i].user.find(findstr) != std::string::npos) {
			print_entry(i);
		}
	}
}

static void cmd_save(std::fstream & archive_file) {
	try {
		archive_file = std::fstream {archive_path, std::ios::in | std::ios::out | std::ios::binary | std::ios::trunc};
		std::vector<uint8_t> save_buffer = compress_entries();
		
		cryptor crypt = stored_cryptor.size() ? get_cypher(stored_cryptor.c_str()) : input_cipher("Vault Cipher");
		std::unique_ptr<HashFunction> hash = stored_hash.size() ? HashFunction::create(stored_hash.c_str()) : input_hash("Vault Key Hash Function");
		std::string key = stored_key.size() ? stored_key.c_str() : input_strne("Vault Key");
		
		std::vector<uint8_t> enc_save_buffer = encrypt_vector(save_buffer, crypt, hash, key);
		std::vector<uint8_t> verify_buf = decrypt_vector(enc_save_buffer, crypt, hash, key);
		decompress_entries(verify_buf);
		
		archive_file.write(reinterpret_cast<char *>(enc_save_buffer.data()), enc_save_buffer.size());
	} catch (std::exception & e) {
		
	}
}

static void cmd_passwd() {
	size_t index = input_index("Entries Index");
	print_entry(index);
	if (input_yn("Change Password for This Entry?")) {
		entries[index].pwd = passgen();
	}
}

static void cmd_info() {
	size_t index = input_index("Entries Index");
	print_entry(index);
	if (input_yn("Change Info for This Entry?")) {
		entries[index].additional_info = input_str("Additional Info");
	}
}

//================================================================
//----------------------------------------------------------------
//================================================================

int main(int argc, char * * argv) {
	
	bool archive_mode = false;
	std::fstream archive_file {};
	
	switch (argc) {
		case 1:
			if (input_yn("Load archive?")) archive_mode = true; else break;
			archive_path = input_strne("Load File");
			break;
		default:
			archive_mode = true;
			archive_path = argv[1];
			break;
	}
	
	if (archive_mode) {
		
		if (!std::experimental::filesystem::exists(archive_path)) {
			printf("File ('%s') does not exist.\n", archive_path.c_str());
			if (!input_yn("Create new archive?")) return 0;
			std::ofstream cf {archive_path, std::ios::out | std::ios::binary};
		}
		
		archive_file = std::fstream {archive_path, std::ios::in | std::ios::out | std::ios::binary | std::ios::ate};
		if (!archive_file.good()) {
			printf("Failed to open file('%s') for r/w; check permissions.\n", archive_path.c_str());
			return 1;
		}
		
		std::fstream::pos_type pos = archive_file.tellg();
		archive_file.seekg(0, std::ios::beg);
		std::vector<uint8_t> archive_buffer {};
		archive_buffer.resize(pos);
		archive_file.read(reinterpret_cast<char *>(archive_buffer.data()), pos);
		
		if (argc >= 3) { stored_cryptor = argv[2]; }
		if (argc >= 4) { stored_hash = argv[3]; }
		if (argc >= 5) { stored_key = argv[4]; }
		
		if (pos > 0) {
			cryptor crypt = stored_cryptor.size() ? get_cypher(stored_cryptor.c_str()) : input_cipher("Vault Cipher");
			std::unique_ptr<HashFunction> hash = stored_hash.size() ? HashFunction::create(stored_hash.c_str()) : input_hash("Vault Key Hash Function");
			std::string key = stored_key.size() ? stored_key.c_str() : input_strne("Vault Key");
			
			try {
				std::vector<uint8_t> decrypted_buffer = decrypt_vector(archive_buffer, crypt, hash, key);
				decompress_entries(decrypted_buffer);
			} catch (std::exception & e) {
				std::cout << e.what() << std::endl;
				return -1;
			}
		}
	
	}
	
	for (;;) { //event loop
		std::string inp;
		printf("(boa)> ");
		std::getline(std::cin, inp);
		
		if (inp == "hash") {
			cmd_hash();
		} else if (inp == "cipher") {
			cmd_cipher();
		} else if (inp == "rand") {
			cmd_random();
		} else if (inp == "randhex") {
			cmd_random_hex();
		} else if (inp == "add") {
			cmd_add();
		} else if (inp == "list") {
			cmd_list();
		} else if (inp == "remove") {
			cmd_remove();
		} else if (inp == "find") {
			cmd_find();
		} else if (inp == "save") {
			if (archive_mode) cmd_save(archive_file);
			else printf("Cannot save, not in archive mode.\n");
		} else if (inp == "passwd") {
			cmd_passwd();
		} else if (inp == "info") {
			cmd_info();
		} else if (inp == "exit" || inp == "quit") {
			break;
		} else if (inp == "help") {
			printf("commands: hash, cipher, rand, add, list, remove, find, save, passwd, exit, quit, help\n");
		} else {
			printf("Unrecognized command.\n");
		}
	}
	
	if (archive_mode && input_yn("Save?")) cmd_save(archive_file);
	
	return 0;
}

//================================================================
//----------------------------------------------------------------
//================================================================
