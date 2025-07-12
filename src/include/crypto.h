#pragma once

#include <stddef.h>

int encrypt_file(const char *infile, const char *outfile, const unsigned char *key, size_t key_len);
int decrypt_file(const char *infile, const char *outfile, const unsigned char *key, size_t key_len);
int derive_key_from_password(const char *password, unsigned char *salt, unsigned char *key, size_t key_len);
