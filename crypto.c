#include "include/crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SALT_SIZE 16
#define IV_SIZE 16
#define KEY_SIZE 32
#define BUFFER_SIZE 4096

int derive_key_from_password(const char *password, unsigned char *salt, unsigned char *key, size_t key_len) {
    return PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, 100000, EVP_sha256(), key_len, key);
}

static void handle_errors(const char *msg) {
    fprintf(stderr, "\033[31m[ERROR]\033[0m %s\n", msg);
}

int encrypt_file(const char *infile, const char *outfile, const unsigned char *key, size_t key_len) {
    FILE *fin = fopen(infile, "rb");
    FILE *fout = fopen(outfile, "wb");
    if (!fin || !fout) {
        handle_errors("Failed to open input/output file.");
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return -1;
    }

    unsigned char salt[SALT_SIZE], iv[IV_SIZE];
    if (!RAND_bytes(salt, SALT_SIZE) || !RAND_bytes(iv, IV_SIZE)) {
        handle_errors("Failed to generate random bytes.");
        fclose(fin);
        fclose(fout);
        return -1;
    }

    fwrite(salt, 1, SALT_SIZE, fout);
    fwrite(iv, 1, IV_SIZE, fout);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_errors("Failed to create cipher context.");
        fclose(fin);
        fclose(fout);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handle_errors("EVP_EncryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        fclose(fout);
        return -1;
    }

    unsigned char inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            handle_errors("EVP_EncryptUpdate failed.");
            EVP_CIPHER_CTX_free(ctx);
            fclose(fin);
            fclose(fout);
            return -1;
        }
        fwrite(outbuf, 1, outlen, fout);
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        handle_errors("EVP_EncryptFinal_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        fclose(fout);
        return -1;
    }
    fwrite(outbuf, 1, outlen, fout);

    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
    fclose(fout);
    return 0;
}

int decrypt_file(const char *infile, const char *outfile, const unsigned char *key, size_t key_len) {
    FILE *fin = fopen(infile, "rb");
    FILE *fout = fopen(outfile, "wb");
    if (!fin || !fout) {
        handle_errors("Failed to open input/output file.");
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return -1;
    }

    unsigned char salt[SALT_SIZE], iv[IV_SIZE];
    if (fread(salt, 1, SALT_SIZE, fin) != SALT_SIZE || fread(iv, 1, IV_SIZE, fin) != IV_SIZE) {
        handle_errors("Failed to read salt/IV from input.");
        fclose(fin);
        fclose(fout);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_errors("Failed to create cipher context.");
        fclose(fin);
        fclose(fout);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handle_errors("EVP_DecryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        fclose(fout);
        return -1;
    }

    unsigned char inbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH], outbuf[BUFFER_SIZE];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, fin)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            handle_errors("EVP_DecryptUpdate failed.");
            EVP_CIPHER_CTX_free(ctx);
            fclose(fin);
            fclose(fout);
            return -1;
        }
        fwrite(outbuf, 1, outlen, fout);
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        handle_errors("EVP_DecryptFinal_ex failed: incorrect password or corrupted file.");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        fclose(fout);
        return -1;
    }
    fwrite(outbuf, 1, outlen, fout);

    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
    fclose(fout);
    return 0;
}
