#include "include/crypto.h"
#include "include/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define KEY_LEN 32

static char *arg_value(int *argc, char ***argv, const char *key) {
    for (int i = 0; i < *argc; i++) {
        if (strncmp((*argv)[i], key, strlen(key)) == 0) {
            if ((*argv)[i][strlen(key)] == '=') {
                char *val = (*argv)[i] + strlen(key) + 1;
                for (int j = i; j < *argc - 1; j++) (*argv)[j] = (*argv)[j+1];
                (*argc)--;
                return val;
            } else if (i + 1 < *argc) {
                char *val = (*argv)[i+1];
                for (int j = i; j < *argc - 2; j++) (*argv)[j] = (*argv)[j+2];
                (*argc) -= 2;
                return val;
            }
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    print_banner();

    if (argc < 3) {
        print_help(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    const char *file = argv[2];

    argc -= 3;
    argv += 3;

    int remove_after_lock = 0;
    char *custom_encrypt_key = NULL;
    char *inline_password = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--rm") == 0) {
            remove_after_lock = 1;
            for (int j = i; j < argc - 1; j++) argv[j] = argv[j+1];
            argc--;
            i--;
        }
    }

    custom_encrypt_key = arg_value(&argc, &argv, "--encrypt-key");
    inline_password = arg_value(&argc, &argv, "--password");

    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        print_help(argv[-3]);
        return 0;
    }

    unsigned char key[KEY_LEN];
    unsigned char salt[16];

    int result = 0;

    if (strcmp(cmd, "lock") == 0) {
        char *password = NULL;

        if (custom_encrypt_key) {
            size_t len = strlen(custom_encrypt_key);
            if (len != KEY_LEN) {
                print_info("Custom key must be exactly 32 bytes (256 bits).");
                return 1;
            }
            memcpy(key, custom_encrypt_key, KEY_LEN);
        } else {
            password = prompt_password("Enter password: ");
            if (!password) {
                print_error("Failed to read password.");
                return 1;
            }
            if (derive_key_from_password(password, salt, key, KEY_LEN) != 1) {
                print_error("Failed to derive key from password.");
                free(password);
                return 1;
            }
            free(password);
        }

        char out[1024];
        snprintf(out, sizeof(out), "%s.lock", file);
        print_info("Encrypting...");
        result = encrypt_file(file, out, key, KEY_LEN);

        if (result == 0 && remove_after_lock) {
            if (unlink(file) == 0) {
                print_info("Original file removed.");
            } else {
                print_error("Failed to remove original file.");
            }
        }
    } else if (strcmp(cmd, "unlock") == 0) {
        char *password = NULL;

        if (inline_password) {
            password = inline_password;
        } else {
            password = prompt_password("Enter password: ");
            if (!password) {
                print_error("Failed to read password.");
                return 1;
            }
        }

        if (derive_key_from_password(password, salt, key, KEY_LEN) != 1) {
            print_error("Failed to derive key from password.");
            if (password != inline_password) free(password);
            return 1;
        }

        char out[1024];
        snprintf(out, sizeof(out), "%s.dec", file);
        print_info("Decrypting...");
        result = decrypt_file(file, out, key, KEY_LEN);

        if (password != inline_password) free(password);
    } else {
        print_error("Invalid command. Use lock or unlock.");
        print_help(argv[-3]);
        return 1;
    }

    if (result == 0) {
        print_info("Operation successful.");
        return 0;
    } else {
        print_error("Operation failed.");
        return 1;
    }
}
