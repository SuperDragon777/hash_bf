#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <ctype.h>
#include <math.h>

#ifdef _WIN32
    #include <windows.h>
#endif

#define MAX_LEN 6
#define CHARSET "abcdefghijklmnopqrstuvwxyz0123456789"
#define CHARSET_LEN 36
#define MAX_DIGEST_LEN 64

typedef struct {
    char name[10];
    const char *algo_name;
    int digest_len;
} HashAlgo;

void hash_data(const char *algo_name, unsigned char *data, unsigned int len, unsigned char *digest, int *digest_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_get_digestbyname(algo_name);
    
    if (!md) {
        fprintf(stderr, "Unknown algorithm: %s\n", algo_name);
        EVP_MD_CTX_free(mdctx);
        return;
    }
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, digest, (unsigned int *)digest_len);
    EVP_MD_CTX_free(mdctx);
}

void hash_to_hex(unsigned char *hash, int len, char *hex_str) {
    for (int i = 0; i < len; i++) {
        sprintf(hex_str + (i * 2), "%02x", hash[i]);
    }
    hex_str[len * 2] = '\0';
}

long long calculate_total(int max_len) {
    long long total = 0;
    for (int i = 1; i <= max_len; i++) {
        long long power = 1;
        for (int j = 0; j < i; j++) power *= CHARSET_LEN;
        total += power;
    }
    return total;
}

void generate_combinations(int length, char *target_hash, HashAlgo *algorithms, int algo_count) {
    char pwd[MAX_LEN + 1];
    unsigned char hash[MAX_DIGEST_LEN];
    char hash_hex[2 * MAX_DIGEST_LEN + 1];
    long long total = calculate_total(MAX_LEN);
    long long attempt = 0;
    
    for (int idx = 0; idx < length; idx++) pwd[idx] = CHARSET[0];
    pwd[length] = '\0';
    
    while (1) {
        attempt++;
        
        if (attempt % 10000 == 0) {
            double percent = (attempt / (double)total) * 100;
            printf("    [%lld] %.1f%%\r", attempt, percent);
            fflush(stdout);
        }
        
        for (int a = 0; a < algo_count; a++) {
            int digest_len;
            hash_data(algorithms[a].algo_name, (unsigned char*)pwd, strlen(pwd), hash, &digest_len);
            hash_to_hex(hash, digest_len, hash_hex);
            
            if (strcmp(hash_hex, target_hash) == 0) {
                printf("\n[+] FOUND!\n");
                printf("    Password: %s\n", pwd);
                printf("    Algorithm: %s\n", algorithms[a].name);
                printf("    Attempts: %lld\n", attempt);
                return;
            }
        }
        
        int pos = length - 1;
        while (pos >= 0) {
            int char_idx = strchr(CHARSET, pwd[pos]) - CHARSET;
            if (char_idx < CHARSET_LEN - 1) {
                pwd[pos] = CHARSET[char_idx + 1];
                break;
            } else {
                pwd[pos] = CHARSET[0];
                pos--;
            }
        }
        
        if (pos < 0) break;
    }
    
    printf("\n[-] Not found (checked: %lld)\n", attempt);
}

int main() {
    #ifdef _WIN32
        SetConsoleCP(65001);
        SetConsoleOutputCP(65001);
        setvbuf(stdout, NULL, _IONBF, 0);
    #endif

    printf("HASH BRUTE FORCER\n");
    
    char target_hash[2 * MAX_DIGEST_LEN + 1];
    printf("\nEnter hash to crack: ");
    fgets(target_hash, sizeof(target_hash), stdin);
    
    size_t len = strlen(target_hash);
    if (len > 0 && target_hash[len - 1] == '\n') {
        target_hash[len - 1] = '\0';
    }
    
    if (strlen(target_hash) == 0) {
        printf("[!] No hash entered\n");
        return 1;
    }
    
    HashAlgo algorithms[] = {
        {"MD5", "md5", 16},
        {"SHA1", "sha1", 20},
        {"SHA256", "sha256", 32},
        {"SHA512", "sha512", 64},
    };
    int algo_count = 4;
    
    printf("\n[*] Checking all algorithms...\n");
    
    for (int length = 1; length <= MAX_LEN; length++) {
        printf("\n[*] Checking passwords of length %d...\n", length);
        generate_combinations(length, target_hash, algorithms, algo_count);
    }
    
    return 0;
}
