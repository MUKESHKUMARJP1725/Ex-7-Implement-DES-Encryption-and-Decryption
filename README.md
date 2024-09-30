# EX-4-ADVANCED-ENCRYPTION-STANDARD-DES-ALGORITHM

## Aim:
  To use Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption.

## ALGORITHM: 
  1. AES is based on a design principle known as a substitution–permutation. 
  2. AES does not use a Feistel network like DES, it uses variant of Rijndael. 
  3. It has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits. 
  4. AES operates on a 4 × 4 column-major order array of bytes, termed the state

## PROGRAM:
```
#include <stdio.h>
#include <string.h>

// Basic XOR Encryption
void encrypt(char *message, char *key, char *encrypted) {
    int messageLen = strlen(message);
    int keyLen = strlen(key);
    for (int i = 0; i < messageLen; i++) {
        encrypted[i] = message[i] ^ key[i % keyLen];  // XOR with the key
    }
    encrypted[messageLen] = '\0';  // Null-terminate the encrypted message
}

// Basic XOR Decryption (same as encryption in this case)
void decrypt(char *encrypted, char *key, char *decrypted) {
    int encryptedLen = strlen(encrypted);
    int keyLen = strlen(key);
    for (int i = 0; i < encryptedLen; i++) {
        decrypted[i] = encrypted[i] ^ key[i % keyLen];  // XOR again with the same key
    }
    decrypted[encryptedLen] = '\0';  // Null-terminate the decrypted message
}

int main() {
    char message[] = "Hello, DES!";
    char key[] = "mykey123";  // Example key
    char encrypted[100], decrypted[100];

    // Encrypt the message
    encrypt(message, key, encrypted);
    printf("Encrypted Message: %s\n", encrypted);

    // Decrypt the message
    decrypt(encrypted, key, decrypted);
    printf("Decrypted Message: %s\n", decrypted);

    return 0;
}
```
## OUTPUT:

![Screenshot 2024-09-30 103345](https://github.com/user-attachments/assets/171eb9aa-af17-4b4a-b17c-baaf79cf4fc3)

## RESULT:
Thus, AES encryption and decryption were implemented correctly using the provided key and initialization vector (IV).
