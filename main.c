#include <stdio.h>
#include <sodium.h>
#include <string.h>

static const unsigned char sigma[16] = {
  'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
};

int LoadSecretKeyFromFile(unsigned char *secretKey, char *filename);
int LoadPublicKeyFromFile(unsigned char *publicKey, char *filename);
int EncryptFile(char *filename, unsigned char *secretKey, unsigned char *publicKey);
int DecryptFile(char *filename, unsigned char *secretKey, unsigned char *publicKey);
int GenerateKey(char *name);
void PrintUsage();

typedef enum {CMD_MAKE_KEY, CMD_ENCRYPT, CMD_DECRYPT} command_t;

int main(int argc, char *argv[])
{
  command_t command;

  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretKey[crypto_box_SECRETKEYBYTES];

  if (sodium_init() == -1) {
    printf("ERROR: Can't initialize libSodium. Stopping.\n");
    return 1;
  }

  if (argc < 2) {
    PrintUsage();
    return 0;
  }

  if (strcmp(argv[1], "genkey") == 0) {
    command = CMD_MAKE_KEY;
  } else if (strcmp(argv[1], "encrypt") == 0) {
    command = CMD_ENCRYPT;
  } else if (strcmp(argv[1], "decrypt") == 0) {
    command = CMD_DECRYPT;
  } else {
    printf("Unknown command: %s\n\n", argv[1]);
    PrintUsage();
    return 1;
  }

  switch (command) {
    case CMD_MAKE_KEY:
      if (argc < 3) {
        printf("Need name for keypair\n\n");
        PrintUsage();
        return 1;
      }
      return GenerateKey(argv[2]);
      break;
    case CMD_ENCRYPT:
      if (argc < 5) {
        printf("Need file, secret key file, and public key file\n\n");
        PrintUsage();
        return 1;
      }
      if (!LoadSecretKeyFromFile(secretKey, argv[3]) && 
          !LoadPublicKeyFromFile(publicKey, argv[4]))
      {
        return EncryptFile(argv[2], secretKey, publicKey);
      } else {
        return 1;
      }
      break;
    case CMD_DECRYPT:
      if (argc < 5) {
        printf("Need file, secret key file, and public key file\n\n");
        PrintUsage();
        return 1;
      }
      if (!LoadSecretKeyFromFile(secretKey, argv[3]) && 
          !LoadPublicKeyFromFile(publicKey, argv[4]))
      {
        return DecryptFile(argv[2], secretKey, publicKey);
      } else {
        return 1;
      }
      break;
  }

  sodium_memzero(secretKey, sizeof secretKey);
  sodium_memzero(publicKey, sizeof publicKey);
  return 0;
}

int LoadSecretKeyFromFile(unsigned char *secretKey, char *filename) {
  FILE *f;
  int ret = 0;
  // Load Secret Key
  f = fopen(filename, "rb");
  if (f == NULL) {
    printf("Failed to open file %s for loading secret key\n", filename);
    ret = 1;
  } else {
    if (fread(secretKey, sizeof(char), crypto_box_SECRETKEYBYTES, f) < crypto_box_SECRETKEYBYTES) {
      ret = 1;
      printf("Failed to read secret key from %s\n", filename);
    }
  }
  fclose(f);
  return ret;
}

int LoadPublicKeyFromFile(unsigned char *publicKey, char *filename) {
  FILE *f;
  int ret = 0;
  // Load Public Key
  f = fopen(filename, "rb");
  if (f == NULL) {
    printf("Failed to open file %s for loading public key\n", filename);
    ret = 1;
  } else {
    if (fread(publicKey, sizeof(char), crypto_box_PUBLICKEYBYTES, f) < crypto_box_PUBLICKEYBYTES) {
      ret = 1;
      printf("Failed to read public key from %s\n", filename);
    }
  }
  fclose(f);
  return ret;
}

// EncryptFile - Encrypt file filename with publicKey, signing with secretKey {{{
int EncryptFile(char *filename, unsigned char *secretKey, unsigned char *publicKey)
{
  int ret = 0;
  char *outFilename = malloc(strlen(filename) + 11);
  FILE *f;
  FILE *outFile;

  // Prepare files for reading and writing
  f = fopen(filename, "rb");
  if (f == NULL) {
    printf("Failed to open file %s for encrypting\n", filename);
    ret = 1;
  }
  strcpy(outFilename, filename);
  strcat(outFilename, ".encrypted");
  outFile = fopen(outFilename, "wb");
  if (outFile == NULL) {
    printf("Failed to open file %s for encrypting\n", outFilename);
    ret = 1;
  }

  // Perform encryption
  unsigned char keyNonce[crypto_box_NONCEBYTES];
  unsigned char fileKey[crypto_stream_KEYBYTES]; // Secret key for stream cipher
  unsigned char fileNonce[crypto_stream_NONCEBYTES]; // Nonce for given fileKey
  unsigned char fileKeyCipher[crypto_secretbox_MACBYTES + sizeof fileKey + sizeof fileNonce];
  unsigned char block[64];
  unsigned char readSize;
  uint64_t ic;
  unsigned char subkey[32];
  if (ret == 0) {

    // Create Symmetric Key and necessary nonces
    randombytes_buf(keyNonce, sizeof keyNonce);
    randombytes_buf(fileNonce, sizeof fileNonce);
    randombytes_buf(fileKey, sizeof fileKey);
    memcpy((void *)fileKeyCipher, (void *)fileKey, sizeof fileKey);
    memcpy((void *)fileKeyCipher + sizeof fileKey, (void *)fileNonce, sizeof fileNonce);
    crypto_box_easy(fileKeyCipher, fileKeyCipher,
        sizeof fileKey + sizeof fileNonce,
        keyNonce, publicKey, secretKey);
    // Write Version, keyNonce, and encrypted & signed Symmetric key and nonce
    fputc(1, outFile); // Version 1 of Cipher
    fwrite((void *)keyNonce, sizeof(char), sizeof keyNonce, outFile);
    fwrite((void *)fileKeyCipher, sizeof(char), sizeof fileKeyCipher, outFile);

    // Actually perform file stream encryption
    // TODO: Add HMAC at the end of the stream
    crypto_core_hsalsa20(subkey, fileNonce, fileKey, sigma);
    ic = 0;
    readSize = fread((void *)block, sizeof(char), sizeof block, f);
    while (readSize > 0)
    {
      // WATCH OUT: I'm using crypto_steam_xor_ic here. I *think* I know 
      // what I'm doing, but I'm honestly not positive this is a secure way to 
      // process a file stream
      crypto_stream_salsa20_xor_ic(block, block, readSize, fileNonce+16, ic, subkey);
      ic++;
      fwrite((void *)block, sizeof(char), readSize, outFile);
      readSize = fread((void *)block, sizeof(char), sizeof block, f);
    }
  }
  
  // Close out files and zero out sensitive memory
  fclose(f);
  fclose(outFile);
  sodium_memzero(subkey, sizeof subkey);
  sodium_memzero(fileKeyCipher, sizeof fileKeyCipher);
  sodium_memzero(keyNonce, sizeof keyNonce);
  sodium_memzero(fileKey, sizeof fileKey);
  free(outFilename);
  return ret;
}
//}}}

// DecryptFile - Decrypt file filename with secretKey, verifying with publicKey {{{
int DecryptFile(char *filename, unsigned char *secretKey, unsigned char *publicKey)
{
  int ret = 0;
  char *outFilename = malloc(strlen(filename)+11);
  FILE *f;
  FILE *outFile;

  // Prepare files for reading and writing
  f = fopen(filename, "rb");
  if (f == NULL) {
    printf("Failed to open file %s for decrypting\n", filename);
    ret = 1;
  }
  strcpy(outFilename, filename);
  char *lastdot = strrchr(outFilename, '.');
  char *lastsep = strrchr(outFilename, '/');
  if (lastdot != NULL) {
    char *fileEnding = strstr(lastdot, "encrypted");
    if ((fileEnding != NULL) && (lastdot > lastsep)) {
      *lastdot = '\0';
    } else {
      strcat(outFilename, ".decrypted");
    }
  } else {
    strcat(outFilename, ".decrypted");
  }
  printf("Decrypting to %s\n", outFilename);

  outFile = fopen(outFilename, "wb");
  if (outFile == NULL) {
    printf("Failed to open file %s for decrypting\n", outFilename);
    ret = 1;
  }

  // Perform decryption
  unsigned char keyNonce[crypto_box_NONCEBYTES];
  unsigned char fileKey[crypto_stream_KEYBYTES]; // Secret key for stream cipher
  unsigned char fileNonce[crypto_stream_NONCEBYTES]; // Nonce for given fileKey
  unsigned char fileKeyCipher[crypto_secretbox_MACBYTES + sizeof fileKey + sizeof fileNonce];
  unsigned char block[64];
  unsigned char readSize;
  uint64_t ic;
  unsigned char subkey[32];
  int version;
  if (ret == 0) {

    // Fetch version, nonce for encrypted file key, and encrypted file key & file nonce
    version = fgetc(f);
    if (version > 1) {
      printf("Version number is greater than supported. Please upgrade this program.\n");
    }
    fread((void *)keyNonce, sizeof(char), sizeof keyNonce, f);
    fread((void *)fileKeyCipher, sizeof(char), sizeof fileKeyCipher, f);
    if (crypto_box_open_easy(fileKeyCipher, fileKeyCipher, sizeof fileKeyCipher, keyNonce,
          publicKey, secretKey) != 0) {
      printf("Authentication failed! Does not match with public key provided.\n");
    }
    memcpy((void *)fileKey, (void *)fileKeyCipher, sizeof fileKey);
    memcpy((void *)fileNonce, (void *)fileKeyCipher + sizeof fileKey, sizeof fileNonce);

    // Actually perform the stream decryption of the file
    crypto_core_hsalsa20(subkey, fileNonce, fileKey, sigma);
    ic = 0;
    readSize = fread((void *)block, sizeof(char), sizeof block, f);
    while (readSize > 0)
    {
      // WATCH OUT: I'm using crypto_steam_xor_ic here. I *think* I know 
      // what I'm doing, but I'm honestly not positive this is a secure way to 
      // process a file stream
      crypto_stream_salsa20_xor_ic(block, block, readSize, fileNonce+16, ic, subkey);
      ic++;
      fwrite((void *)block, sizeof(char), readSize, outFile);
      readSize = fread((void *)block, sizeof(char), sizeof block, f);
    }
  }

  // Close out files, free up allocated memory, zero out sensitive data
  fclose(f);
  fclose(outFile);
  sodium_memzero(subkey, sizeof subkey);
  sodium_memzero(fileKeyCipher, sizeof fileKeyCipher);
  sodium_memzero(keyNonce, sizeof keyNonce);
  sodium_memzero(fileKey, sizeof fileKey);
  free(outFilename);
  return ret;
}
//}}}

// GenerateKey - Generate Keypair {{{
int GenerateKey(char *name)
{
  int ret;
  unsigned char publickey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretKey[crypto_box_SECRETKEYBYTES];
  char *filename = malloc(strlen(name) + 12); // .secretKey + 1
  FILE *f;
  // Generate Keypair
  ret = crypto_box_keypair(publickey, secretKey);
  if (ret != 0) {
    printf("Failed to generate keypair\n");
  }
  // Write Secret Key
  if (ret == 0) {
    strcpy(filename, name);
    strcat(filename, ".secretKey");
    f = fopen(filename, "wb");
    if (f == NULL) {
      ret = 1;
      printf("Could not open %s for writing\n", filename);
    } else {
      fwrite((void *)secretKey, sizeof(char), crypto_box_SECRETKEYBYTES, f);
      fclose(f);
    }
  }
  // Write Public Key
  if (ret == 0) {
    strcpy(filename, name);
    strcat(filename, ".publickey");
    f = fopen(filename, "wb");
    if (f == NULL) {
      ret = 1;
      printf("Could not open %s for writing\n", filename);
    } else {
      fwrite((void *)publickey, sizeof(char), crypto_box_PUBLICKEYBYTES, f);
      fclose(f);
    }
  }
  // Close out function
  if (ret == 0) {
    printf("Generated keypair %s\n", name);
  }
  sodium_memzero(secretKey, sizeof secretKey);
  free(filename);
  return ret;
}
//}}}

// PrintUsage - Print program usage {{{
void PrintUsage() {
    printf(
        "Usage:\n"
        "cryptid genkey [NAME] - Generate key named NAME\n"
        "    Generate a public and secret key\n"
        "cryptid encrypt FILE SECRETKEY PUBLICKEY\n"
        "    Encrypt FILE using PUBLICKEY file and sign it using SECRETKEY\n"
        "cryptid decrypt FILE SECRETKEY PUBLICKEY\n"
        "    Decrypt FILE using SECRETKEY file, checking signature against PUBLICKEY\n"
        );
}
//}}}

// vim:set fdm=marker:
