#include <stdio.h>
#include <sodium.h>
#include <string.h>

static const unsigned char sigma[16] = {
  'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
};

int EncryptFile(char *filename, char *privatefile, char *publicfile);
int DecryptFile(char *filename, char *privatefile, char *publicfile);
int GenerateKey(char *name);
void PrintUsage();

typedef enum {CMD_MAKE_KEY, CMD_ENCRYPT, CMD_DECRYPT} command_t;

int main(int argc, char *argv[])
{
  command_t command;

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
        printf("Need file, private key file, and public key file\n\n");
        PrintUsage();
        return 1;
      }
      return EncryptFile(argv[2], argv[3], argv[4]);
      break;
    case CMD_DECRYPT:
      if (argc < 5) {
        printf("Need file, private key file, and public key file\n\n");
        PrintUsage();
        return 1;
      }
      return DecryptFile(argv[2], argv[3], argv[4]);
      break;
  }

  return 0;
}

// EncryptFile - Encrypt file filename with key in public file, signing with key in privatefile {{{
int EncryptFile(char *filename, char *privatefile, char *publicfile)
{
  int ret = 0;
  char *outFilename = malloc(strlen(filename) + 11);
  FILE *f;
  FILE *outFile;
  unsigned char publickey[crypto_box_PUBLICKEYBYTES];
  unsigned char privatekey[crypto_box_SECRETKEYBYTES];
  // Load Public Key
  f = fopen(publicfile, "rb");
  if (f == NULL) {
    printf("Failed to open file %s for loading public key\n", publicfile);
    ret = 1;
  } else {
    if (fread(publickey, sizeof(char), crypto_box_PUBLICKEYBYTES, f) < crypto_box_PUBLICKEYBYTES) {
      ret = 1;
      printf("Failed to read public key from %s\n", publicfile);
    }
  }
  fclose(f);

  // Load Private Key
  f = fopen(privatefile, "rb");
  if (f == NULL) {
    printf("Failed to open file %s for loading private key\n", privatefile);
    ret = 1;
  } else {
    if (fread(privatekey, sizeof(char), crypto_box_SECRETKEYBYTES, f) < crypto_box_SECRETKEYBYTES) {
      ret = 1;
      printf("Failed to read private key from %s\n", privatefile);
    }
  }
  fclose(f);

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

    randombytes_buf(keyNonce, sizeof keyNonce);
    randombytes_buf(fileNonce, sizeof fileNonce);
    randombytes_buf(fileKey, sizeof fileKey);
    memcpy((void *)fileKeyCipher, (void *)fileKey, sizeof fileKey);
    memcpy((void *)fileKeyCipher + sizeof fileKey, (void *)fileNonce, sizeof fileNonce);
    crypto_box_easy(fileKeyCipher, fileKeyCipher, sizeof fileKey + sizeof fileNonce, keyNonce, publickey, privatekey);
    fputc(1, outFile); // Version 1 of Cipher
    fwrite((void *)keyNonce, sizeof(char), sizeof keyNonce, outFile);
    fwrite((void *)fileKeyCipher, sizeof(char), sizeof fileKeyCipher, outFile);

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
  
  fclose(f);
  fclose(outFile);
  sodium_memzero(subkey, sizeof subkey);
  sodium_memzero(fileKeyCipher, sizeof fileKeyCipher);
  sodium_memzero(keyNonce, sizeof keyNonce);
  sodium_memzero(fileKey, sizeof fileKey);
  sodium_memzero(privatekey, sizeof privatekey);
  free(outFilename);
  return ret;
}
//}}}

// DecryptFile - Decrypt file filename with key in privatefile, verifying with key in publicfile {{{
int DecryptFile(char *filename, char *privatefile, char *publicfile)
{
  int ret = 0;
  char *outFilename = malloc(strlen(filename) + 11);
  FILE *f;
  FILE *outFile;
  unsigned char publickey[crypto_box_PUBLICKEYBYTES];
  unsigned char privatekey[crypto_box_SECRETKEYBYTES];
  // Load Public Key
  f = fopen(publicfile, "rb");
  if (f == NULL) {
    printf("Failed to open file %s for loading public key\n", publicfile);
    ret = 1;
  } else {
    if (fread(publickey, sizeof(char), crypto_box_PUBLICKEYBYTES, f) < crypto_box_PUBLICKEYBYTES) {
      ret = 1;
      printf("Failed to read public key from %s\n", publicfile);
    }
  }
  fclose(f);

  // Load Private Key
  f = fopen(privatefile, "rb");
  if (f == NULL) {
    printf("Failed to open file %s for loading private key\n", privatefile);
    ret = 1;
  } else {
    if (fread(privatekey, sizeof(char), crypto_box_SECRETKEYBYTES, f) < crypto_box_SECRETKEYBYTES) {
      ret = 1;
      printf("Failed to read private key from %s\n", privatefile);
    }
  }
  fclose(f);

  // Prepare files for reading and writing
  f = fopen(filename, "rb");
  if (f == NULL) {
    printf("Failed to open file %s for decrypting\n", filename);
    ret = 1;
  }
  strcpy(outFilename, filename);
  strcat(outFilename, ".encrypted");
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

    version = fgetc(f);
    if (version > 1) {
      printf("Version number is greater than supported. Please upgrade this program.\n");
    }
    fread((void *)keyNonce, sizeof(char), sizeof keyNonce, f);
    fread((void *)fileKeyCipher, sizeof(char), sizeof fileKeyCipher, f);
    if (crypto_box_open_easy(fileKeyCipher, fileKeyCipher, sizeof fileKeyCipher, keyNonce,
          publickey, privatekey) != 0) {
      printf("Authentication failed! Does not match with public key provided.\n");
    }
    memcpy((void *)fileKey, (void *)fileKeyCipher, sizeof fileKey);
    memcpy((void *)fileNonce, (void *)fileKeyCipher + sizeof fileKey, sizeof fileNonce);

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

  fclose(f);
  fclose(outFile);
  sodium_memzero(subkey, sizeof subkey);
  sodium_memzero(fileKeyCipher, sizeof fileKeyCipher);
  sodium_memzero(keyNonce, sizeof keyNonce);
  sodium_memzero(fileKey, sizeof fileKey);
  sodium_memzero(privatekey, sizeof privatekey);
  free(outFilename);
  return ret;
}
//}}}

// GenerateKey - Generate Keypair {{{
int GenerateKey(char *name)
{
  int ret;
  unsigned char publickey[crypto_box_PUBLICKEYBYTES];
  unsigned char privatekey[crypto_box_SECRETKEYBYTES];
  char *filename = malloc(strlen(name) + 12); // .PRIVATEKEY + 1
  FILE *f;
  // Generate Keypair
  ret = crypto_box_keypair(publickey, privatekey);
  if (ret != 0) {
    printf("Failed to generate keypair\n");
  }
  // Write Private Key
  if (ret == 0) {
    strcpy(filename, name);
    strcat(filename, ".privatekey");
    f = fopen(filename, "wb");
    if (f == NULL) {
      ret = 1;
      printf("Could not open %s for writing\n", filename);
    } else {
      fwrite((void *)privatekey, sizeof(char), crypto_box_SECRETKEYBYTES, f);
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
  sodium_memzero(privatekey, sizeof privatekey);
  free(filename);
  return ret;
}
//}}}

// PrintUsage - Print program usage {{{
void PrintUsage() {
    printf(
        "Usage:\n"
        "cryptid genkey [NAME] - Generate key named NAME\n"
        "    Generate a public and private key\n"
        "cryptid encrypt FILE PRIVATEKEY PUBLICKEY\n"
        "    Encrypt FILE using PUBLICKEY file and sign it using PRIVATEKEY\n"
        "cryptid decrypt FILE PRIVATEKEY PUBLICKEY\n"
        "    Decrypt FILE using PRIVATEKEY file, checking signature against PUBLICKEY\n"
        );
}
//}}}

// vim:set fdm=marker:
