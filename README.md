# SodiumUtils
Simple set of crypto utilities built on libSodium as a practice exercise.

## Format ##
Currently, secret and public keys are written out in binary form to 
NAME.secretkey and NAME.publickey.

Encrypted files have a header at the beginning, consisting of a 1-byte version 
number, a nonce used in authenticated public-key encryption, an encrypted 
section containing a nonce and key used for the stream cipher, and a hash-based 
message authentication code for the file contents.

## Encryption Process ##

To encrypt a file, a symmetric key is randomly generated, along with a nonce. 
These are encrypted using Curve25519 for key exchange, XSalsa20 as a stream 
cipher, and Poly1305 MAC for verifying the contents. The file itself is then 
encrypted using the symmetric key and nonce through the XSalsa20 stream cipher. 
The resulting ciphertext is hashed using Poly1305 with the symmetric key, and 
the result is stored in the header for message authentication.
