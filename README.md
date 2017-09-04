# encrypt-cli

A trivial file encryption/decryption application written in C++. It uses XChaCha20-Poly1305 for symmetric encryption and Argon2i for key derivation. Asymmetric encryption may be added later.

## Building
Only depends on libsodium.
```
cmake .
make -j2
```

## Usage
```
% encrypt-cli secret-notes.txt
Please enter your symmetric encryption key: mypassword
Please confirm your symmetric encryption key: mypassword
Deriving key, please wait...
Success!
```

Encrypted files are written to `<file name>.enc`.
