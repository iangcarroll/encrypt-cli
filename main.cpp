#include <cstring>
#include <iostream>
#include <string>

extern "C" {
    #include <sodium.h>
    #include <stdio.h>
    #include <sys/stat.h>
    #include <unistd.h>    
}

typedef struct {
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
} file_header_t;

/* Decrypt instead of encrypt. */
bool decrypt = false;

/* Take in file contents from standard input instead of a file. */
bool standardInput = false;

/* The file path to encrypt or decrypt. Not used with standardInput. */
std::string filePath;

/* The "printable" symmetric encryption key. */
char * symmetricKey = NULL;

/* The file or standard input data. */
unsigned char * data = NULL;

/* The size of `data`. */
size_t dataSize = 0;

/* The encrypted or decrypted output data. */
unsigned char * outputData = NULL;

/* The size of `outputData`. */
size_t outputDataSize = 0;

/* The file header. */
file_header_t outputHeader;

bool parseArgs(int argc, char * argv[]) {
    int filePathIndex = -1;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = std::string(argv[i]);

        if (filePathIndex == i) {
            filePath = arg;
        } else if (filePathIndex < i && filePathIndex > 0) {
            /* If there is anything after the file path, it's likely user error. */
            std::cerr << "Unexpected argument after the file path encountered." << std::endl;            
            return false;
        } else if (arg == "--") {
            /* Force the next argument to be the file path. */
            filePathIndex = i + 1;
        } else if (arg == "--decrypt" || arg == "-d") {
            decrypt = true;
        } else if (arg == "--stdin" || arg == "-i") {
            standardInput = true;
        } else if (arg.substr(0, 2) != "--" && filePath.empty()) {
            filePath = arg;
        } else {
            std::cerr << "Unexpected argument " << arg << " encountered." << std::endl;
            return false;
        }
    }

    return true;
}

bool validateParameters() {
    /* Ensure either the file path or standard input is passed, but never both. */
    if (filePath.empty() && ! standardInput) {
        std::cerr << "You must provide a file path or pass --stdin." << std::endl;
        return false;
    } else if (! filePath.empty() && standardInput) {
        std::cerr << "Do not provide a file path with standard input." << std::endl;
        return false;
    }

    if (! filePath.empty()) {
        if (access(filePath.c_str(), F_OK) == -1) {
            std::cerr << "The file path " << filePath << " does not exist." << std::endl;
            return false;
        }
    }

    return true;
}

bool readData() {
    FILE * f;

    if (standardInput) {
        f = stdin;
    } else {
        f = fopen(filePath.c_str(), "rb");
    }

    if (f == NULL) {
        std::cerr << "Could not open file." << std::endl;
        return false;
    }

    fseek(f, 0L, SEEK_END);
    dataSize = ftell(f);
    
    rewind(f);
    
    data = new unsigned char[dataSize];
    size_t readData = fread(data, 1, dataSize, f);

    fclose(f);

    if (readData < dataSize) {
        std::cerr << "Did not read enough data." << std::endl;
        return false;
    }

    return true;
}

bool captureSymmetricKey() {
    std::cout << "Please enter your symmetric encryption key: " << std::flush;

    symmetricKey = new char[256];
    std::cin.getline(symmetricKey, 256);

    if (strlen(symmetricKey) >= 255) {
        std::cerr << "The symmetric encryption key must be less than 256 characters." << std::endl;
        return false;
    } else if (strlen(symmetricKey) < 3) {
        std::cerr << "The symmetric encryption key must be at least three characters." << std::endl;
        return false;
    }

    if (! decrypt) {
        std::cout << "Please confirm your symmetric encryption key: " << std::flush;
        
        char * symmetricKeyConfirmation = new char[256];
        std::cin.getline(symmetricKeyConfirmation, 256);

        if (strlen(symmetricKey) != strlen(symmetricKeyConfirmation)) {
            std::cerr << "The confirmation did not match the original." << std::endl << std::endl;
            return false;
        }

        if (strncmp(symmetricKey, symmetricKeyConfirmation, strlen(symmetricKey)) != 0) {
            std::cerr << "The confirmation did not match the original." << std::endl << std::endl;
            return false;
        }
    }

    return true;
}

bool readKeys() {
    /* Capture the symmetric encryption key if needed. */
    if (symmetricKey == NULL) {
        while (! captureSymmetricKey()) {
            /* Loop until success. */
        }
    }

    return true;    
}

bool decryptData() {
    void * encryptedContents = (void *) (data + sizeof(file_header_t));
    file_header_t * header = (file_header_t *) data;

    outputDataSize = dataSize;
    outputData = new unsigned char[outputDataSize];

    std::cout << "Deriving key, please wait..." << std::endl;

    unsigned char derivedKey[32] = {0};
    
    if (crypto_pwhash(derivedKey, 32, symmetricKey, strlen(symmetricKey), header->salt, crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        std::cerr << "Failure to compute key." << std::endl;
        return false;
    }    

    int result = crypto_aead_xchacha20poly1305_ietf_decrypt(outputData, (unsigned long long *) &outputDataSize,
        NULL,
        (const unsigned char *) encryptedContents, dataSize - sizeof(file_header_t),
        NULL, 0,
        header->nonce, derivedKey);
    
    if (result != 0) {
        std::cerr << "Error decrypting file." << std::endl;
    }

    return result == 0;
}

bool encryptData() {
    randombytes_buf(outputHeader.nonce, sizeof(outputHeader.nonce));
    randombytes_buf(outputHeader.salt, sizeof(outputHeader.salt));
    
    outputDataSize = dataSize + crypto_aead_xchacha20poly1305_ietf_ABYTES;    
    outputData = new unsigned char[outputDataSize];

    std::cout << "Deriving key, please wait..." << std::endl;

    unsigned char derivedKey[32] = {0};

    if (crypto_pwhash(derivedKey, 32, symmetricKey, strlen(symmetricKey), outputHeader.salt, crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        std::cerr << "Failure to compute key." << std::endl;
        return false;
    }

    crypto_aead_xchacha20poly1305_ietf_encrypt(outputData, (unsigned long long *) &outputDataSize,
        data, dataSize,
        NULL, 0,
        NULL, outputHeader.nonce, derivedKey);

    return true;
}

bool writeData() {
    char * outputPath;
    asprintf(&outputPath, "%s.enc", filePath.c_str());

    if (access(outputPath, F_OK) != -1) {
        std::cout << "File " << outputPath << " already exists. Overwrite? [y/n] " << std::flush;
        if (getchar() == 'y') {
            unlink(outputPath);
        } else {
            return false;
        }
    }

    FILE * f = fopen(outputPath, "wb+");

    if (! decrypt) {
        fwrite((void *) &outputHeader, 1, sizeof(file_header_t), f);
    }
    
    fwrite(outputData, 1, outputDataSize, f);
    fclose(f);

    return true;
}

int main(int argc, char * argv[]) {
    /* Parse out the arguments and various options. */
    if (! parseArgs(argc, argv)) {
        return 1;
    }

    /* Validate the arguments/options and retrieve the symmetric key if needed. */
    if (! validateParameters()) {
        return 1;
    }

    /* Read the input into memory. */
    if (! readData()) {
        return 1;
    }

    /* Read the keys into memory. */
    if (! readKeys()) {
        return 1;
    }

    /* Decrypt or encrypt into outputData. */
    if (decrypt) {
        if (! decryptData()) {
            return 1;
        }
    } else {
        if (! encryptData()) {
            return 1;
        }
    }

    /* Write the outputData. */
    if (! writeData()) {
        exit(1);
    }

    std::cout << "Success!" << std::endl;

    /* Success! */
    return 0;
}