#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#define PORT 8080

std::string hash(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.size(), hash);
    char outputBuffer[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(outputBuffer + (i * 2), sizeof(outputBuffer) - (i * 2), "%02x", hash[i]);
    outputBuffer[64] = 0;
    return std::string(outputBuffer);
}

void generate_keys() {
    // Generate ECC key pair
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *pkey = NULL;

    if (!pctx) {
        // Handle error
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        // Handle error
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        // Handle error
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        // Handle error
    }

    // Use pkey for further operations

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
}

std::string generate_ecc_key_pair(std::string& private_key_hex, std::string& public_key_hex) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *pkey = NULL;

    if (!pctx) {
        // Handle error
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        // Handle error
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        // Handle error
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        // Handle error
    }

    // Extract private key
    size_t priv_len;
    unsigned char *priv = NULL;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, &priv_len) <= 0) {
        // Handle error
    }
    priv = (unsigned char *)OPENSSL_malloc(priv_len);
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, priv, priv_len, &priv_len) <= 0) {
        // Handle error
    }
    private_key_hex = std::string((char*)priv, priv_len);
    OPENSSL_free(priv);

    // Extract public key
    size_t pub_len;
    unsigned char *pub = NULL;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_len) <= 0) {
        // Handle error
    }
    pub = (unsigned char *)OPENSSL_malloc(pub_len);
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len, &pub_len) <= 0) {
        // Handle error
    }
    public_key_hex = std::string((char*)pub, pub_len);
    OPENSSL_free(pub);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    return private_key_hex + "," + public_key_hex;
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cout << "Socket creation error" << std::endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 address from text to binary
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        std::cout << "Invalid address or address not supported" << std::endl;
        return -1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cout << "Connection Failed" << std::endl;
        return -1;
    }

    // Generate private and public keys
    std::string P_RIVui, P_UBui;
    generate_ecc_key_pair(P_RIVui, P_UBui);

    // Generate Ai and Idi
    std::string Idi = "User123";
    std::string Pwi = "UserPassword";
    std::string Bioi = "UserBioData";
    std::string sigma = hash(Bioi);
    std::string Ai = hash(Idi + Pwi + sigma);

    // Compute Ei = q ⊕ Ai (XOR between private key and Ai hash)
    std::string Ei = hash(P_RIVui) + Ai;

    // Send Ai, Idi, and public key to server
    std::string registration_data = Ai + "," + Idi + "," + P_UBui;
    send(sock, registration_data.c_str(), registration_data.size(), 0);
    std::cout << "Registration data sent: " << registration_data << std::endl;

    // Receive server response
    int valread = read(sock, buffer, 1024);
    std::string server_response(buffer, valread);
    std::cout << "Received response from server: " << server_response << std::endl;

    // Store values in TEE (simulated storage)
    size_t delimiter_pos = server_response.find(",");
    std::string Ci = server_response.substr(0, delimiter_pos);
    std::string hx = server_response.substr(delimiter_pos + 1);

    std::cout << "Stored values in TEE: Ci = " << Ci << ", h(x) = " << hx << ", Ei = " << Ei << std::endl;
    std::cout << "Public Key (Published):" << std::endl;
    std::cout << P_UBui << std::endl;
    close(sock);
    return 0;
}
