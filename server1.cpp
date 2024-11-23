#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#define PORT 8080

std::string hash(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.size(), hash);

    char outputBuffer[65]; // Buffer to store the hexadecimal string representation
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        // Use snprintf to safely format the hex string into outputBuffer
        snprintf(outputBuffer + (i * 2), sizeof(outputBuffer) - (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;  // Null terminate the string
    return std::string(outputBuffer);
}

void handle_client(int new_socket) {
    char buffer[1024] = {0};
    int valread = read(new_socket, buffer, 1024);

    // Receive Ai, Idi, and public key from client
    std::string received_data(buffer, valread);
    std::cout << "Received data from client: " << received_data << std::endl;

    // Split received data (for simplicity, assume format is "Ai,Idi,PubKey")
    size_t first_delim = received_data.find(",");
    size_t second_delim = received_data.find(",", first_delim + 1);

    std::string Ai = received_data.substr(0, first_delim);
    std::string Idi = received_data.substr(first_delim + 1, second_delim - first_delim - 1);
    std::string PubKeyClient = received_data.substr(second_delim + 1);

    // Calculate Bi, Di, and Ci based on protocol requirements
    std::string x = "secret_value"; // Simulated secret known only to registration center
    std::string Bi = hash(x + Idi);
    std::string Di = hash(hash(x) + Idi) + Bi;
    std::string Ci = hash(hash(x) + Ai + Idi);

    // Send Ci and h(x) back to the client
    std::string response = Ci + "," + hash(x);
    send(new_socket, response.c_str(), response.size(), 0);
    std::cout << "Response sent to client: " << response << std::endl;

    close(new_socket);
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Attach socket to port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR , &opt, sizeof(opt)))    {

        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "Server listening on port " << PORT << std::endl;

    // Accept incoming connections
    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }
        handle_client(new_socket);
    }

    return 0;
}
