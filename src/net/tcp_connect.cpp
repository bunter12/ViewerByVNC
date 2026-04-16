#include "net/tcp_connect.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <sys/socket.h>
#include <unistd.h>

bool TcpSocket::ConnectTo(const std::string& host, uint16_t port, int timeoutMS) {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start)
               .count() < timeoutMS) {
        CloseSocket();
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return false;
        }

        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(port);
        if (inet_pton(AF_INET, host.c_str(), &serverAddress.sin_addr) != 1) {
            CloseSocket();
            return false;
        }

        if (connect(sock, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == 0) {
            return true;
        }

        usleep(100 * 1000);
    }

    CloseSocket();
    return false;
}

bool TcpSocket::SendAll(const void* data, size_t size) {
    if (sock < 0) {
        return false;
    }

    const char* bytes = static_cast<const char*>(data);
    size_t sent = 0;
    while (sent < size) {
        ssize_t n = send(sock, bytes + sent, size - sent, 0);
        if (n <= 0) {
            return false;
        }
        sent += static_cast<size_t>(n);
    }

    return true;
}

bool TcpSocket::GetAll(void* data, size_t size) {
    if (sock < 0) {
        return false;
    }

    char* bytes = static_cast<char*>(data);
    size_t received = 0;
    while (received < size) {
        ssize_t n = recv(sock, bytes + received, size - received, 0);
        if (n <= 0) {
            return false;
        }
        received += static_cast<size_t>(n);
    }

    return true;
}

bool TcpSocket::CloseSocket() {
    if (sock < 0) {
        return true;
    }

    shutdown(sock, SHUT_RDWR);
    int status = close(sock);
    sock = -1;
    return status == 0;
}
