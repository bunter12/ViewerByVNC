#include "net/tcp_connect.hpp"
#include <arpa/inet.h>

bool TcpSocket::ConnectTo(const std::string &host, uint16_t port, int timeoutMs){
    sock = socket(AF_INET, SOCK_STREAM, 0);
    
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &serverAddress.sin_addr);
    
    return !connect(sock, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
}
