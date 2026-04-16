#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

class TcpSocket {
public:
    ~TcpSocket() { CloseSocket(); }

    bool ConnectTo(const std::string& host, uint16_t port, int timeoutMS = 5000);
    bool SendAll(const void* data, size_t size);
    bool GetAll(void* data, size_t size);
    bool CloseSocket();

private:
    int sock = -1;
};
