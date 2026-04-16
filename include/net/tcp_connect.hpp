#pragma once

#include <iostream>
#include <sys/socket.h>
#include <stdint.h>
#include <string>

class TcpSocket{
public:
    ~TcpSocket(){};
    
    bool ConnectTo(const std::string& host, uint16_t port, int timeoutMs = 5000);
private:
    int sock;
};
