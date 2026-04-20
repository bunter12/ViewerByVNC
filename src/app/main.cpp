#include "rfb/rfb_core.hpp"

#include <iostream>

int main() {
    TcpSocket tcp;
    RfbCore rfb(tcp);

    if (!tcp.ConnectTo("127.0.0.1", 5900)) {
        std::cout << "Connection failed\n";
        return 1;
    }
    std::cout << "Connection successful\n";

    if (!rfb.Handshake()){
        std::cout << "Handshake failed\n";
        return 1;
    }
    std::cout << "Handshake successful\n";

    if (!rfb.SecurityHandshake()){
        std::cout << "Security handshake failed\n";
        return 1;
    }
    std::cout << "Security handshake successful\n";

    if (!rfb.Init()) {
        std::cout << "Server init failed\n";
        return 1;
    }
    std::cout << "Server init successful\n";

    return 0;
}
