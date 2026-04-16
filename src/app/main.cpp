#include "net/tcp_connect.hpp"
#include <iostream>

int main(){
    TcpSocket tcp;
    
    if(tcp.ConnectTo("127.0.0.1", 5900)){
        std::cout<<"Connection succesfull\n";
    }
    else{
        std::cout<<"Connection failed";
    }
    return 0;
}
