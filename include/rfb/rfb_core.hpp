#pragma once
#include "net/tcp_connect.hpp"
#include <vector>
#include <string>
#include <array>

#define HANDSHAKE_SIZE 12
#define SECURITY_HANDSHAKE_SIZE 1
#define SECURITY_RESULT_SIZE 4

struct PIXEL_FORMAT{
    uint8_t bits_per_pixel;
    uint8_t depth;
    uint8_t big_endian_flag;
    uint8_t true_color_flag;
    uint16_t red_max;
    uint16_t green_max;
    uint16_t blue_max;
    uint8_t red_shift;
    uint8_t green_shift;
    uint8_t blue_shift;
    std::array<uint8_t, 3> padding;
};

enum ClietnToServerMessage{
    SetPixelFormat              = 0,
    SetEncodings                = 2,
    FramebufferUpdateRequest    = 3,
    KeyEvent                    = 4,
    PointerEvent                = 5,
    ClientCutText               = 6
};

struct ServerInit{
    uint16_t width;
    uint16_t height;
    PIXEL_FORMAT pixel_format;
    uint32_t name_length;
    std::string name;
};

class RfbCore{
public:
    
    RfbCore(TcpSocket& tcp);
    
    bool Handshake();
    bool SecurityHandshake();
    bool Init();
    
    bool SetPixelFormat();
    bool SetEncodings();
    bool FramebufferUpdateRequest();
    bool ReceiveFramebufferUpdate(std::vector<uint8_t>& frameBuffer);
    const ServerInit& GetInitData() const { return InitData; }
    bool KeyEvent();
    bool PointerEvent();
    bool ClientCutText();
    bool RunGetImageFromServer();
private:
    bool DecodeRawRectangle(std::vector<uint8_t>& frameBuffer,
                            uint16_t x,
                            uint16_t y,
                            uint16_t width,
                            uint16_t height);
    bool DecodeRectangleByEncoding(int32_t encodingType,
                                   std::vector<uint8_t>& frameBuffer,
                                   uint16_t x,
                                   uint16_t y,
                                   uint16_t width,
                                   uint16_t height);

    int protocolMajor = 3;
    int protocolMinor = 8;

    ServerInit InitData;
    TcpSocket* tcp;
};
