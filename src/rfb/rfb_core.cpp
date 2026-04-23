#include "rfb/rfb_core.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#include <openssl/des.h>

namespace {

bool ReadU16BE(TcpSocket* tcp, uint16_t& out) {
    std::array<uint8_t, 2> raw{};
    if (!tcp->GetAll(raw.data(), raw.size())) {
        return false;
    }
    out = (static_cast<uint16_t>(raw[0]) << 8) | static_cast<uint16_t>(raw[1]);
    return true;
}

bool ReadU32BE(TcpSocket* tcp, uint32_t& out) {
    std::array<uint8_t, 4> raw{};
    if (!tcp->GetAll(raw.data(), raw.size())) {
        return false;
    }
    out = (static_cast<uint32_t>(raw[0]) << 24) |
          (static_cast<uint32_t>(raw[1]) << 16) |
          (static_cast<uint32_t>(raw[2]) << 8) |
          static_cast<uint32_t>(raw[3]);
    return true;
}

bool ReadI32BE(TcpSocket* tcp, int32_t& out) {
    uint32_t raw = 0;
    if (!ReadU32BE(tcp, raw)) {
        return false;
    }
    out = static_cast<int32_t>(raw);
    return true;
}

void WriteU16BE(uint8_t* dst, uint16_t value) {
    dst[0] = static_cast<uint8_t>((value >> 8) & 0xFF);
    dst[1] = static_cast<uint8_t>(value & 0xFF);
}

void WriteU32BE(uint8_t* dst, uint32_t value) {
    dst[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
    dst[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    dst[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    dst[3] = static_cast<uint8_t>(value & 0xFF);
}

bool ReadFailureReason(TcpSocket* tcp, std::string& out) {
    uint32_t reasonLen = 0;
    if (!ReadU32BE(tcp, reasonLen)) {
        return false;
    }
    std::vector<char> reason(reasonLen);
    if (reasonLen > 0 && !tcp->GetAll(reason.data(), reason.size())) {
        return false;
    }
    out.assign(reason.begin(), reason.end());
    return true;
}

uint8_t ReverseBits(uint8_t x) {
    x = static_cast<uint8_t>(((x & 0xF0) >> 4) | ((x & 0x0F) << 4));
    x = static_cast<uint8_t>(((x & 0xCC) >> 2) | ((x & 0x33) << 2));
    x = static_cast<uint8_t>(((x & 0xAA) >> 1) | ((x & 0x55) << 1));
    return x;
}

std::string GetVncPasswordFromEnv() {
    const char* value = std::getenv("VNC_PASSWORD");
    if (value == nullptr || value[0] == '\0') {
        return {};
    }
    return std::string(value);
}

bool BuildVncAuthResponse(const std::string& password,
                          const std::array<uint8_t, 16>& challenge,
                          std::array<uint8_t, 16>& response) {
    std::array<uint8_t, 8> key{};
    for (size_t i = 0; i < key.size() && i < password.size(); ++i) {
        key[i] = ReverseBits(static_cast<uint8_t>(password[i]));
    }

    DES_cblock keyBlock{};
    std::memcpy(keyBlock, key.data(), key.size());

    DES_key_schedule schedule{};
    DES_set_key_unchecked(&keyBlock, &schedule);

    for (size_t i = 0; i < 2; ++i) {
        DES_cblock input{};
        DES_cblock output{};
        std::memcpy(input, challenge.data() + i * 8, 8);
        DES_ecb_encrypt(&input, &output, &schedule, DES_ENCRYPT);
        std::memcpy(response.data() + i * 8, output, 8);
    }

    return true;
}

bool DoVncAuthentication(TcpSocket* tcp, const std::string& password) {
    std::array<uint8_t, 16> challenge{};
    if (!tcp->GetAll(challenge.data(), challenge.size())) {
        return false;
    }

    std::array<uint8_t, 16> response{};
    if (!BuildVncAuthResponse(password, challenge, response)) {
        return false;
    }

    return tcp->SendAll(response.data(), response.size());
}

bool SkipBytes(TcpSocket* tcp, size_t count) {
    std::array<uint8_t, 4096> tmp{};
    size_t left = count;
    while (left > 0) {
        const size_t chunk = std::min(left, tmp.size());
        if (!tcp->GetAll(tmp.data(), chunk)) {
            return false;
        }
        left -= chunk;
    }
    return true;
}

bool SkipServerMessage(TcpSocket* tcp, uint8_t messageType) {
    if (messageType == 1) { // SetColorMapEntries
        uint8_t padding = 0;
        uint16_t firstColor = 0;
        uint16_t colorsCount = 0;
        if (!tcp->GetAll(&padding, sizeof(padding))) return false;
        if (!ReadU16BE(tcp, firstColor)) return false;
        if (!ReadU16BE(tcp, colorsCount)) return false;
        (void)firstColor;
        return SkipBytes(tcp, static_cast<size_t>(colorsCount) * 6);
    }

    if (messageType == 2) { // Bell
        return true;
    }

    if (messageType == 3) { // ServerCutText
        std::array<uint8_t, 3> padding{};
        uint32_t textLen = 0;
        if (!tcp->GetAll(padding.data(), padding.size())) return false;
        if (!ReadU32BE(tcp, textLen)) return false;
        return SkipBytes(tcp, static_cast<size_t>(textLen));
    }

    return false;
}

} // namespace

RfbCore::RfbCore(TcpSocket& tcp) {
    this->tcp = &tcp;
}

bool RfbCore::Handshake() {
    std::array<uint8_t, HANDSHAKE_SIZE> buf{};

    if (!tcp->GetAll(buf.data(), buf.size())) {
        return false;
    }

    std::array<char, HANDSHAKE_SIZE + 1> serverVersion{};
    std::memcpy(serverVersion.data(), buf.data(), buf.size());
    serverVersion[HANDSHAKE_SIZE] = '\0';

    int major = 0;
    int minor = 0;
    if (std::sscanf(serverVersion.data(), "RFB %03d.%03d", &major, &minor) == 2) {
        protocolMajor = major;
        protocolMinor = minor;
    }

    std::cout << "Server protocol: " << protocolMajor << "." << protocolMinor << "\n";

    if (!tcp->SendAll(buf.data(), buf.size())) {
        return false;
    }

    return true;
}

bool RfbCore::SecurityHandshake() {
    const bool isRfb33 = (protocolMajor == 3 && protocolMinor == 3);
    const std::string password = GetVncPasswordFromEnv();

    if (isRfb33) {
        uint32_t securityType = 0;
        if (!ReadU32BE(tcp, securityType)) {
            return false;
        }

        std::cout << "Security type: " << securityType << "\n";

        if (securityType == 0) {
            std::string reason;
            if (ReadFailureReason(tcp, reason)) {
                std::cout << "Security failed: " << reason << "\n";
            }
            return false;
        }

        if (securityType == 1) {
            return true;
        }

        if (securityType == 2) {
            if (password.empty()) {
                std::cout << "VNC auth requires password. Set VNC_PASSWORD\n";
                return false;
            }
            if (!DoVncAuthentication(tcp, password)) {
                return false;
            }

            uint32_t secRes = 0;
            if (!ReadU32BE(tcp, secRes)) {
                return false;
            }
            return secRes == 0;
        }

        return false;
    }

    uint8_t count = 0;
    if (!tcp->GetAll(&count, SECURITY_HANDSHAKE_SIZE)) {
        return false;
    }

    if (count == 0) {
        std::string reason;
        if (ReadFailureReason(tcp, reason)) {
            std::cout << "Security failed: " << reason << "\n";
        }
        return false;
    }

    std::vector<uint8_t> offeredTypes(count);
    if (!tcp->GetAll(offeredTypes.data(), offeredTypes.size())) {
        return false;
    }

    std::cout << "Offered security types:";
    for (uint8_t value : offeredTypes) {
        std::cout << " " << static_cast<int>(value);
    }
    std::cout << "\n";

    bool hasNone = false;
    bool hasVncAuth = false;
    for (uint8_t value : offeredTypes) {
        if (value == 1) {
            hasNone = true;
        }
        if (value == 2) {
            hasVncAuth = true;
        }
    }

    uint8_t selectedType = 0;
    if (hasNone) {
        selectedType = 1;
    } else if (hasVncAuth) {
        selectedType = 2;
    } else {
        return false;
    }

    if (!tcp->SendAll(&selectedType, sizeof(selectedType))) {
        return false;
    }

    if (selectedType == 2) {
        if (password.empty()) {
            std::cout << "VNC auth requires password. Set VNC_PASSWORD\n";
            return false;
        }
        if (!DoVncAuthentication(tcp, password)) {
            return false;
        }
    }

    uint32_t secRes = 0;
    if (!ReadU32BE(tcp, secRes)) {
        return false;
    }
    if (secRes != 0) {
        if (protocolMinor >= 8) {
            std::string reason;
            if (ReadFailureReason(tcp, reason)) {
                std::cout << "Security failed: " << reason << "\n";
            }
        }
        return false;
    }

    return true;
}

bool RfbCore::Init(){
    uint8_t shared_flag = 1;
    if (!tcp->SendAll(&shared_flag, sizeof(shared_flag))) {
        return false;
    }

    if (!ReadU16BE(tcp, InitData.width)) return false;
    if (!ReadU16BE(tcp, InitData.height)) return false;

    if (!tcp->GetAll(&InitData.pixel_format.bits_per_pixel, sizeof(InitData.pixel_format.bits_per_pixel))) return false;
    if (!tcp->GetAll(&InitData.pixel_format.depth, sizeof(InitData.pixel_format.depth))) return false;
    if (!tcp->GetAll(&InitData.pixel_format.big_endian_flag, sizeof(InitData.pixel_format.big_endian_flag))) return false;
    if (!tcp->GetAll(&InitData.pixel_format.true_color_flag, sizeof(InitData.pixel_format.true_color_flag))) return false;
    if (!ReadU16BE(tcp, InitData.pixel_format.red_max)) return false;
    if (!ReadU16BE(tcp, InitData.pixel_format.green_max)) return false;
    if (!ReadU16BE(tcp, InitData.pixel_format.blue_max)) return false;
    if (!tcp->GetAll(&InitData.pixel_format.red_shift, sizeof(InitData.pixel_format.red_shift))) return false;
    if (!tcp->GetAll(&InitData.pixel_format.green_shift, sizeof(InitData.pixel_format.green_shift))) return false;
    if (!tcp->GetAll(&InitData.pixel_format.blue_shift, sizeof(InitData.pixel_format.blue_shift))) return false;
    if (!tcp->GetAll(InitData.pixel_format.padding.data(), InitData.pixel_format.padding.size())) return false;
    if (!ReadU32BE(tcp, InitData.name_length)) {
        return false;
    }

    InitData.name.clear();
    if (InitData.name_length > 0) {
        std::vector<char> nameRaw(InitData.name_length);
        if (!tcp->GetAll(nameRaw.data(), nameRaw.size())) {
            return false;
        }
        InitData.name.assign(nameRaw.begin(), nameRaw.end());
    }

    
    return true;
}

bool RfbCore::SetPixelFormat(){
    if (InitData.pixel_format.bits_per_pixel == 0) {
        return false;
    }

    std::vector<uint8_t> msg(20, 0);
    msg[0] = 0; // SetPixelFormat

    msg[4] = InitData.pixel_format.bits_per_pixel;
    msg[5] = InitData.pixel_format.depth;
    msg[6] = InitData.pixel_format.big_endian_flag;
    msg[7] = InitData.pixel_format.true_color_flag;

    WriteU16BE(msg.data() + 8, InitData.pixel_format.red_max);
    WriteU16BE(msg.data() + 10, InitData.pixel_format.green_max);
    WriteU16BE(msg.data() + 12, InitData.pixel_format.blue_max);

    msg[14] = InitData.pixel_format.red_shift;
    msg[15] = InitData.pixel_format.green_shift;
    msg[16] = InitData.pixel_format.blue_shift;
    msg[17] = 0;
    msg[18] = 0;
    msg[19] = 0;

    return tcp->SendAll(msg.data(), msg.size());
}

bool RfbCore::SetEncodings() {
    std::vector<int32_t> encodings = {0}; // Raw

    std::vector<uint8_t> msg(4 + 4 * encodings.size());
    msg[0] = 2;
    msg[1] = 0;

    uint16_t n = static_cast<uint16_t>(encodings.size());
    msg[2] = static_cast<uint8_t>((n >> 8) & 0xFF);
    msg[3] = static_cast<uint8_t>(n & 0xFF);

    for (size_t i = 0; i < encodings.size(); ++i) {
        uint32_t v = static_cast<uint32_t>(encodings[i]);
        size_t p = 4 + i * 4;
        msg[p + 0] = static_cast<uint8_t>((v >> 24) & 0xFF);
        msg[p + 1] = static_cast<uint8_t>((v >> 16) & 0xFF);
        msg[p + 2] = static_cast<uint8_t>((v >> 8) & 0xFF);
        msg[p + 3] = static_cast<uint8_t>(v & 0xFF);
    }

    return tcp->SendAll(msg.data(), msg.size());
}


bool RfbCore::FramebufferUpdateRequest(){
    std::vector<uint8_t> msg(10);
    msg[0] = 3;
    msg[1] = 0;
    msg[2] = 0;
    msg[3] = 0;
    msg[4] = 0;
    msg[5] = 0;
    msg[6] = static_cast<uint8_t>((InitData.width >> 8) & 0xFF);
    msg[6 + 1] = static_cast<uint8_t>((InitData.width) & 0xFF);
    msg[8] = static_cast<uint8_t>((InitData.height >> 8) & 0xFF);
    msg[8 + 1] = static_cast<uint8_t>((InitData.height) & 0xFF);
    
    return tcp->SendAll(msg.data(), msg.size());
}

bool RfbCore::ReceiveFramebufferUpdate(std::vector<uint8_t>& frameBuffer) {
    uint8_t messageType = 0;
    while (true) {
        if (!tcp->GetAll(&messageType, sizeof(messageType))) {
            return false;
        }
        if (messageType == 0) {
            break;
        }
        if (!SkipServerMessage(tcp, messageType)) {
            return false;
        }
    }

    uint8_t padding = 0;
    uint16_t rectanglesCount = 0;
    if (!tcp->GetAll(&padding, sizeof(padding))) {
        return false;
    }
    if (!ReadU16BE(tcp, rectanglesCount)) {
        return false;
    }

    if (InitData.width == 0 || InitData.height == 0) {
        return false;
    }
    if (InitData.pixel_format.bits_per_pixel == 0 || (InitData.pixel_format.bits_per_pixel % 8) != 0) {
        return false;
    }

    const size_t bytesPerPixel = static_cast<size_t>(InitData.pixel_format.bits_per_pixel / 8);
    const size_t fbWidth = static_cast<size_t>(InitData.width);
    const size_t fbHeight = static_cast<size_t>(InitData.height);
    frameBuffer.assign(fbWidth * fbHeight * bytesPerPixel, 0);

    for (uint16_t rectIndex = 0; rectIndex < rectanglesCount; ++rectIndex) {
        uint16_t x = 0;
        uint16_t y = 0;
        uint16_t width = 0;
        uint16_t height = 0;
        int32_t encodingType = 0;

        if (!ReadU16BE(tcp, x)) return false;
        if (!ReadU16BE(tcp, y)) return false;
        if (!ReadU16BE(tcp, width)) return false;
        if (!ReadU16BE(tcp, height)) return false;
        if (!ReadI32BE(tcp, encodingType)) return false;

        if ((static_cast<size_t>(x) + static_cast<size_t>(width) > fbWidth) ||
            (static_cast<size_t>(y) + static_cast<size_t>(height) > fbHeight)) {
            return false;
        }

        if (!DecodeRectangleByEncoding(encodingType, frameBuffer, x, y, width, height)) {
            return false;
        }
    }

    return true;
}

bool RfbCore::DecodeRawRectangle(std::vector<uint8_t>& frameBuffer,
                                 uint16_t x,
                                 uint16_t y,
                                 uint16_t width,
                                 uint16_t height) {
    if (InitData.pixel_format.bits_per_pixel == 0 || (InitData.pixel_format.bits_per_pixel % 8) != 0) {
        return false;
    }

    const size_t bytesPerPixel = static_cast<size_t>(InitData.pixel_format.bits_per_pixel / 8);
    const size_t fbWidth = static_cast<size_t>(InitData.width);
    const size_t rectStride = static_cast<size_t>(width) * bytesPerPixel;
    const size_t rectSize = rectStride * static_cast<size_t>(height);

    std::vector<uint8_t> rectPixels(rectSize);
    if (!tcp->GetAll(rectPixels.data(), rectPixels.size())) {
        return false;
    }

    for (size_t row = 0; row < static_cast<size_t>(height); ++row) {
        const size_t srcOffset = row * rectStride;
        const size_t dstOffset =
            ((static_cast<size_t>(y) + row) * fbWidth + static_cast<size_t>(x)) * bytesPerPixel;
        std::copy(rectPixels.begin() + static_cast<std::ptrdiff_t>(srcOffset),
                  rectPixels.begin() + static_cast<std::ptrdiff_t>(srcOffset + rectStride),
                  frameBuffer.begin() + static_cast<std::ptrdiff_t>(dstOffset));
    }

    return true;
}

bool RfbCore::DecodeRectangleByEncoding(int32_t encodingType,
                                        std::vector<uint8_t>& frameBuffer,
                                        uint16_t x,
                                        uint16_t y,
                                        uint16_t width,
                                        uint16_t height) {
    if (encodingType == 0) { // Raw
        return DecodeRawRectangle(frameBuffer, x, y, width, height);
    }
    return false;
}

bool RfbCore::KeyEvent(){
    std::vector<uint8_t> msg(8, 0);
    msg[0] = 4; // KeyEvent
    msg[1] = 0; // key up
    WriteU32BE(msg.data() + 4, 0);
    return tcp->SendAll(msg.data(), msg.size());
}

bool RfbCore::PointerEvent(){
    std::vector<uint8_t> msg(6, 0);
    msg[0] = 5; // PointerEvent
    msg[1] = 0; // no buttons
    WriteU16BE(msg.data() + 2, 0); // x
    WriteU16BE(msg.data() + 4, 0); // y
    return tcp->SendAll(msg.data(), msg.size());
}

bool RfbCore::ClientCutText(){
    std::vector<uint8_t> msg(8, 0);
    msg[0] = 6; // ClientCutText
    WriteU32BE(msg.data() + 4, 0); // text length
    return tcp->SendAll(msg.data(), msg.size());
}
