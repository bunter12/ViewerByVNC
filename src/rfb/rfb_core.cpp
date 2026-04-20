#include "rfb/rfb_core.hpp"

#include <array>
#include <vector>
#include <iostream>

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

} // namespace

RfbCore::RfbCore(TcpSocket& tcp) {
    this->tcp = &tcp;
}

bool RfbCore::Handshake() {
    std::array<uint8_t, HANDSHAKE_SIZE> buf{};

    if (!tcp->GetAll(buf.data(), buf.size())) {
        return false;
    }

    if (!tcp->SendAll(buf.data(), buf.size())) {
        return false;
    }

    return true;
}

bool RfbCore::SecurityHandshake() {
    uint8_t count = 0;
    bool res = tcp->GetAll(&count, SECURITY_HANDSHAKE_SIZE);
    if (!res) {
        return false;
    }
    std::vector<uint8_t> buf(count);
    if (count > 0) {
        res &= tcp->GetAll(buf.data(), count);
    }
    else
        return false;

    uint8_t type = 0;
    for (uint8_t offeredType : buf) {
        if (offeredType == 1) {
            type = 1;
            break;
        }
    }
    if (type == 0) {
        return false;
    }

    res &= tcp->SendAll(&type, sizeof(type));
    if (!res) {
        return false;
    }

    uint32_t secRes = 0;
    res &= ReadU32BE(tcp, secRes);
    if (!res) {
        return false;
    }

    res = res && (secRes == 0);
    return res;
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
