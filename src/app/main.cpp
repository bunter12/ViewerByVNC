#include "rfb/rfb_core.hpp"

#include <QColor>
#include <QImage>

#include <iostream>
#include <vector>

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

    if (!rfb.SetEncodings()) {
        std::cout << "SetEncodings failed\n";
        return 1;
    }
    std::cout << "SetEncodings successful\n";

    if (!rfb.FramebufferUpdateRequest()) {
        std::cout << "FramebufferUpdateRequest failed\n";
        return 1;
    }
    std::cout << "FramebufferUpdateRequest successful\n";

    std::vector<uint8_t> frameBuffer;
    if (!rfb.ReceiveFramebufferUpdate(frameBuffer)) {
        std::cout << "ReceiveFramebufferUpdate failed\n";
        return 1;
    }
    std::cout << "Frame received, bytes: " << frameBuffer.size() << "\n";

    const ServerInit& initData = rfb.GetInitData();
    const PIXEL_FORMAT& pf = initData.pixel_format;

    if (!pf.true_color_flag) {
        std::cout << "Unsupported pixel format: true_color_flag == 0\n";
        return 1;
    }

    if (pf.bits_per_pixel == 0 || (pf.bits_per_pixel % 8) != 0) {
        std::cout << "Unsupported bits_per_pixel\n";
        return 1;
    }

    const size_t bytesPerPixel = static_cast<size_t>(pf.bits_per_pixel / 8);
    const size_t width = static_cast<size_t>(initData.width);
    const size_t height = static_cast<size_t>(initData.height);
    const size_t expectedSize = width * height * bytesPerPixel;

    if (frameBuffer.size() < expectedSize) {
        std::cout << "Frame buffer size is too small\n";
        return 1;
    }

    QImage image(static_cast<int>(initData.width), static_cast<int>(initData.height), QImage::Format_RGB32);

    auto readPixelValue = [&](const uint8_t* src) -> uint32_t {
        uint32_t value = 0;
        if (pf.big_endian_flag) {
            for (size_t i = 0; i < bytesPerPixel; ++i) {
                value = (value << 8) | static_cast<uint32_t>(src[i]);
            }
        } else {
            for (size_t i = 0; i < bytesPerPixel; ++i) {
                value |= (static_cast<uint32_t>(src[i]) << (8 * i));
            }
        }
        return value;
    };

    auto scaleTo8Bit = [](uint32_t component, uint16_t maxComponent) -> int {
        if (maxComponent == 0) {
            return 0;
        }
        return static_cast<int>((component * 255u + (maxComponent / 2u)) / maxComponent);
    };

    for (size_t y = 0; y < height; ++y) {
        for (size_t x = 0; x < width; ++x) {
            const size_t offset = (y * width + x) * bytesPerPixel;
            const uint32_t pixelValue = readPixelValue(frameBuffer.data() + offset);

            const uint32_t redRaw = (pixelValue >> pf.red_shift) & pf.red_max;
            const uint32_t greenRaw = (pixelValue >> pf.green_shift) & pf.green_max;
            const uint32_t blueRaw = (pixelValue >> pf.blue_shift) & pf.blue_max;

            const int red = scaleTo8Bit(redRaw, pf.red_max);
            const int green = scaleTo8Bit(greenRaw, pf.green_max);
            const int blue = scaleTo8Bit(blueRaw, pf.blue_max);

            image.setPixelColor(static_cast<int>(x), static_cast<int>(y), QColor(red, green, blue));
        }
    }

    if (!image.save("frame.bmp")) {
        std::cout << "Failed to save image\n";
        return 1;
    }
    std::cout << "Saved image: frame.bmp\n";

    return 0;
}
