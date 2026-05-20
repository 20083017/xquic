/**
 * @file xqc_nv12_mosaic_smoke.cpp
 * @brief Roadmap P8 smoke: compose synthetic NV12 frames into a 2x2 mosaic.
 */

#include "xqc_nv12_mosaic.hh"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace {

struct Options {
    int width = 320;
    int height = 240;
    int columns = 2;
    int rows = 2;
    std::string output = "mosaic_2x2.nv12";
    std::vector<std::string> inputs;
};

void usage(const char* argv0) {
    std::printf(
        "Usage: %s [--width N] [--height N] [--columns N] [--rows N]\n"
        "          [--input cam0.nv12 ...] [--output file.nv12]\n"
        "\n"
        "When --input is omitted, synthetic solid-color NV12 cells are generated.\n"
        "Each input must be compact NV12 with size width*height*3/2.\n",
        argv0);
}

bool parse_int(const char* s, int& out) {
    char* end = nullptr;
    const long v = std::strtol(s, &end, 10);
    if (!s || !s[0] || (end && *end) || v <= 0 || v > 8192) {
        return false;
    }
    out = static_cast<int>(v);
    return true;
}

bool parse_args(int argc, char** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--width") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], opt.width)) {
                return false;
            }
        } else if (std::strcmp(a, "--height") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], opt.height)) {
                return false;
            }
        } else if (std::strcmp(a, "--columns") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], opt.columns)) {
                return false;
            }
        } else if (std::strcmp(a, "--rows") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], opt.rows)) {
                return false;
            }
        } else if (std::strcmp(a, "--output") == 0 && i + 1 < argc) {
            opt.output = argv[++i];
        } else if (std::strcmp(a, "--input") == 0 && i + 1 < argc) {
            opt.inputs.emplace_back(argv[++i]);
        } else if (std::strcmp(a, "-h") == 0 || std::strcmp(a, "--help") == 0) {
            usage(argv[0]);
            std::exit(0);
        } else {
            return false;
        }
    }
    return (opt.width % 2) == 0 && (opt.height % 2) == 0
        && opt.columns > 0 && opt.rows > 0 && !opt.output.empty();
}

XqcNv12Frame make_solid_frame(uint16_t camera_id, int width, int height, uint8_t y, uint8_t u, uint8_t v) {
    XqcNv12Frame f;
    f.camera_id = camera_id;
    f.width = width;
    f.height = height;
    f.backing = XqcNv12Backing::Cpu;
    f.data.resize(xqc_nv12_byte_size(width, height));

    const std::size_t y_size = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    std::memset(f.data.data(), y, y_size);
    uint8_t* uv = f.data.data() + y_size;
    for (int row = 0; row < height / 2; ++row) {
        for (int col = 0; col < width; col += 2) {
            uv[static_cast<std::size_t>(row) * static_cast<std::size_t>(width) + static_cast<std::size_t>(col)] = u;
            uv[static_cast<std::size_t>(row) * static_cast<std::size_t>(width) + static_cast<std::size_t>(col + 1)] = v;
        }
    }
    return f;
}

bool read_raw_nv12(const std::string& path, uint16_t camera_id, int width, int height, XqcNv12Frame& out) {
    FILE* fp = std::fopen(path.c_str(), "rb");
    if (!fp) {
        std::perror(path.c_str());
        return false;
    }
    out.camera_id = camera_id;
    out.width = width;
    out.height = height;
    out.backing = XqcNv12Backing::Cpu;
    out.data.resize(xqc_nv12_byte_size(width, height));
    const size_t n = std::fread(out.data.data(), 1, out.data.size(), fp);
    const int extra = std::fgetc(fp);
    std::fclose(fp);
    if (n != out.data.size() || extra != EOF) {
        std::fprintf(stderr, "[mosaic] invalid NV12 input size: %s expected=%zu got_at_least=%zu\n",
            path.c_str(), out.data.size(), n);
        return false;
    }
    return true;
}

bool write_file(const std::string& path, const XqcNv12Frame& frame) {
    FILE* fp = std::fopen(path.c_str(), "wb");
    if (!fp) {
        std::perror(path.c_str());
        return false;
    }
    const bool ok = std::fwrite(frame.data.data(), 1, frame.data.size(), fp) == frame.data.size();
    std::fclose(fp);
    return ok;
}

} // namespace

int main(int argc, char** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        return 2;
    }

    const int capacity = opt.columns * opt.rows;
    const uint8_t palette[][3] = {
        {76, 84, 255},
        {150, 44, 21},
        {29, 255, 107},
        {226, 0, 148},
        {180, 128, 128},
        {96, 192, 64},
        {210, 64, 192},
        {48, 192, 192},
    };

    std::vector<XqcNv12Frame> inputs;
    if (!opt.inputs.empty()) {
        inputs.reserve(opt.inputs.size());
        for (std::size_t i = 0; i < opt.inputs.size(); ++i) {
            XqcNv12Frame f;
            if (!read_raw_nv12(opt.inputs[i], static_cast<uint16_t>(i), opt.width, opt.height, f)) {
                return 1;
            }
            inputs.push_back(std::move(f));
        }
        if (static_cast<int>(inputs.size()) > capacity) {
            std::fprintf(stderr, "[mosaic] warning: %zu inputs provided, only first %d cells are used\n",
                inputs.size(), capacity);
        }
    } else {
        inputs.reserve(static_cast<std::size_t>(capacity));
        for (int i = 0; i < capacity; ++i) {
            const uint8_t* p = palette[i % (sizeof(palette) / sizeof(palette[0]))];
            inputs.push_back(make_solid_frame(static_cast<uint16_t>(i), opt.width, opt.height, p[0], p[1], p[2]));
        }
    }

    XqcNv12MosaicLayout layout;
    layout.columns = opt.columns;
    layout.rows = opt.rows;
    layout.cell_width = opt.width;
    layout.cell_height = opt.height;

    XqcNv12Frame out;
    if (!xqc_nv12_compose_mosaic_same_size(inputs, layout, out)) {
        std::fprintf(stderr, "[mosaic] compose failed\n");
        return 1;
    }
    if (!write_file(opt.output, out)) {
        std::fprintf(stderr, "[mosaic] write failed\n");
        return 1;
    }

    std::printf("[mosaic] wrote %s %dx%d bytes=%zu cells=%dx%d\n",
        opt.output.c_str(), out.width, out.height, out.data.size(), opt.columns, opt.rows);
    return 0;
}
