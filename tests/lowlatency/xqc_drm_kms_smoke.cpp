/**
 * @file xqc_drm_kms_smoke.cpp
 * @brief Roadmap P5: non-destructive DRM/KMS capability smoke test.
 *
 * This tool intentionally does not modeset by default. It verifies that the
 * process can open a DRM node, enable atomic/universal-plane caps, enumerate
 * connectors/CRTCs/planes, and print enough state for the later direct-scanout
 * implementation.
 */

#include <xf86drm.h>
#include <xf86drmMode.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <inttypes.h>
#include <string>
#include <unistd.h>

namespace {

struct Options {
    std::string device = "/dev/dri/card0";
    bool list_props = false;
};

void usage(const char* argv0) {
    std::printf(
        "Usage: %s [--device /dev/dri/cardN] [--list-props]\n"
        "\n"
        "Non-destructive DRM/KMS smoke test for roadmap P5.\n",
        argv0);
}

bool parse_args(int argc, char** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--device") == 0 && i + 1 < argc) {
            opt.device = argv[++i];
        } else if (std::strcmp(a, "--list-props") == 0) {
            opt.list_props = true;
        } else if (std::strcmp(a, "-h") == 0 || std::strcmp(a, "--help") == 0) {
            usage(argv[0]);
            std::exit(0);
        } else {
            return false;
        }
    }
    return !opt.device.empty();
}

const char* connection_name(uint32_t connection) {
    switch (connection) {
    case DRM_MODE_CONNECTED:
        return "connected";
    case DRM_MODE_DISCONNECTED:
        return "disconnected";
    case DRM_MODE_UNKNOWNCONNECTION:
    default:
        return "unknown";
    }
}

const char* connector_type_name(uint32_t type) {
    switch (type) {
    case DRM_MODE_CONNECTOR_HDMIA:
        return "HDMI-A";
    case DRM_MODE_CONNECTOR_HDMIB:
        return "HDMI-B";
    case DRM_MODE_CONNECTOR_DisplayPort:
        return "DisplayPort";
    case DRM_MODE_CONNECTOR_eDP:
        return "eDP";
    case DRM_MODE_CONNECTOR_DVID:
        return "DVI-D";
    case DRM_MODE_CONNECTOR_VGA:
        return "VGA";
    default:
        return "other";
    }
}

void print_props(int fd, uint32_t object_id, uint32_t object_type) {
    drmModeObjectPropertiesPtr props = drmModeObjectGetProperties(fd, object_id, object_type);
    if (!props) {
        std::printf("    props: unavailable (%s)\n", std::strerror(errno));
        return;
    }
    for (uint32_t i = 0; i < props->count_props; ++i) {
        drmModePropertyPtr prop = drmModeGetProperty(fd, props->props[i]);
        if (!prop) {
            continue;
        }
        std::printf("    prop %-24s = %" PRIu64 "\n", prop->name, props->prop_values[i]);
        drmModeFreeProperty(prop);
    }
    drmModeFreeObjectProperties(props);
}

void print_connectors(int fd, drmModeResPtr res, bool list_props) {
    std::printf("[drm] connectors=%d\n", res->count_connectors);
    for (int i = 0; i < res->count_connectors; ++i) {
        drmModeConnectorPtr c = drmModeGetConnector(fd, res->connectors[i]);
        if (!c) {
            continue;
        }
        std::printf("[drm] connector id=%u type=%s-%u status=%s modes=%d encoders=%d\n",
            c->connector_id, connector_type_name(c->connector_type),
            c->connector_type_id, connection_name(c->connection),
            c->count_modes, c->count_encoders);
        if (c->connection == DRM_MODE_CONNECTED && c->count_modes > 0) {
            const drmModeModeInfo& m = c->modes[0];
            std::printf("      preferred-ish mode: %ux%u@%u clock=%u\n",
                m.hdisplay, m.vdisplay, m.vrefresh, m.clock);
        }
        if (list_props) {
            print_props(fd, c->connector_id, DRM_MODE_OBJECT_CONNECTOR);
        }
        drmModeFreeConnector(c);
    }
}

void print_crtcs(int fd, drmModeResPtr res, bool list_props) {
    std::printf("[drm] crtcs=%d\n", res->count_crtcs);
    for (int i = 0; i < res->count_crtcs; ++i) {
        drmModeCrtcPtr c = drmModeGetCrtc(fd, res->crtcs[i]);
        if (!c) {
            continue;
        }
        std::printf("[drm] crtc id=%u active=%d pos=%dx%d size=%ux%u\n",
            c->crtc_id, c->mode_valid, c->x, c->y, c->width, c->height);
        if (list_props) {
            print_props(fd, c->crtc_id, DRM_MODE_OBJECT_CRTC);
        }
        drmModeFreeCrtc(c);
    }
}

void print_planes(int fd, bool list_props) {
    drmModePlaneResPtr planes = drmModeGetPlaneResources(fd);
    if (!planes) {
        std::printf("[drm] planes unavailable (%s)\n", std::strerror(errno));
        return;
    }
    std::printf("[drm] planes=%u\n", planes->count_planes);
    for (uint32_t i = 0; i < planes->count_planes; ++i) {
        drmModePlanePtr p = drmModeGetPlane(fd, planes->planes[i]);
        if (!p) {
            continue;
        }
        std::printf("[drm] plane id=%u crtc_id=%u fb_id=%u possible_crtcs=0x%x formats=%u\n",
            p->plane_id, p->crtc_id, p->fb_id, p->possible_crtcs, p->count_formats);
        std::printf("      formats:");
        for (uint32_t j = 0; j < p->count_formats && j < 12; ++j) {
            char fourcc[5] = {
                static_cast<char>(p->formats[j] & 0xff),
                static_cast<char>((p->formats[j] >> 8) & 0xff),
                static_cast<char>((p->formats[j] >> 16) & 0xff),
                static_cast<char>((p->formats[j] >> 24) & 0xff),
                '\0',
            };
            std::printf(" %s", fourcc);
        }
        std::printf("\n");
        if (list_props) {
            print_props(fd, p->plane_id, DRM_MODE_OBJECT_PLANE);
        }
        drmModeFreePlane(p);
    }
    drmModeFreePlaneResources(planes);
}

} // namespace

int main(int argc, char** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        return 2;
    }

    const int fd = open(opt.device.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        std::fprintf(stderr, "[drm] open %s failed: %s\n", opt.device.c_str(), std::strerror(errno));
        return 1;
    }

    const int universal = drmSetClientCap(fd, DRM_CLIENT_CAP_UNIVERSAL_PLANES, 1);
    const int universal_errno = errno;
    const int atomic = drmSetClientCap(fd, DRM_CLIENT_CAP_ATOMIC, 1);
    const int atomic_errno = errno;
    std::printf("[drm] device=%s universal_planes=%s atomic=%s\n",
        opt.device.c_str(),
        universal == 0 ? "yes" : std::strerror(universal_errno),
        atomic == 0 ? "yes" : std::strerror(atomic_errno));

    drmModeResPtr res = drmModeGetResources(fd);
    if (!res) {
        std::fprintf(stderr, "[drm] drmModeGetResources failed: %s\n", std::strerror(errno));
        close(fd);
        return 1;
    }

    print_connectors(fd, res, opt.list_props);
    print_crtcs(fd, res, opt.list_props);
    print_planes(fd, opt.list_props);

    drmModeFreeResources(res);
    close(fd);
    return atomic == 0 ? 0 : 1;
}
