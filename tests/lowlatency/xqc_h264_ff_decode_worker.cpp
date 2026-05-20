/**
 * @file xqc_h264_ff_decode_worker.cpp
 * @brief Off-reactor H.264 decode: stream path + optional EOS file verification.
 *
 * ## Thread model
 * - **libevent / Seastar reactor**: parses QUIC video wire, calls `xqc_h264_decode_push_annexb_ts`.
 * - **DecodeWorker thread** (this file): SPSC Annex-B ring → NV12 → lock-free NV12 SPSC ring.
 * - **Display thread** (`xqc_nv12_gl_linux.cpp`): pops NV12, uploads to GPU, presents.
 *
 * ## GPU vs CPU on Linux/WSL (current default)
 * | Stage | Hardware | Notes |
 * |-------|----------|-------|
 * | H.264 decode | **CPU** (libavcodec software) | `avcodec_open2` without hwdevice on Linux |
 * | Pixel format | **CPU** (libswscale) | If decoder outputs non-NV12, `sws_scale` to NV12 |
 * | NV12 pack | **CPU** (`memcpy` rows) | `frame_to_nv12` builds compact buffer for GL |
 * | Upload | **GPU** (OpenGL PBO) | `glMapBufferRange` → `glTexSubImage2D` from PBO |
 * | YUV→RGB | **GPU** (GLSL 3.3) | Fragment shader samples R8 + RG8 textures |
 * | Present | **GPU** (swapchain) | `glfwSwapBuffers` |
 *
 * Windows builds may attempt **D3D11VA** hw decode (`AV_HWDEVICE_TYPE_D3D11VA`); frames are
 * still converted to CPU NV12 today before the Windows GL viewer — see `xqc_pbo_dynamic_manager.hh`.
 *
 * **4K**: queue depth 4 × ~12 MiB NV12 ≈ 48 MiB worst case; see `XQC_NV12_BYTES_4K`.
 *
 * ## Stream vs EOS file
 * - **Stream**: `CamDecoder` + `av_parser_parse2` per camera (low latency, `from_stream=true`).
 * - **EOS file**: `decode_file_impl` via libavformat (validation, `from_stream=false`).
 */

#include "xqc_h264_ff_decode_api.hh"
#include "xqc_e2e_latency.hh"
#include "xqc_h264_decode_stats.hh"
#include "xqc_h264_hw_linux.hh"
#include "xqc_spsc_frame_queue.hh"
#include "xqc_thread_affinity.hh"
#include "xqc_video_codec.hh"
#include "xqc_video_low_latency.hh"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <sys/time.h>
#include <thread>
#include <vector>

static constexpr std::size_t kAnnexbRingCapacity = 64;
static constexpr std::size_t kNv12RingCapacity = 8;

#if defined(XQC_HAVE_FFMPEG)

#if defined(XQC_HAVE_HW_DECODE)
#include "xqc_h264_hw_linux.hh"
#else
void xqc_nv12_frame_release(XqcNv12Frame& f) {
    (void)f;
}
#endif

static XqcH264DecodeStats g_stats;
static XqcSpscQueueStats g_spsc_stats;
static XqcVideoCodec g_default_codec = XqcVideoCodec::HEVC;
static std::map<uint16_t, XqcVideoCodec> g_camera_codecs;
static std::mutex g_codec_mu;

static XqcVideoCodec codec_for_camera(uint16_t camera_id) {
    std::lock_guard<std::mutex> lk(g_codec_mu);
    const auto it = g_camera_codecs.find(camera_id);
    if (it != g_camera_codecs.end()) {
        return it->second;
    }
    return g_default_codec;
}

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/imgutils.h>
#include <libavutil/frame.h>
#include <libavutil/log.h>
#include <libswscale/swscale.h>
#if defined(_WIN32) || defined(_WIN64)
#include <libavutil/hwcontext.h>
#endif
}

static constexpr int kMaxDrainFrames = 64;
static constexpr int kMaxParserSteps = 256;

static uint64_t wall_us() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return static_cast<uint64_t>(tv.tv_sec) * 1000000ULL + static_cast<uint64_t>(tv.tv_usec);
}

/** CPU NV12 pack (software decode, CUDA hwdownload, or swscale). */
bool xqc_frame_to_nv12_cpu(const AVFrame* src, uint16_t camera_id, XqcNv12Frame& out) {
    if (!src || src->width <= 0 || src->height <= 0) {
        return false;
    }

    const int w = src->width;
    const int h = src->height;
    const size_t need = static_cast<size_t>(w) * static_cast<size_t>(h)
        + static_cast<size_t>(w) * static_cast<size_t>(h / 2);

    if (src->format == AV_PIX_FMT_NV12) {
        out.camera_id = camera_id;
        out.width = w;
        out.height = h;
        out.backing = XqcNv12Backing::Cpu;
        out.data.resize(need);
        const size_t y_sz = static_cast<size_t>(w) * static_cast<size_t>(h);
        for (int row = 0; row < h; ++row) {
            std::memcpy(out.data.data() + static_cast<size_t>(row) * static_cast<size_t>(w),
                src->data[0] + static_cast<size_t>(row) * static_cast<size_t>(src->linesize[0]),
                static_cast<size_t>(w));
        }
        uint8_t* uv_dst = out.data.data() + y_sz;
        for (int row = 0; row < h / 2; ++row) {
            std::memcpy(uv_dst + static_cast<size_t>(row) * static_cast<size_t>(w),
                src->data[1] + static_cast<size_t>(row) * static_cast<size_t>(src->linesize[1]),
                static_cast<size_t>(w));
        }
        return true;
    }

    SwsContext* sws = sws_getContext(w, h, static_cast<AVPixelFormat>(src->format),
        w, h, AV_PIX_FMT_NV12, SWS_BILINEAR, nullptr, nullptr, nullptr);
    if (!sws) {
        return false;
    }

    AVFrame* dst = av_frame_alloc();
    if (!dst) {
        sws_freeContext(sws);
        return false;
    }
    dst->format = AV_PIX_FMT_NV12;
    dst->width = w;
    dst->height = h;
    if (av_frame_get_buffer(dst, 32) < 0) {
        av_frame_free(&dst);
        sws_freeContext(sws);
        return false;
    }
    sws_scale(sws, src->data, src->linesize, 0, h, dst->data, dst->linesize);
    sws_freeContext(sws);

    const bool ok = xqc_frame_to_nv12_cpu(dst, camera_id, out);
    av_frame_free(&dst);
    return ok;
}

namespace {

struct Slice {
    uint16_t camera_id = 0;
    std::vector<uint8_t> annexb;
    bool flush = false;
    int64_t wire_pts_us = 0;
    uint64_t recv_us = 0;
};

XqcSpscFrameQueue<XqcNv12Frame, kNv12RingCapacity> g_nv12_ring;
std::atomic<bool> g_nv12_out{false};
std::thread::id g_nv12_producer_tid{};

void nv12_frame_release_fn(XqcNv12Frame& f) {
    xqc_nv12_frame_release(f);
}

void nv12_push_drop_oldest(XqcNv12Frame&& nv12) {
    if (!g_nv12_out.load(std::memory_order_acquire)) {
        nv12_frame_release_fn(nv12);
        return;
    }
    const std::size_t max_depth = xqc_video_nv12_queue_depth();
    while (g_nv12_ring.size() >= max_depth) {
        XqcNv12Frame old;
        if (!g_nv12_ring.try_pop(old)) {
            break;
        }
        g_spsc_stats.nv12_drop_depth.fetch_add(1, std::memory_order_relaxed);
        nv12_frame_release_fn(old);
    }
    const bool ring_full = g_nv12_ring.size() >= g_nv12_ring.usable_capacity();
    if (!g_nv12_ring.push_drop_oldest(std::move(nv12), nv12_frame_release_fn)) {
        g_spsc_stats.nv12_drop_ring.fetch_add(1, std::memory_order_relaxed);
        nv12_frame_release_fn(nv12);
    } else {
        g_spsc_stats.nv12_push.fetch_add(1, std::memory_order_relaxed);
        if (ring_full) {
            g_spsc_stats.nv12_drop_ring.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

bool nv12_push_allowed_from_this_thread() {
    const auto producer = g_nv12_producer_tid;
    return producer == std::thread::id{} || std::this_thread::get_id() == producer;
}

class DecodeWorker;

/**
 * Per-camera streaming decoder: persistent parser + codec context.
 * SPS/PPS on the wire populate extradata via av_parser_parse2 before slice NALs decode.
 */
class CamDecoder {
public:
    explicit CamDecoder(DecodeWorker* owner) : owner_(owner) {}

    ~CamDecoder() {
        close();
    }

    void set_codec(XqcVideoCodec codec);
    bool ensure_open();
    void feed(const uint8_t* data, std::size_t len, uint16_t camera_id,
        int64_t wire_pts_us, uint64_t recv_us);
    void flush(uint16_t camera_id);

private:
    void close();
    bool should_feed_nal(const uint8_t* nal, int size) const;
    void send_packet(const uint8_t* pkt_data, int pkt_len, uint16_t camera_id,
        int64_t wire_pts_us, uint64_t recv_us);
    void drain(uint16_t camera_id, int64_t wire_pts_us, uint64_t recv_us);

    DecodeWorker* owner_ = nullptr;
    AVCodecContext* ctx_ = nullptr;
    AVCodecParserContext* parser_ = nullptr;
    AVPacket* pkt_ = nullptr;
    AVFrame* frame_ = nullptr;
    bool open_ = false;
    XqcVideoCodec codec_ = XqcVideoCodec::HEVC;
    int64_t pending_pts_ = 0;
    uint64_t pending_recv_ = 0;
};

class DecodeWorker {
public:
    DecodeWorker() = default;

    void start() {
        if (thread_.joinable()) {
            return;
        }
        stop_.store(false, std::memory_order_release);
        annexb_ring_.reset();
        frames_out_ = 0;
        thread_ = std::thread([this] { run(); });
    }

    void stop() {
        stop_.store(true, std::memory_order_release);
        request_flush(0);
        if (thread_.joinable()) {
            thread_.join();
        }
        decoders_.clear();
    }

    void push_ts(uint16_t camera_id, const uint8_t* p, std::size_t n,
        int64_t wire_pts_us, uint64_t recv_us)
    {
        if (stop_.load(std::memory_order_acquire) || n == 0) {
            return;
        }
        g_stats.annexb_pushed.fetch_add(1);
        Slice s;
        s.camera_id = camera_id;
        s.wire_pts_us = wire_pts_us;
        s.recv_us = recv_us;
        s.annexb.assign(p, p + n);
        const bool annexb_full = annexb_ring_.size() >= annexb_ring_.usable_capacity();
        annexb_ring_.push_drop_oldest(std::move(s));
        g_spsc_stats.annexb_push.fetch_add(1, std::memory_order_relaxed);
        if (annexb_full) {
            g_spsc_stats.annexb_drop_oldest.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void request_flush(uint16_t camera_id = 0) {
        Slice s;
        s.camera_id = camera_id;
        s.flush = true;
        annexb_ring_.push_drop_oldest(std::move(s));
    }

    std::size_t annexb_queue_depth() const {
        return annexb_ring_.size();
    }

    void emit_nv12(const AVFrame* frame, uint16_t camera_id,
        int64_t wire_pts_us, uint64_t recv_us, bool from_file);

private:
    CamDecoder& decoder_for(uint16_t camera_id);

    void run();

    XqcSpscFrameQueue<Slice, kAnnexbRingCapacity> annexb_ring_;
    std::thread thread_;
    std::atomic<bool> stop_{false};
    uint64_t frames_out_ = 0;
    std::map<uint16_t, std::unique_ptr<CamDecoder>> decoders_;
};

void DecodeWorker::emit_nv12(const AVFrame* frame, uint16_t camera_id,
    int64_t wire_pts_us, uint64_t recv_us, bool from_file)
{
    ++frames_out_;
    const uint64_t decode_us = wall_us();
    XqcNv12Frame nv12;
    bool ok = false;
#if defined(XQC_HAVE_HW_DECODE)
    ok = xqc_h264_hw_frame_to_output(const_cast<AVFrame*>(frame), nv12, camera_id);
#endif
    if (!ok) {
        ok = xqc_frame_to_nv12_cpu(frame, camera_id, nv12);
    }
    if (!ok) {
        return;
    }
    nv12.pts_us = wire_pts_us;
    nv12.recv_us = recv_us;
    nv12.decode_us = decode_us;
    nv12.from_stream = !from_file;
    xqc_h264_decode_stats_note_nv12(recv_us, decode_us, wire_pts_us, from_file);

    nv12_push_drop_oldest(std::move(nv12));
    if ((frames_out_ & 63u) == 0u) {
        std::fprintf(stderr, "[decode] camera=%u frames=%llu %dx%d\n",
            static_cast<unsigned>(camera_id),
            static_cast<unsigned long long>(frames_out_),
            frame->width, frame->height);
    }
}

CamDecoder& DecodeWorker::decoder_for(uint16_t camera_id) {
    auto it = decoders_.find(camera_id);
    if (it == decoders_.end()) {
        auto dec = std::make_unique<CamDecoder>(this);
        dec->set_codec(codec_for_camera(camera_id));
        it = decoders_.emplace(camera_id, std::move(dec)).first;
    } else {
        it->second->set_codec(codec_for_camera(camera_id));
    }
    return *it->second;
}

void CamDecoder::set_codec(XqcVideoCodec codec) {
    if (codec_ == codec) {
        return;
    }
    if (open_) {
        close();
    }
    codec_ = codec;
}

bool CamDecoder::ensure_open() {
    if (open_) {
        return true;
    }
    const enum AVCodecID av_id = xqc_video_codec_av_id(codec_);
    ctx_ = avcodec_alloc_context3(nullptr);
    parser_ = av_parser_init(av_id);
    pkt_ = av_packet_alloc();
    frame_ = av_frame_alloc();
    if (!ctx_ || !parser_ || !pkt_ || !frame_) {
        close();
        return false;
    }
    const AVCodec* codec = nullptr;
#if defined(XQC_HAVE_HW_DECODE)
    if (xqc_h264_hw_active_backend() != XqcHwDecodeBackend::Software
        && xqc_h264_hw_open_decoder(ctx_, codec, codec_)) {
        open_ = true;
        std::fprintf(stderr, "[decode] camera codec=%s backend=%s\n",
            xqc_video_codec_name(codec_), xqc_h264_hw_backend_name());
        return true;
    }
    close();
    ctx_ = avcodec_alloc_context3(nullptr);
    parser_ = av_parser_init(av_id);
    pkt_ = av_packet_alloc();
    frame_ = av_frame_alloc();
    if (!ctx_ || !parser_ || !pkt_ || !frame_) {
        close();
        return false;
    }
#endif
    codec = avcodec_find_decoder(av_id);
    if (!codec) {
        close();
        return false;
    }
    ctx_->thread_count = 1;
    ctx_->max_b_frames = 0;
    ctx_->flags |= AV_CODEC_FLAG_LOW_DELAY;
    if (avcodec_open2(ctx_, codec, nullptr) < 0) {
        close();
        return false;
    }
    open_ = true;
    std::fprintf(stderr, "[decode] camera codec=%s backend=software\n",
        xqc_video_codec_name(codec_));
    return true;
}

void CamDecoder::close() {
    if (ctx_) {
        avcodec_free_context(&ctx_);
        ctx_ = nullptr;
    }
    if (parser_) {
        av_parser_close(parser_);
        parser_ = nullptr;
    }
    av_packet_free(&pkt_);
    av_frame_free(&frame_);
    open_ = false;
}

bool CamDecoder::should_feed_nal(const uint8_t* nal, int size) const {
    return xqc_annexb_should_feed_nal(codec_, nal, size);
}

void CamDecoder::drain(uint16_t camera_id, int64_t wire_pts_us, uint64_t recv_us) {
    for (int n = 0; n < kMaxDrainFrames && avcodec_receive_frame(ctx_, frame_) == 0; ++n) {
        owner_->emit_nv12(frame_, camera_id, wire_pts_us, recv_us, false);
        av_frame_unref(frame_);
    }
}

void CamDecoder::send_packet(const uint8_t* pkt_data, int pkt_len, uint16_t camera_id,
    int64_t wire_pts_us, uint64_t recv_us)
{
    if (pkt_len <= 4) {
        return;
    }
    const uint8_t* rbsp = pkt_data;
    int rbsp_len = pkt_len;
    if (pkt_data[0] == 0 && pkt_data[1] == 0
        && (pkt_data[2] == 1 || (pkt_data[2] == 0 && pkt_data[3] == 1))) {
        rbsp = pkt_data + (pkt_data[2] == 1 ? 3 : 4);
        rbsp_len = pkt_len - static_cast<int>(rbsp - pkt_data);
    }
    if (!should_feed_nal(rbsp, rbsp_len)) {
        return;
    }
    if (av_new_packet(pkt_, pkt_len) < 0) {
        return;
    }
    std::memcpy(pkt_->data, pkt_data, static_cast<size_t>(pkt_len));
    pkt_->size = pkt_len;
    pkt_->pts = wire_pts_us;
    int ret = avcodec_send_packet(ctx_, pkt_);
    for (int retry = 0; ret == AVERROR(EAGAIN) && retry < 8; ++retry) {
        drain(camera_id, wire_pts_us, recv_us);
        ret = avcodec_send_packet(ctx_, pkt_);
    }
    if (ret >= 0) {
        drain(camera_id, wire_pts_us, recv_us);
    }
    av_packet_unref(pkt_);
}

void CamDecoder::feed(const uint8_t* data, std::size_t len, uint16_t camera_id,
    int64_t wire_pts_us, uint64_t recv_us)
{
    if (!open_ || !data || len == 0) {
        return;
    }
    pending_pts_ = wire_pts_us;
    pending_recv_ = recv_us;

    const uint8_t* in = data;
    int in_len = static_cast<int>(len);
    int steps = 0;
    while (in_len > 0 && steps++ < kMaxParserSteps) {
        uint8_t* out_pkt = nullptr;
        int out_pkt_size = 0;
        const int used = av_parser_parse2(parser_, ctx_, &out_pkt, &out_pkt_size,
            in, in_len, wire_pts_us, wire_pts_us, 0);
        if (used < 0) {
            break;
        }
        if (used == 0 && out_pkt_size == 0) {
            break;
        }
        in += used;
        in_len -= used;
        if (out_pkt_size > 0 && out_pkt) {
            send_packet(out_pkt, out_pkt_size, camera_id, pending_pts_, pending_recv_);
        }
    }
}

void CamDecoder::flush(uint16_t camera_id) {
    if (!open_) {
        return;
    }
    int ret = avcodec_send_packet(ctx_, nullptr);
    if (ret == AVERROR(EAGAIN)) {
        drain(camera_id, pending_pts_, pending_recv_);
        (void)avcodec_send_packet(ctx_, nullptr);
    }
    drain(camera_id, pending_pts_, pending_recv_);
}

void DecodeWorker::run() {
    int decode_cpu = -1;
    int display_cpu = -1;
    xqc_resolve_pipeline_cpus(decode_cpu, display_cpu);
    (void)xqc_pin_current_thread(decode_cpu, "decode");

    av_log_set_level(AV_LOG_FATAL);
    g_nv12_producer_tid = std::this_thread::get_id();
    std::fprintf(stderr,
        "[decode] stream worker started default_codec=%s backend=%s SPSC annexb=%zu nv12=%zu lock-free=1 (FFmpeg %d.x)\n",
        xqc_video_codec_name(g_default_codec),
#if defined(XQC_HAVE_HW_DECODE)
        xqc_h264_hw_backend_name(),
#else
        "software",
#endif
        kAnnexbRingCapacity - 1,
        kNv12RingCapacity - 1,
        LIBAVCODEC_VERSION_MAJOR);

    auto process_slice = [this](Slice& slice) {
        g_spsc_stats.annexb_pop.fetch_add(1, std::memory_order_relaxed);
        CamDecoder& dec = decoder_for(slice.camera_id);
        if (!dec.ensure_open()) {
            std::fprintf(stderr, "[decode] camera %u open failed\n", slice.camera_id);
            return;
        }
        if (slice.flush) {
            dec.flush(slice.camera_id);
            return;
        }
        dec.feed(slice.annexb.data(), slice.annexb.size(), slice.camera_id,
            slice.wire_pts_us, slice.recv_us);
    };

    while (true) {
        Slice slice;
        if (annexb_ring_.try_pop(slice)) {
            process_slice(slice);
            continue;
        }
        if (stop_.load(std::memory_order_acquire)) {
            while (annexb_ring_.try_pop(slice)) {
                process_slice(slice);
            }
            break;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }

    for (auto& kv : decoders_) {
        kv.second->flush(kv.first);
    }
    decoders_.clear();
    g_nv12_producer_tid = std::thread::id{};
    std::fprintf(stderr, "[decode] exit frames=%llu stream=%llu file=%llu\n",
        static_cast<unsigned long long>(frames_out_),
        static_cast<unsigned long long>(g_stats.stream_frames.load()),
        static_cast<unsigned long long>(g_stats.file_frames.load()));
}

void decode_file_impl(const char* path, uint16_t camera_id) {
    if (!path || !path[0]) {
        return;
    }
    av_log_set_level(AV_LOG_FATAL);

    AVFormatContext* fmt = nullptr;
    if (avformat_open_input(&fmt, path, nullptr, nullptr) < 0) {
        std::fprintf(stderr, "[decode_file] open failed: %s\n", path);
        return;
    }
    if (avformat_find_stream_info(fmt, nullptr) < 0) {
        avformat_close_input(&fmt);
        return;
    }
    const int vidx = av_find_best_stream(fmt, AVMEDIA_TYPE_VIDEO, -1, -1, nullptr, 0);
    if (vidx < 0) {
        avformat_close_input(&fmt);
        return;
    }
    AVCodecParameters* par = fmt->streams[vidx]->codecpar;
    const AVCodec* codec = avcodec_find_decoder(par->codec_id);
    if (!codec) {
        avformat_close_input(&fmt);
        return;
    }
    AVCodecContext* ctx = avcodec_alloc_context3(codec);
    if (!ctx || avcodec_parameters_to_context(ctx, par) < 0) {
        avcodec_free_context(&ctx);
        avformat_close_input(&fmt);
        return;
    }
    ctx->thread_count = 1;
    if (avcodec_open2(ctx, codec, nullptr) < 0) {
        avcodec_free_context(&ctx);
        avformat_close_input(&fmt);
        return;
    }

    AVPacket* pkt = av_packet_alloc();
    AVFrame* frame = av_frame_alloc();
    uint64_t frames = 0;
    const uint64_t recv_us = wall_us();
    while (av_read_frame(fmt, pkt) >= 0) {
        if (pkt->stream_index != vidx) {
            av_packet_unref(pkt);
            continue;
        }
        if (avcodec_send_packet(ctx, pkt) < 0) {
            av_packet_unref(pkt);
            continue;
        }
        av_packet_unref(pkt);
        while (avcodec_receive_frame(ctx, frame) == 0) {
            ++frames;
            const uint64_t decode_us = wall_us();
            XqcNv12Frame nv12;
            if (xqc_frame_to_nv12_cpu(frame, camera_id, nv12)) {
                nv12.recv_us = recv_us;
                nv12.decode_us = decode_us;
                nv12.from_stream = false;
                xqc_h264_decode_stats_note_nv12(recv_us, decode_us, 0, true);
                if (nv12_push_allowed_from_this_thread()) {
                    nv12_push_drop_oldest(std::move(nv12));
                }
            }
            av_frame_unref(frame);
        }
    }
    avcodec_send_packet(ctx, nullptr);
    while (avcodec_receive_frame(ctx, frame) == 0) {
        ++frames;
        const uint64_t decode_us = wall_us();
        XqcNv12Frame nv12;
        if (xqc_frame_to_nv12_cpu(frame, camera_id, nv12)) {
            nv12.recv_us = recv_us;
            nv12.decode_us = decode_us;
            nv12.from_stream = false;
            xqc_h264_decode_stats_note_nv12(recv_us, decode_us, 0, true);
            if (nv12_push_allowed_from_this_thread()) {
                nv12_push_drop_oldest(std::move(nv12));
            }
        }
        av_frame_unref(frame);
    }

    const char* cname = "unknown";
    if (par->codec_id == AV_CODEC_ID_H264) {
        cname = "h264";
    } else if (par->codec_id == AV_CODEC_ID_HEVC) {
        cname = "hevc";
    }
    std::fprintf(stderr, "[decode_file] %s (%s) -> %llu frames\n", path, cname,
        static_cast<unsigned long long>(frames));

    av_frame_free(&frame);
    av_packet_free(&pkt);
    avcodec_free_context(&ctx);
    avformat_close_input(&fmt);
}

std::mutex g_mu;
std::unique_ptr<DecodeWorker> g_worker;

} // namespace

void xqc_h264_decode_stats_reset() {
    g_stats.annexb_pushed.store(0);
    g_stats.nv12_out.store(0);
    g_stats.stream_frames.store(0);
    g_stats.file_frames.store(0);
    g_stats.latency_sum_us.store(0);
    g_stats.latency_count.store(0);
    g_stats.last_wire_pts_us.store(0);
    g_stats.last_decode_us.store(0);
    g_spsc_stats.annexb_push.store(0);
    g_spsc_stats.annexb_pop.store(0);
    g_spsc_stats.annexb_drop_oldest.store(0);
    g_spsc_stats.nv12_push.store(0);
    g_spsc_stats.nv12_drop_depth.store(0);
    g_spsc_stats.nv12_drop_ring.store(0);
    g_spsc_stats.nv12_display_pop.store(0);
    g_spsc_stats.nv12_skipped_latest.store(0);
    g_spsc_stats.display_submit.store(0);
}

XqcH264DecodeStats* xqc_h264_decode_stats() {
    return &g_stats;
}

XqcSpscQueueStats* xqc_spsc_queue_stats() {
    return &g_spsc_stats;
}

void xqc_h264_decode_log_spsc_stats() {
    const std::size_t annexb_depth = xqc_h264_decode_annexb_queue_depth();
    const std::size_t nv12_depth = xqc_h264_decode_nv12_queue_depth();
    std::fprintf(stderr,
        "[spsc] annexb push=%llu pop=%llu drop=%llu depth=%zu/%zu"
        " | nv12 push=%llu pop=%llu skip=%llu drop_depth=%llu drop_ring=%llu depth=%zu/%zu"
        " | display_submit=%llu lock_free=1\n",
        static_cast<unsigned long long>(g_spsc_stats.annexb_push.load()),
        static_cast<unsigned long long>(g_spsc_stats.annexb_pop.load()),
        static_cast<unsigned long long>(g_spsc_stats.annexb_drop_oldest.load()),
        annexb_depth, kAnnexbRingCapacity - 1,
        static_cast<unsigned long long>(g_spsc_stats.nv12_push.load()),
        static_cast<unsigned long long>(g_spsc_stats.nv12_display_pop.load()),
        static_cast<unsigned long long>(g_spsc_stats.nv12_skipped_latest.load()),
        static_cast<unsigned long long>(g_spsc_stats.nv12_drop_depth.load()),
        static_cast<unsigned long long>(g_spsc_stats.nv12_drop_ring.load()),
        nv12_depth, kNv12RingCapacity - 1,
        static_cast<unsigned long long>(g_spsc_stats.display_submit.load()));
}

void xqc_h264_decode_note_display_submit() {
    g_spsc_stats.display_submit.fetch_add(1, std::memory_order_relaxed);
}

void xqc_h264_decode_stats_note_nv12(uint64_t recv_us, uint64_t decode_us,
    int64_t wire_pts_us, bool from_file)
{
    g_stats.nv12_out.fetch_add(1);
    if (from_file) {
        g_stats.file_frames.fetch_add(1);
    } else {
        g_stats.stream_frames.fetch_add(1);
    }
    if (recv_us > 0 && decode_us >= recv_us) {
        g_stats.latency_sum_us.fetch_add(decode_us - recv_us);
        g_stats.latency_count.fetch_add(1);
    }
    if (wire_pts_us > 0) {
        g_stats.last_wire_pts_us.store(static_cast<uint64_t>(wire_pts_us));
    }
    g_stats.last_decode_us.store(decode_us);
}

void xqc_h264_decode_enable_nv12_output(bool enable) {
    g_nv12_out.store(enable, std::memory_order_release);
    if (enable) {
        std::fprintf(stderr,
            "[spsc] NV12 ring enabled cap=%zu max_depth=%zu (lock-free SPSC, display bridge consumer)\n",
            kNv12RingCapacity - 1, xqc_video_nv12_queue_depth());
    } else {
        XqcNv12Frame dropped;
        while (g_nv12_ring.try_pop(dropped)) {
            nv12_frame_release_fn(dropped);
        }
        g_nv12_ring.reset();
    }
}

std::size_t xqc_h264_decode_annexb_queue_depth() {
    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_worker) {
        return 0;
    }
    return g_worker->annexb_queue_depth();
}

std::size_t xqc_h264_decode_nv12_queue_depth() {
    return g_nv12_ring.size();
}

bool xqc_h264_decode_try_pop_nv12(XqcNv12Frame& out) {
    if (!g_nv12_out.load(std::memory_order_acquire)) {
        return false;
    }
    if (!g_nv12_ring.try_pop(out)) {
        return false;
    }
    g_spsc_stats.nv12_display_pop.fetch_add(1, std::memory_order_relaxed);
    XqcNv12Frame newer;
    while (g_nv12_ring.try_pop(newer)) {
        g_spsc_stats.nv12_skipped_latest.fetch_add(1, std::memory_order_relaxed);
        nv12_frame_release_fn(out);
        out = std::move(newer);
    }
    return true;
}

bool xqc_h264_decode_try_pop_nv12_fifo(XqcNv12Frame& out) {
    if (!g_nv12_out.load(std::memory_order_acquire)) {
        return false;
    }
    return g_nv12_ring.try_pop(out);
}

void xqc_h264_decode_configure_hw(const char* mode) {
#if defined(XQC_HAVE_HW_DECODE)
    xqc_h264_hw_configure(mode);
#else
    (void)mode;
#endif
}

void xqc_h264_decode_set_default_codec(XqcVideoCodec codec) {
    std::lock_guard<std::mutex> lk(g_codec_mu);
    g_default_codec = codec;
}

void xqc_h264_decode_set_camera_codec(uint16_t camera_id, XqcVideoCodec codec) {
    std::lock_guard<std::mutex> lk(g_codec_mu);
    g_camera_codecs[camera_id] = codec;
}

XqcVideoCodec xqc_h264_decode_camera_codec(uint16_t camera_id) {
    return codec_for_camera(camera_id);
}

void xqc_h264_decode_worker_start() {
    xqc_h264_decode_stats_reset();
    xqc_e2e_latency_reset();
#if defined(XQC_HAVE_HW_DECODE)
    /* Probe GPU before first NAL (CUDA init can take seconds). */
    xqc_h264_hw_init();
    std::fprintf(stderr, "[decode] hw ready backend=%s default_codec=%s\n",
        xqc_h264_hw_backend_name(), xqc_video_codec_name(g_default_codec));
#endif
    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_worker) {
        g_worker = std::make_unique<DecodeWorker>();
    }
    g_worker->start();
    std::fprintf(stderr,
        "[spsc] decode worker up: Annex-B ring producer=reactor consumer=decode-thread (cap=%zu)\n",
        kAnnexbRingCapacity - 1);
}

void xqc_h264_decode_worker_stop() {
    xqc_h264_decode_enable_nv12_output(false);
    std::unique_ptr<DecodeWorker> w;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        w = std::move(g_worker);
    }
    if (w) {
        w->stop();
    }
}

void xqc_h264_decode_push_annexb_ts(uint16_t camera_id, const uint8_t* annexb,
    std::size_t annexb_len, int64_t wire_pts_us, uint64_t recv_us)
{
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_worker) {
        g_worker->push_ts(camera_id, annexb, annexb_len, wire_pts_us, recv_us);
    }
}

void xqc_h264_decode_push_annexb(uint16_t camera_id, const uint8_t* annexb, std::size_t annexb_len) {
    xqc_h264_decode_push_annexb_ts(camera_id, annexb, annexb_len, 0, 0);
}

void xqc_h264_decode_flush_camera(uint16_t camera_id) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_worker) {
        g_worker->request_flush(camera_id);
    }
}

void xqc_h264_decode_flush() {
    xqc_h264_decode_flush_camera(0);
}

void xqc_h264_decode_file(const char* path, uint16_t camera_id) {
    decode_file_impl(path, camera_id);
}

#else

void xqc_h264_decode_stats_reset() {}
XqcH264DecodeStats* xqc_h264_decode_stats() { return nullptr; }
XqcSpscQueueStats* xqc_spsc_queue_stats() { return nullptr; }
void xqc_h264_decode_log_spsc_stats() {}
void xqc_h264_decode_note_display_submit() {}
void xqc_h264_decode_stats_note_nv12(uint64_t, uint64_t, int64_t, bool) {}

void xqc_h264_decode_enable_nv12_output(bool) {}
bool xqc_h264_decode_try_pop_nv12(XqcNv12Frame&) { return false; }
bool xqc_h264_decode_try_pop_nv12_fifo(XqcNv12Frame&) { return false; }
void xqc_h264_decode_flush() {}
void xqc_h264_decode_flush_camera(uint16_t) {}
void xqc_h264_decode_file(const char*, uint16_t) {}
void xqc_h264_decode_configure_hw(const char*) {}
void xqc_h264_decode_set_default_codec(XqcVideoCodec) {}
void xqc_h264_decode_set_camera_codec(uint16_t, XqcVideoCodec) {}
XqcVideoCodec xqc_h264_decode_camera_codec(uint16_t) { return XqcVideoCodec::HEVC; }
void xqc_h264_decode_worker_start() {}
void xqc_h264_decode_worker_stop() {}
void xqc_h264_decode_push_annexb(uint16_t, const uint8_t*, std::size_t) {}
void xqc_h264_decode_push_annexb_ts(uint16_t, const uint8_t*, std::size_t, int64_t, uint64_t) {}

#endif
