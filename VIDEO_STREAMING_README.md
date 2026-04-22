# XQUIC Video Streaming Implementation

This document describes the high-performance video streaming implementation over XQUIC protocol with reordering and jitter buffer support.

## Overview

The implementation includes:
- Global timeline-based receiving buffer with PTS-based sorting
- Reordering mechanism with frame dependency tracking (I/P/B frames)
- Jitter buffer with dynamic latency control
- Lock-free queues for high-performance data transfer
- Support for multi-stream video transmission

## Architecture Components

### 1. Frame Handling System
- `FrameInfo` structure with PTS, DTS, frame type, dependencies, and data
- Dual indexing: `std::map<PTS, FrameInfo*>` for sorting and `std::unordered_map<FrameID, FrameInfo*>` for lookup
- Dependency checking to ensure I-frames arrive before P-frames that depend on them

### 2. VideoFrameHandler Class
- Core reordering and buffering logic
- Dynamic latency management (default 200ms target)
- Expired frame handling for resilience against packet loss
- Thread-safe operations

### 3. Integration Points
- Modified server to use `VideoFrameHandler` for processing incoming video streams
- Client-side video stream creation and chunking
- Lock-free queues for high-throughput data flow

## Building

### Prerequisites
- CMake >= 3.5
- OpenSSL/BoringSSL/BabaSSL
- libevent-dev
- C++11 compatible compiler

### Certificate Generation
```bash
cd tests/
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=test.xquic.com"
```

### Build Commands
```bash
chmod +x build_video_demo.sh
./build_video_demo.sh
```

## Running the Demo

### 1. Start the Server
```bash
cd build/
./test_server -p 8443 -c ../tests/server.crt -k ../tests/server.key
```

### 2. Start the Video Stream Sender (in another terminal)
```bash
cd build/
./video_stream_sender -a 127.0.0.1 -p 8443 -h test.xquic.com
```

### 3. Monitor Output
- Server logs will show received frames and processing
- Video data will be saved to `decoded_video.bin` in the server directory

## Key Features

### Reordering Logic
1. Data chunks from different streams are parsed for frame metadata
2. Frames are stored in a PTS-sorted buffer
3. Dependencies are checked before frames are marked as ready for decode
4. Jitter buffer holds frames until target latency is reached or timeout occurs

### Jitter Buffer Mechanism
- Target latency: 200ms by default
- Expired frame handling: Frames waiting longer than max threshold (500ms) are processed
- Dependency resolution: P-frames wait for their reference I/P-frames
- Resilience: Handles lost frames gracefully with error concealment

### Performance Optimizations
- Lock-free queues for inter-thread communication
- Efficient data structures for fast lookups
- Memory pooling to reduce allocation overhead
- Asynchronous processing pipeline

## Customization

### Adjusting Latency Settings
Modify the constructor of `VideoFrameHandler` to change target latency:
```cpp
g_video_handler = std::make_unique<VideoFrameHandler>(latency_ms); // Default is 200ms
```

### Frame Types
Currently supports:
- `FRAME_TYPE_I`: Key frames with no dependencies
- `FRAME_TYPE_P`: Predictive frames depending on previous frames
- `FRAME_TYPE_B`: Bidirectional frames (not currently used in demo)

## Troubleshooting

### Common Issues
1. **Certificate mismatch**: Ensure SNI in client matches certificate CN
2. **Port conflicts**: Verify port 8443 is available
3. **Library linking**: Ensure OpenSSL paths are correctly configured

### Debugging
Enable debug logging in XQUIC by adding `-DXQC_LOG_LEVEL=XQC_LOG_DEBUG` to the build configuration.

## Performance Considerations

The implementation is designed for high-throughput video streaming:
- Frame reassembly happens asynchronously
- Buffer sizes adapt to network conditions
- Memory allocations are minimized in hot paths
- Processing pipeline maximizes throughput under latency constraints