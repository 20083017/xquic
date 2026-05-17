##### build test_client/test_server, demo_client/demo_server #####
# CUnit TODO: fix test unit on windows
find_package(CUnit 2.1)
enable_testing()
set(HAVE_CUNIT ${CUNIT_FOUND})
if(HAVE_CUNIT)
    add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
endif()

option(XQC_ENABLE_SEASTAR_EXAMPLE "Build Seastar integration example under tests/" OFF)
option(XQC_ENABLE_LOWLATENCY_PHASES "Build W1-W5 low-latency sample tools (Windows: GPU selftest, NV12 viewer)" OFF)
option(XQC_ENABLE_LOWLATENCY_FFMPEG "FFmpeg H.264 decode worker for video_client + xquic_server_seastar (vcpkg)" OFF)
option(XQC_ENABLE_HW_DECODE "Linux VAAPI/CUDA hw decode + EGL dma-buf display (requires FFmpeg)" OFF)

# find LibEvent include and library path
find_package(LibEvent 2.0.21)
if(NOT LIBEVENT_FOUND)
    message(FATAL_ERROR "libevent with required version not found")
endif()

include_directories(
    "${CMAKE_SOURCE_DIR}/"
    "${CMAKE_SOURCE_DIR}/include"
    ${CMAKE_SOURCE_DIR}
    ${CUNIT_INCLUDE_DIRS}
    ${LIBEVENT_INCLUDE_DIR}
)

set(LOWLATENCY_H264_DECODE_SOURCES lowlatency/xqc_h264_ff_decode_worker.cpp)

if(XQC_ENABLE_LOWLATENCY_FFMPEG)
    if(CMAKE_SYSTEM_NAME MATCHES "Windows")
        find_package(ffmpeg CONFIG REQUIRED)
        set(XQC_FFMPEG_LIBS ffmpeg::avcodec ffmpeg::avutil ffmpeg::swscale)
    else()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(LIBAV REQUIRED IMPORTED_TARGET
            libavcodec libavutil libswscale libavformat)
        set(XQC_FFMPEG_LIBS PkgConfig::LIBAV)
    endif()
endif()

set(TEST_SERVER_SOURCES
    test_server.cpp
    xquic_server.cpp
)

set(TEST_CLIENT_SOURCES
    test_client.cpp
    xquic_client.cpp
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(GETOPT_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/getopt.c
        CACHE STRING "xquic windows getopt source")

    set(TEST_SERVER_SOURCES
        ${TEST_SERVER_SOURCES}
        ${GETOPT_SOURCES}
    )

    set(TEST_CLIENT_SOURCES
        ${TEST_CLIENT_SOURCES}
        ${GETOPT_SOURCES}
    )
endif()


### test client/server ###
add_executable(test_server ${TEST_SERVER_SOURCES})
add_executable(test_client ${TEST_CLIENT_SOURCES})

# link libraries
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    set(APP_DEPEND_LIBS
        xquic-static
        ${SSL_LIB_PATH}
        ${LIBEVENT_LIBRARY}
        -lm
        CACHE STRING "xquic app depend libs")
else()
    set(APP_DEPEND_LIBS
        xquic-static
        ${SSL_LIB_PATH}
        ${LIBEVENT_LIBRARY}
        m
        dl
        stdc++
        pthread
        CACHE STRING "xquic app depend libs")
endif()

target_link_libraries(test_server ${APP_DEPEND_LIBS})
target_link_libraries(test_client ${APP_DEPEND_LIBS})

# Video streaming client
set(VIDEO_CLIENT_SOURCES
    xqc_video_client.cpp
)
add_executable(video_client ${VIDEO_CLIENT_SOURCES})
target_sources(video_client PRIVATE ${LOWLATENCY_H264_DECODE_SOURCES})
target_link_libraries(video_client PRIVATE ${APP_DEPEND_LIBS})
if(XQC_ENABLE_LOWLATENCY_FFMPEG)
    target_compile_definitions(video_client PRIVATE XQC_HAVE_FFMPEG=1)
    target_link_libraries(video_client PRIVATE ${XQC_FFMPEG_LIBS})
endif()

# Video streaming benchmark client
set(VIDEO_BENCH_SOURCES
    xqc_video_bench.cpp
)
add_executable(video_bench ${VIDEO_BENCH_SOURCES})
target_link_libraries(video_bench ${APP_DEPEND_LIBS})

if(XQC_ENABLE_LOWLATENCY_PHASES AND CMAKE_SYSTEM_NAME MATCHES "Windows")
    add_executable(xqc_gpu_windows_selftest
        lowlatency/xqc_gpu_windows_selftest.cpp
    )
    target_compile_features(xqc_gpu_windows_selftest PRIVATE cxx_std_17)
    target_link_libraries(xqc_gpu_windows_selftest PRIVATE opengl32 user32 gdi32)

    add_executable(xqc_nv12_gl_pbo_viewer
        lowlatency/xqc_nv12_gl_pbo_viewer.cpp
    )
    target_compile_features(xqc_nv12_gl_pbo_viewer PRIVATE cxx_std_17)
    target_link_libraries(xqc_nv12_gl_pbo_viewer PRIVATE opengl32 user32 gdi32)
endif()

if(XQC_ENABLE_SEASTAR_EXAMPLE)
    # When XQC_ENABLE_SEASTAR is ON, Seastar is built from submodule
    # (third_party/seastar) and provides the Seastar::seastar target.
    # Fallback to pkg-config for system-installed Seastar.
    if(TARGET Seastar::seastar)
        message(STATUS "Using Seastar from submodule (Seastar::seastar target)")
        set(SEASTAR_LINK_TARGET Seastar::seastar)
    else()
        message(STATUS "Seastar::seastar target not found, falling back to pkg-config")
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(SEASTAR REQUIRED IMPORTED_TARGET seastar)
        set(SEASTAR_LINK_TARGET PkgConfig::SEASTAR)
    endif()

    add_executable(xquic_server_seastar
        xquic_server_seastar.cpp
    )
    target_sources(xquic_server_seastar PRIVATE ${LOWLATENCY_H264_DECODE_SOURCES})

    target_compile_features(xquic_server_seastar PRIVATE cxx_std_20)

    if(CMAKE_SYSTEM_NAME MATCHES "Windows")
        # Seastar::seastar should propagate Winsock / BCrypt etc.; do not link
        # POSIX-only libs (m, dl, pthread) on Windows.
        target_link_libraries(xquic_server_seastar
            PRIVATE
            xquic-static
            ${SEASTAR_LINK_TARGET}
            ${SSL_LIB_PATH}
        )
    else()
        target_link_libraries(xquic_server_seastar
            PRIVATE
            xquic-static
            ${SEASTAR_LINK_TARGET}
            ${SSL_LIB_PATH}
            m
            dl
            pthread
        )
    endif()
    if(XQC_ENABLE_LOWLATENCY_FFMPEG)
        target_compile_definitions(xquic_server_seastar PRIVATE XQC_HAVE_FFMPEG=1)
        target_link_libraries(xquic_server_seastar PRIVATE ${XQC_FFMPEG_LIBS})
    endif()

    # POSIX + eBPF reuseport variant (Linux-only; not built on Windows)
    if(NOT CMAKE_SYSTEM_NAME MATCHES "Windows")
        add_executable(xquic_server_seastar_ebpf
            xquic_server_seastar_ebpf.cpp
        )

        target_compile_features(xquic_server_seastar_ebpf PRIVATE cxx_std_20)

        target_link_libraries(xquic_server_seastar_ebpf
            PRIVATE
            xquic-static
            ${SEASTAR_LINK_TARGET}
            ${SSL_LIB_PATH}
            m
            dl
            pthread
        )
    endif()
endif()

if(XQC_ENABLE_LOWLATENCY_FFMPEG AND NOT CMAKE_SYSTEM_NAME MATCHES "Windows")
    find_package(OpenGL REQUIRED)
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(GLFW3 glfw3)
    endif()
    set(LOWLATENCY_H264_HW_SOURCES "")
    if(XQC_ENABLE_HW_DECODE)
        pkg_check_modules(EGL REQUIRED IMPORTED_TARGET egl)
        pkg_check_modules(LIBVA REQUIRED IMPORTED_TARGET libva libva-drm)
        pkg_check_modules(DRM REQUIRED IMPORTED_TARGET libdrm)
        set(LOWLATENCY_H264_HW_SOURCES
            lowlatency/xqc_h264_hw_linux.cpp
            lowlatency/xqc_gl_egl_dma.cpp)
    endif()
    set(VIDEO_RECEIVER_SOURCES
        xqc_video_receiver.cpp
        ${LOWLATENCY_H264_DECODE_SOURCES}
        ${LOWLATENCY_H264_HW_SOURCES}
    )
    if(GLFW3_FOUND)
        list(APPEND VIDEO_RECEIVER_SOURCES lowlatency/xqc_nv12_gl_linux.cpp)
    endif()
    add_executable(xqc_video_receiver ${VIDEO_RECEIVER_SOURCES})
    target_compile_features(xqc_video_receiver PRIVATE cxx_std_17)
    target_compile_definitions(xqc_video_receiver PRIVATE XQC_HAVE_FFMPEG=1)
    target_link_libraries(xqc_video_receiver PRIVATE ${APP_DEPEND_LIBS} ${XQC_FFMPEG_LIBS} OpenGL::GL)
    if(XQC_ENABLE_HW_DECODE)
        target_compile_definitions(xqc_video_receiver PRIVATE XQC_HAVE_HW_DECODE=1)
        target_link_libraries(xqc_video_receiver PRIVATE PkgConfig::EGL PkgConfig::LIBVA PkgConfig::DRM)
    endif()
    if(GLFW3_FOUND)
        target_compile_definitions(xqc_video_receiver PRIVATE XQC_HAVE_GLFW=1)
        target_include_directories(xqc_video_receiver PRIVATE ${GLFW3_INCLUDE_DIRS})
        target_link_libraries(xqc_video_receiver PRIVATE ${GLFW3_LIBRARIES})
    endif()

    add_executable(xqc_h264_decode_smoke lowlatency/xqc_h264_decode_smoke.cpp ${LOWLATENCY_H264_DECODE_SOURCES})
    target_compile_features(xqc_h264_decode_smoke PRIVATE cxx_std_17)
    target_compile_definitions(xqc_h264_decode_smoke PRIVATE XQC_HAVE_FFMPEG=1)
    target_link_libraries(xqc_h264_decode_smoke PRIVATE ${XQC_FFMPEG_LIBS})
endif()


# build run_tests
if(HAVE_CUNIT)

    set (UNIT_TEST_DIR unittest)

    set(test_SOURCES
        ${UNIT_TEST_DIR}/main.c
        ${UNIT_TEST_DIR}/xqc_random_test.c
        ${UNIT_TEST_DIR}/xqc_pq_test.c
        ${UNIT_TEST_DIR}/xqc_common_test.c
        ${UNIT_TEST_DIR}/xqc_conn_test.c
        ${UNIT_TEST_DIR}/xqc_engine_test.c
        ${UNIT_TEST_DIR}/xqc_common_test.c
        ${UNIT_TEST_DIR}/xqc_vint_test.c
        ${UNIT_TEST_DIR}/xqc_packet_test.c
        ${UNIT_TEST_DIR}/xqc_recv_record_test.c
        ${UNIT_TEST_DIR}/xqc_reno_test.c
        ${UNIT_TEST_DIR}/xqc_cubic_test.c
        ${UNIT_TEST_DIR}/xqc_stream_frame_test.c
        ${UNIT_TEST_DIR}/xqc_process_frame_test.c
        ${UNIT_TEST_DIR}/xqc_tp_test.c
        ${UNIT_TEST_DIR}/xqc_tls_test.c
        ${UNIT_TEST_DIR}/xqc_crypto_test.c
        ${UNIT_TEST_DIR}/xqc_h3_test.c
        ${UNIT_TEST_DIR}/xqc_stable_test.c
        ${UNIT_TEST_DIR}/xqc_dtable_test.c
        ${UNIT_TEST_DIR}/utils/xqc_2d_hash_table_test.c
        ${UNIT_TEST_DIR}/utils/xqc_ring_array_test.c
        ${UNIT_TEST_DIR}/utils/xqc_ring_mem_test.c
        ${UNIT_TEST_DIR}/utils/xqc_huffman_test.c
        ${UNIT_TEST_DIR}/xqc_encoder_test.c
        ${UNIT_TEST_DIR}/xqc_qpack_test.c
        ${UNIT_TEST_DIR}/xqc_prefixed_str_test.c
        ${UNIT_TEST_DIR}/xqc_cid_test.c
        ${UNIT_TEST_DIR}/xqc_id_hash_test.c
        ${UNIT_TEST_DIR}/xqc_retry_test.c
        ${UNIT_TEST_DIR}/xqc_datagram_test.c
        ${UNIT_TEST_DIR}/xqc_h3_ext_test.c
        ${UNIT_TEST_DIR}/xqc_ack_with_timestamp_test.c
    )

    if(XQC_ENABLE_FEC)
        set(
            test_SOURCES
            ${test_SOURCES}
            ${UNIT_TEST_DIR}/xqc_galois_test.c
            ${UNIT_TEST_DIR}/xqc_fec_scheme_test.c
            ${UNIT_TEST_DIR}/xqc_fec_test.c
        )
    endif()

    add_executable(run_tests
        ${test_SOURCES}
    )

    target_include_directories(run_tests
        PRIVATE
        ${INCLUDE_DIRECTORIES}
        ${CUNIT_INCLUDE_DIRS})

    if(CMAKE_SYSTEM_NAME MATCHES "Windows")
        set(CUTEST_DEPEND_LIBS
            xquic-static
            ${CUNIT_LIBRARIES}
            ${SSL_LIB_PATH}
            m
            CACHE STRING "xquic unit test depend libs")
    else()
        set(CUTEST_DEPEND_LIBS
            xquic-static
            ${CUNIT_LIBRARIES}
            ${SSL_LIB_PATH}
            m
            stdc++
            dl
            pthread
            CACHE STRING "xquic unit test depend libs")
    endif()
    
    target_link_libraries(run_tests
        ${CUTEST_DEPEND_LIBS}
    )

    add_test(run_tests run_tests)
    add_dependencies(check run_tests)
endif()
