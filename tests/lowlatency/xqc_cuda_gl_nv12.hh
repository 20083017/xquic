/**
 * @file xqc_cuda_gl_nv12.hh
 * @brief CUDA NVDEC NV12 → OpenGL R8/RG8 textures via cudaGraphicsGLRegisterImage (zero CPU copy).
 *
 * Display thread only: requires GLX/GL context current (see `xqc_nv12_gl_linux.cpp`).
 * Decode thread passes `XqcNv12Backing::CudaGl` frames holding a ref'd AVFrame (AV_PIX_FMT_CUDA).
 */

#pragma once

#include "xqc_nv12_frame.hh"

/** Select CUDA device and register internal Y/UV GL textures (lazy sizing on first upload). */
bool xqc_cuda_gl_nv12_init();

void xqc_cuda_gl_nv12_shutdown();

/** D2D copy from NVDEC CUDA planes into registered GL textures. */
bool xqc_cuda_gl_nv12_upload_nv12(const XqcNv12Frame& frame);

bool xqc_cuda_gl_nv12_available();

/** True when interop UV texture is GL_LUMINANCE_ALPHA (sample .ra, not .rg). */
bool xqc_cuda_gl_nv12_uses_luminance_alpha_uv();

/** hwdownload + CPU NV12 pack when cudaGraphicsGLRegisterImage is unavailable. */
bool xqc_cuda_gl_nv12_fallback_to_cpu(XqcNv12Frame& frame);

unsigned int xqc_cuda_gl_nv12_tex_y();
unsigned int xqc_cuda_gl_nv12_tex_uv();
