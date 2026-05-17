/**
 * @file xqc_gl_egl_dma.hh
 * @brief Import VAAPI DRM PRIME NV12 dma-buf as EGLImages → GL textures (zero-copy).
 *
 * Requires GLFW context created with `GLFW_EGL_CONTEXT_API` (see `xqc_nv12_gl_linux.cpp`).
 */

#pragma once

#include "xqc_nv12_frame.hh"

struct GLFWwindow;

/** Probe EGL_EXT_image_dma_buf_import on the GLFW window's EGL display. */
bool xqc_gl_egl_dma_init(GLFWwindow* win);

void xqc_gl_egl_dma_shutdown();

/**
 * Bind @p frame dma-buf planes to internal Y/UV GL textures (cached EGLImages per fd generation).
 * @return true if textures are ready to draw with the existing NV12 shader.
 */
bool xqc_gl_egl_dma_upload_nv12(const XqcNv12Frame& frame);

/** True after successful init and at least one dma upload. */
bool xqc_gl_egl_dma_available();

/** GL texture names after successful upload (valid until next upload). */
unsigned int xqc_gl_egl_tex_y();
unsigned int xqc_gl_egl_tex_uv();
