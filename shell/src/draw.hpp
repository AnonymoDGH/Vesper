// Vesper shell -- Direct2D + DirectWrite drawing.
//
// A UI this small does not need a scene graph, so this is a thin immediate-mode
// wrapper: one render target, cached brushes, cached text formats, and the
// handful of primitives the layout actually uses. Software rendering is
// acceptable (and selected automatically when no GPU path exists), which keeps
// the shell working on RDP sessions and VMs.
#pragma once

#include <d2d1.h>
#include <d2d1helper.h>
#include <dwrite.h>

#include <string>
#include <vector>

#include "theme.hpp"

namespace vesper::ui {

// COM identity is data, so it can live in the source. MinGW's libdwrite does not
// export IID_IDWriteFactory at all, and taking both values from the headers keeps
// this file independent of which import libraries happen to be installed.
inline const GUID kD2D1FactoryIID = {0x06152247, 0x6f50, 0x465a, {0x92, 0x45, 0x11, 0x8b, 0xfd, 0x3b, 0x60, 0x07}};
inline const GUID kDWriteFactoryIID = {0xb859ee5a, 0xd838, 0x4b5b, {0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48}};

struct TextStyle {
    float size = 13.0f;
    bool bold = false;
    bool mono = false;
};

class Render {
public:
    ~Render() { destroy(); }

    bool create(HWND window) {
        if (factory_ == nullptr) {
            if (FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, kD2D1FactoryIID, nullptr,
                                         reinterpret_cast<void**>(&factory_)))) {
                return false;
            }
        }
        if (dwrite_ == nullptr) {
            if (FAILED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, kDWriteFactoryIID,
                                           reinterpret_cast<IUnknown**>(&dwrite_)))) {
                return false;
            }
        }
        window_ = window;
        return create_target();
    }

    void destroy() {
        release_target();
        if (dwrite_ != nullptr) {
            dwrite_->Release();
            dwrite_ = nullptr;
        }
        if (factory_ != nullptr) {
            factory_->Release();
            factory_ = nullptr;
        }
        window_ = nullptr;
    }

    bool resize(UINT width, UINT height) {
        if (target_ == nullptr) return create_target();
        if (width == 0 || height == 0) return true;
        return SUCCEEDED(target_->Resize(D2D1::SizeU(width, height)));
    }

    bool valid() const { return target_ != nullptr; }

    void begin() {
        if (target_ == nullptr) return;
        target_->BeginDraw();
        target_->SetTransform(D2D1::Matrix3x2F::Identity());
        target_->SetAntialiasMode(D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
        target_->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE);
    }

    void end() {
        if (target_ == nullptr) return;
        const HRESULT result = target_->EndDraw();
        if (result == D2DERR_RECREATE_TARGET) {
            release_target();
            create_target();
        }
    }

    // ------------------------------------------------------------- geometry --

    void rect(const D2D1_RECT_F& box, const Color& color) {
        if (target_ == nullptr) return;
        target_->FillRectangle(&box, brush(color));
    }

    void rounded(const D2D1_RECT_F& box, float radius, const Color& color) {
        if (target_ == nullptr) return;
        D2D1_ROUNDED_RECT shape{box, radius, radius};
        target_->FillRoundedRectangle(&shape, brush(color));
    }

    void rounded_stroke(const D2D1_RECT_F& box, float radius, const Color& color, float width = 1.0f) {
        if (target_ == nullptr) return;
        D2D1_ROUNDED_RECT shape{box, radius, radius};
        target_->DrawRoundedRectangle(&shape, brush(color), width);
    }

    void line(float x0, float y0, float x1, float y1, const Color& color, float width = 1.0f) {
        if (target_ == nullptr) return;
        target_->DrawLine(D2D1::Point2F(x0, y0), D2D1::Point2F(x1, y1), brush(color), width);
    }

    void circle(float center_x, float center_y, float radius, const Color& color) {
        if (target_ == nullptr) return;
        target_->FillEllipse(D2D1::Ellipse(D2D1::Point2F(center_x, center_y), radius, radius), brush(color));
    }

    void ring(float center_x, float center_y, float radius, const Color& color, float width = 1.0f) {
        if (target_ == nullptr) return;
        target_->DrawEllipse(D2D1::Ellipse(D2D1::Point2F(center_x, center_y), radius, radius), brush(color),
                             width);
    }

    // --------------------------------------------------------------- text --

    void text(const std::wstring& value, const D2D1_RECT_F& box, const Color& color,
              const TextStyle& style, DWRITE_TEXT_ALIGNMENT align = DWRITE_TEXT_ALIGNMENT_LEADING,
              DWRITE_PARAGRAPH_ALIGNMENT valign = DWRITE_PARAGRAPH_ALIGNMENT_CENTER, bool wrap = false) {
        if (target_ == nullptr || value.empty()) return;

        IDWriteTextFormat* format = text_format(style);
        if (format == nullptr) return;
        format->SetTextAlignment(align);
        format->SetParagraphAlignment(valign);
        format->SetWordWrapping(wrap ? DWRITE_WORD_WRAPPING_WRAP : DWRITE_WORD_WRAPPING_NO_WRAP);

        target_->DrawTextW(value.c_str(), static_cast<UINT32>(value.size()), format, &box, brush(color),
                           D2D1_DRAW_TEXT_OPTIONS_CLIP);
    }

    // Greedy wrap into a fixed width; returns the height used.
    float paragraph(const std::wstring& value, float x, float y, float width, const Color& color,
                    const TextStyle& style, float line_height = 0.0f,
                    DWRITE_TEXT_ALIGNMENT align = DWRITE_TEXT_ALIGNMENT_LEADING) {
        if (target_ == nullptr || value.empty()) return 0.0f;
        IDWriteTextFormat* format = text_format(style);
        if (format == nullptr) return 0.0f;
        format->SetTextAlignment(align);
        format->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        format->SetWordWrapping(DWRITE_WORD_WRAPPING_WRAP);
        if (line_height > 0.0f) {
            format->SetLineSpacing(DWRITE_LINE_SPACING_METHOD_UNIFORM, line_height, line_height * 0.8f);
        }

        IDWriteTextLayout* layout = nullptr;
        if (FAILED(dwrite_->CreateTextLayout(value.c_str(), static_cast<UINT32>(value.size()), format, width,
                                            4096.0f, &layout)) ||
            layout == nullptr) {
            return 0.0f;
        }

        const D2D1_RECT_F box = D2D1::RectF(x, y, x + width, y + 4096.0f);
        target_->DrawTextLayout(D2D1::Point2F(x, y), layout, brush(color), D2D1_DRAW_TEXT_OPTIONS_CLIP);

        DWRITE_TEXT_METRICS metrics{};
        layout->GetMetrics(&metrics);
        layout->Release();
        (void)box;
        return metrics.height;
    }

    float measure_width(const std::wstring& value, const TextStyle& style) {
        if (dwrite_ == nullptr || value.empty()) return 0.0f;
        IDWriteTextFormat* format = text_format(style);
        if (format == nullptr) return 0.0f;
        IDWriteTextLayout* layout = nullptr;
        if (FAILED(dwrite_->CreateTextLayout(value.c_str(), static_cast<UINT32>(value.size()), format, 4096.0f,
                                             256.0f, &layout)) ||
            layout == nullptr) {
            return 0.0f;
        }
        DWRITE_TEXT_METRICS metrics{};
        layout->GetMetrics(&metrics);
        layout->Release();
        return metrics.widthIncludingTrailingWhitespace;
    }

    // -------------------------------------------------------------- clips --

    void push_clip(const D2D1_RECT_F& box) {
        if (target_ == nullptr) return;
        target_->PushAxisAlignedClip(box, D2D1_ANTIALIAS_MODE_ALIASED);
        ++clip_depth_;
    }

    void pop_clip() {
        if (target_ == nullptr || clip_depth_ == 0) return;
        target_->PopAxisAlignedClip();
        --clip_depth_;
    }

    void reset_clips() {
        while (clip_depth_ > 0) pop_clip();
    }

    void push_offset(float dx, float dy) {
        if (target_ == nullptr) return;
        D2D1_MATRIX_3X2_F current = D2D1::Matrix3x2F::Identity();
        target_->GetTransform(&current);
        transforms_.push_back(current);
        target_->SetTransform(current * D2D1::Matrix3x2F::Translation(dx, dy));
    }

    void pop_offset() {
        if (target_ == nullptr || transforms_.empty()) return;
        target_->SetTransform(transforms_.back());
        transforms_.pop_back();
    }

private:
    struct BrushEntry {
        D2D1_COLOR_F color;
        ID2D1SolidColorBrush* brush;
    };

    struct FormatEntry {
        int size_key;
        bool bold;
        bool mono;
        IDWriteTextFormat* format;
    };

    bool create_target() {
        if (factory_ == nullptr || window_ == nullptr) return false;

        RECT client{};
        GetClientRect(window_, &client);
        const D2D1_SIZE_U size =
            D2D1::SizeU(static_cast<UINT32>(client.right - client.left == 0 ? 1 : client.right - client.left),
                        static_cast<UINT32>(client.bottom - client.top == 0 ? 1 : client.bottom - client.top));

        const D2D1_RENDER_TARGET_PROPERTIES properties = D2D1::RenderTargetProperties(
            D2D1_RENDER_TARGET_TYPE_DEFAULT,
            D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_IGNORE), 0.0f, 0.0f,
            D2D1_RENDER_TARGET_USAGE_NONE, D2D1_FEATURE_LEVEL_DEFAULT);

        if (FAILED(factory_->CreateHwndRenderTarget(properties, D2D1::HwndRenderTargetProperties(window_, size),
                                                    &target_))) {
            target_ = nullptr;
            return false;
        }
        target_->SetDpi(96.0f, 96.0f);
        return true;
    }

    void release_target() {
        for (BrushEntry& entry : brushes_) {
            if (entry.brush != nullptr) entry.brush->Release();
        }
        brushes_.clear();
        if (target_ != nullptr) {
            target_->Release();
            target_ = nullptr;
        }
        clip_depth_ = 0;
        transforms_.clear();
    }

    ID2D1SolidColorBrush* brush(const Color& color) {
        const D2D1_COLOR_F value = color.to_d2d();
        for (BrushEntry& entry : brushes_) {
            if (entry.color.r == value.r && entry.color.g == value.g && entry.color.b == value.b &&
                entry.color.a == value.a) {
                return entry.brush;
            }
        }
        ID2D1SolidColorBrush* created = nullptr;
        if (FAILED(target_->CreateSolidColorBrush(value, &created))) return nullptr;
        brushes_.push_back(BrushEntry{value, created});
        return created;
    }

    IDWriteTextFormat* text_format(const TextStyle& style) {
        const int size_key = static_cast<int>(style.size * 4.0f + 0.5f);
        for (FormatEntry& entry : formats_) {
            if (entry.size_key == size_key && entry.bold == style.bold && entry.mono == style.mono) {
                return entry.format;
            }
        }

        const wchar_t* families_mono[] = {L"Cascadia Mono", L"Consolas", L"Courier New"};
        const wchar_t* families_ui[] = {L"Segoe UI Variable Text", L"Segoe UI", L"Tahoma"};

        IDWriteTextFormat* format = nullptr;
        if (style.mono) {
            for (const wchar_t* family : families_mono) {
                if (SUCCEEDED(dwrite_->CreateTextFormat(family, nullptr,
                                                        style.bold ? DWRITE_FONT_WEIGHT_SEMI_BOLD
                                                                   : DWRITE_FONT_WEIGHT_NORMAL,
                                                        DWRITE_FONT_STYLE_NORMAL,
                                                        DWRITE_FONT_STRETCH_NORMAL, style.size, L"en-us",
                                                        &format)) &&
                    format != nullptr) {
                    break;
                }
                format = nullptr;
            }
        } else {
            for (const wchar_t* family : families_ui) {
                if (SUCCEEDED(dwrite_->CreateTextFormat(family, nullptr,
                                                        style.bold ? DWRITE_FONT_WEIGHT_SEMI_BOLD
                                                                   : DWRITE_FONT_WEIGHT_NORMAL,
                                                        DWRITE_FONT_STYLE_NORMAL,
                                                        DWRITE_FONT_STRETCH_NORMAL, style.size, L"en-us",
                                                        &format)) &&
                    format != nullptr) {
                    break;
                }
                format = nullptr;
            }
        }

        if (format == nullptr) return nullptr;
        formats_.push_back(FormatEntry{size_key, style.bold, style.mono, format});
        return format;
    }

    ID2D1Factory* factory_ = nullptr;
    IDWriteFactory* dwrite_ = nullptr;
    ID2D1HwndRenderTarget* target_ = nullptr;
    HWND window_ = nullptr;
    std::vector<BrushEntry> brushes_;
    std::vector<FormatEntry> formats_;
    std::vector<D2D1_MATRIX_3X2_F> transforms_;
    int clip_depth_ = 0;
};

}  // namespace vesper::ui
