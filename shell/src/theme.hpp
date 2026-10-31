// Vesper -- visual identity.
//
// One palette, one rhythm. Vesper is an evening star: deep indigo surfaces,
// violet structure, a single warm amber accent reserved for the actions that
// matter. Nothing else in the UI is allowed to be colourful, which is what keeps
// the amber reading as an instruction rather than decoration.
#pragma once

#include <d2d1.h>
#include <d2d1helper.h>

namespace vesper::ui {

struct Color {
    float r = 0.0f, g = 0.0f, b = 0.0f, a = 1.0f;

    D2D1_COLOR_F to_d2d() const { return D2D1::ColorF(r, g, b, a); }
    constexpr Color with_alpha(float alpha) const { return Color{r, g, b, alpha}; }

    static constexpr Color hex(unsigned value, float alpha = 1.0f) {
        return Color{static_cast<float>((value >> 16) & 0xff) / 255.0f,
                     static_cast<float>((value >> 8) & 0xff) / 255.0f,
                     static_cast<float>(value & 0xff) / 255.0f,
                     alpha};
    }
};

struct Palette {
    // Surfaces, darkest to lightest.
    Color base = Color::hex(0x0A0A0F);
    Color surface = Color::hex(0x111119);
    Color raised = Color::hex(0x181822);
    Color overlay = Color::hex(0x1F1F2B);
    Color hairline = Color::hex(0x272733);
    Color hairline_strong = Color::hex(0x33333F);

    // Text.
    Color text = Color::hex(0xE8E8F2);
    Color text_dim = Color::hex(0x9A9AB0);
    Color text_faint = Color::hex(0x5E5E72);

    // Identity.
    Color accent = Color::hex(0xFFB454);       // amber: primary action
    Color accent_press = Color::hex(0xE09A3C);
    Color violet = Color::hex(0x7C5CFF);       // structure, selection
    Color violet_dim = Color::hex(0x3A2F73);

    // Status.
    Color good = Color::hex(0x4ADE80);
    Color warn = Color::hex(0xFBBF24);
    Color bad = Color::hex(0xFF6B6B);

    // Console.
    Color editor = Color::hex(0x0D0D14);
    Color console = Color::hex(0x0B0B11);
    Color console_text = Color::hex(0xC6C6D8);
    Color console_error = Color::hex(0xFF8A8A);
    Color gutter = Color::hex(0x14141C);
};

struct Metrics {
    float title_bar = 38.0f;
    float sidebar = 236.0f;
    float status_bar = 30.0f;
    float pad = 14.0f;
    float pad_small = 8.0f;
    float radius = 10.0f;
    float radius_small = 6.0f;
    float control_height = 30.0f;
    float console_height = 168.0f;
    float scrollbar = 8.0f;
};

inline const Palette& palette() {
    static const Palette instance;
    return instance;
}

inline const Metrics& metrics() {
    static const Metrics instance;
    return instance;
}

}  // namespace vesper::ui
