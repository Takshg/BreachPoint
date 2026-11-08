"""BreachPoint silent demo video (Manim Community Edition, no LaTeX).

Render at 1080p30 (the isolated uv environment leaves the project's deps alone):

    uv run --isolated --no-project --python 3.12 --with manim \
        manim -r 1920,1080 --fps 30 --disable_caching --media_dir <dir> \
        demo/breachpoint_demo.py BreachPointDemo
"""

import math

import manimpango
from manim import (
    BOLD,
    DEGREES,
    DOWN,
    LEFT,
    ORIGIN,
    RIGHT,
    TAU,
    UP,
    Arc,
    Circle,
    FadeIn,
    FadeOut,
    GrowFromEdge,
    LaggedStart,
    Line,
    MarkupText,
    Rectangle,
    RoundedRectangle,
    Scene,
    Text,
    VGroup,
    config,
)

BG = "#04070d"
GLOW = "#6fe9ff"
LIGHT = "#d9f7ff"
BRIGHT = "#effcff"
DIM = "#7fa9b8"
ACCENT = "#ffb020"

# Fixed per method.
BREACHPOINT = "#3987e5"
EXPLOIT_EPSS = "#d95926"
EPSS = "#199e70"
CVSS = "#c98500"

config.background_color = BG

FONT = next(
    (f for f in ("Helvetica Neue", "Helvetica", "Arial") if f in manimpango.list_fonts()),
    "",
)


def T(text, size, color=LIGHT, **kwargs):
    return Text(text, font=FONT, font_size=size, color=color, **kwargs)


def lines(rows, size, color=LIGHT, aligned=ORIGIN, buff=0.2, **kwargs):
    return VGroup(*[T(row, size, color, **kwargs) for row in rows]).arrange(
        DOWN, aligned_edge=aligned, buff=buff
    )


def spaced_title(size, spacing):
    return MarkupText(
        f'<span letter_spacing="{spacing}">BreachPoint</span>',
        font=FONT,
        font_size=size,
        color=BRIGHT,
    )


def spin(speed, center):
    def updater(mob, dt):
        mob.rotate(speed * dt, about_point=center)

    return updater


def emblem(radius, center):
    """Concentric rings and tick marks that rotate around a pulsing core."""
    center = center.copy()
    soft = Circle(radius=radius, stroke_color=GLOW, stroke_width=14, stroke_opacity=0.12)
    outer = Circle(radius=radius, stroke_color=GLOW, stroke_width=3)

    ticks = VGroup()
    for i in range(48):
        angle = i * TAU / 48
        long_tick = i % 4 == 0
        inner = radius * 1.04
        outer_r = radius * (1.14 if long_tick else 1.09)
        direction = RIGHT * math.cos(angle) + UP * math.sin(angle)
        ticks.add(
            Line(
                direction * inner,
                direction * outer_r,
                stroke_color=GLOW,
                stroke_width=3 if long_tick else 1.5,
            )
        )

    mid = VGroup(
        *[
            Arc(
                radius=radius * 0.76,
                start_angle=i * TAU / 3,
                angle=95 * DEGREES,
                stroke_color=GLOW,
                stroke_width=5,
            )
            for i in range(3)
        ]
    )
    dashes = VGroup(
        *[
            Arc(
                radius=radius * 0.56,
                start_angle=i * TAU / 24,
                angle=8 * DEGREES,
                stroke_color=LIGHT,
                stroke_width=3,
            )
            for i in range(24)
        ]
    )
    inner_ring = Circle(radius=radius * 0.38, stroke_color=GLOW, stroke_width=1.5, stroke_opacity=0.7)

    # Stacked translucent discs read as a soft radial glow.
    core = VGroup(
        *[
            Circle(radius=radius * r, fill_color=GLOW, fill_opacity=0.07, stroke_width=0)
            for r in (0.34, 0.28, 0.23, 0.18, 0.14, 0.11)
        ],
        Circle(radius=radius * 0.075, fill_color=BRIGHT, fill_opacity=1, stroke_width=0),
    )

    group = VGroup(soft, outer, ticks, mid, dashes, inner_ring, core)
    group.shift(center)

    ticks.add_updater(spin(0.35, center))
    mid.add_updater(spin(-0.8, center))
    dashes.add_updater(spin(1.2, center))

    base_width = core.width
    clock = {"t": 0.0}

    def pulse(mob, dt):
        clock["t"] += dt
        target = base_width * (1 + 0.16 * math.sin(TAU * clock["t"] / 1.3))
        mob.scale(target / mob.width, about_point=center)

    core.add_updater(pulse)
    return group


class BreachPointDemo(Scene):
    def curtain(self):
        return Rectangle(
            width=config.frame_width + 2,
            height=config.frame_height + 2,
            fill_color=BG,
            fill_opacity=1,
            stroke_width=0,
        )

    def fade_clear(self, run_time=0.35):
        cover = self.curtain()
        self.play(FadeIn(cover), run_time=run_time)
        self.clear()

    def mark(self, name):
        print(f"SECTION {name} hold-end {self.renderer.time:.2f}")

    def construct(self):
        self.s1_title()
        self.s2_problem()
        self.s3_finding()
        self.s4_results()
        self.s5_app()
        self.s6_close()

    def s1_title(self):
        mark = emblem(1.7, UP * 1.0)
        title = spaced_title(64, 2400).move_to(DOWN * 1.75)
        subtitle = T("What to fix before the breach", 30, DIM).move_to(DOWN * 2.8)
        cover = self.curtain()
        self.add(mark, cover)
        self.play(FadeOut(cover), run_time=0.7)
        self.play(FadeIn(title, shift=UP * 0.2), run_time=0.6)
        self.play(FadeIn(subtitle), run_time=0.5)
        self.wait(1.8)
        self.mark("1")
        self.fade_clear(0.4)

    def s2_problem(self):
        first = T("72,670 new vulnerabilities.", 56, BRIGHT, weight=BOLD)
        second = T("Which ones will attackers actually hit?", 38, GLOW)
        third = lines(
            ["Severity says how bad an attack could be,", "not whether anyone will attack."],
            30,
            LIGHT,
        )
        VGroup(first, second, third).arrange(DOWN, buff=0.75).move_to(ORIGIN)
        self.play(FadeIn(first, shift=UP * 0.2), run_time=0.5)
        self.wait(0.8)
        self.play(FadeIn(second, shift=UP * 0.2), run_time=0.5)
        self.wait(0.9)
        self.play(FadeIn(third, shift=UP * 0.2), run_time=0.5)
        self.wait(2.0)
        self.mark("2")
        self.fade_clear()

    def s3_finding(self):
        heading = T("Who shipped it says more than how severe it is.", 38, BRIGHT, weight=BOLD)
        heading.move_to(UP * 3.0)
        sub = T("Vulnerabilities with CVSS 9 or higher: later exploited per 10,000", 26, DIM)
        sub.next_to(heading, DOWN, buff=0.35)

        x0 = -2.1
        full = 7.6
        rows = [
            ("Vendor with KEV history", 193, GLOW, 0.7),
            ("No KEV history", 10, DIM, -0.6),
        ]
        labels, bars, values = [], [], []
        for text, value, color, y in rows:
            width = full * value / 193
            bar = Rectangle(width=width, height=0.72, fill_color=color, fill_opacity=1, stroke_width=0)
            bar.move_to(RIGHT * (x0 + width / 2) + UP * y)
            label = T(text, 28)
            label.move_to(UP * y).align_to(LEFT * 6.55, LEFT)
            number = T(str(value), 40, BRIGHT, weight=BOLD)
            number.next_to(bar, RIGHT, buff=0.2)
            labels.append(label)
            bars.append(bar)
            values.append(number)

        caption = T("About 19× difference", 44, ACCENT, weight=BOLD).move_to(DOWN * 2.5)

        self.play(FadeIn(heading, shift=UP * 0.2), run_time=0.5)
        self.play(FadeIn(sub), FadeIn(VGroup(*labels)), run_time=0.5)
        self.play(GrowFromEdge(bars[0], LEFT), run_time=0.9)
        self.play(FadeIn(values[0]), run_time=0.25)
        self.play(GrowFromEdge(bars[1], LEFT), run_time=0.4)
        self.play(FadeIn(values[1]), run_time=0.25)
        self.wait(0.4)
        self.play(FadeIn(caption, shift=UP * 0.2), run_time=0.5)
        self.wait(2.8)
        self.mark("3")
        self.fade_clear()

    def s4_results(self):
        heading = T("Tested on years it never trained on", 36, BRIGHT, weight=BOLD).move_to(UP * 3.35)
        sub = lines(
            ["Later-exploited vulnerabilities found in a top list", "the same share as the scoreboard's top 500"],
            24,
            DIM,
            buff=0.14,
        )
        sub.next_to(heading, DOWN, buff=0.28)

        methods = [
            ("CVSS 3 first", CVSS),
            ("EPSS first", EPSS),
            ("Exploit code, then EPSS", EXPLOIT_EPSS),
            ("BreachPoint", BREACHPOINT),
        ]
        ys = [0.75, 0.1, -0.55, -1.2]
        columns = [
            ("2025 test (45 to find)", -2.7, [4, 8, 14, 16]),
            ("2024 test (24 to find)", 2.2, [0, 1, 4, 7]),
        ]
        unit = 3.6 / 16  # Same scale in both columns.

        labels = VGroup()
        for (name, _), y in zip(methods, ys):
            weight = BOLD if name == "BreachPoint" else "NORMAL"
            label = T(name, 24, BRIGHT, weight=weight)
            label.move_to(UP * y).align_to(LEFT * 6.6, LEFT)
            labels.add(label)

        headers, bars, values = VGroup(), [], VGroup()
        for title, x0, data in columns:
            header = T(title, 26, GLOW)
            header.move_to(UP * 1.5).align_to(RIGHT * x0, LEFT)
            headers.add(header)
            for (name, color), y, value in zip(methods, ys, data):
                width = max(value * unit, 0.05)
                bar = Rectangle(width=width, height=0.42, fill_color=color, fill_opacity=1, stroke_width=0)
                bar.move_to(RIGHT * (x0 + width / 2) + UP * y)
                bars.append(bar)
                weight = BOLD if name == "BreachPoint" else "NORMAL"
                number = T(str(value), 26, BRIGHT, weight=weight)
                number.next_to(bar, RIGHT, buff=0.14)
                values.add(number)

        caption = lines(
            ["Ahead in both years, but with this few real attacks", "the margin isn't statistically clear."],
            28,
            ACCENT,
            buff=0.14,
        )
        caption.move_to(DOWN * 2.85)

        self.play(FadeIn(heading, shift=UP * 0.2), FadeIn(sub), run_time=0.6)
        self.wait(0.5)
        self.play(FadeIn(labels), FadeIn(headers), run_time=0.45)
        self.play(
            LaggedStart(*[GrowFromEdge(b, LEFT) for b in bars], lag_ratio=0.1),
            run_time=1.3,
        )
        self.play(FadeIn(values), run_time=0.3)
        self.wait(0.5)
        self.play(FadeIn(caption, shift=UP * 0.15), run_time=0.5)
        self.wait(3.8)
        self.mark("4")
        self.fade_clear()

    def s5_app(self):
        def card(name, rows, height):
            box = RoundedRectangle(
                corner_radius=0.18,
                width=13.0,
                height=height,
                stroke_color=GLOW,
                stroke_width=2,
                fill_color=GLOW,
                fill_opacity=0.05,
            )
            title = T(name, 32, GLOW, weight=BOLD)
            title.move_to(box.get_center()).align_to(box.get_left() + RIGHT * 0.4, LEFT)
            body = VGroup(*rows).arrange(DOWN, aligned_edge=LEFT, buff=0.2)
            body.move_to(box.get_center()).align_to(RIGHT * (-2.35), LEFT)
            return VGroup(box, title, body)

        fix = card(
            "Fix queue",
            [T("390 of the top 500 sit outside CVSS's top 5,000", 26, t2c={"390": ACCENT})],
            1.3,
        )
        env = card(
            "My environment",
            [
                T("Adds where it runs: 5 of the next 20 fixes change", 26, t2c={"5 of the next 20": ACCENT}),
                T("(made-up sample inventory)", 26, DIM),
            ],
            1.75,
        )
        ask = card(
            "Ask the data",
            [
                T("IBM Granite writes the SQL, read-only on Tiger Data.", 26),
                T("63 of 70 test questions right.", 26, t2c={"63 of 70": ACCENT}),
                T("Cached answers in milliseconds", 26),
            ],
            2.35,
        )
        VGroup(fix, env, ask).arrange(DOWN, buff=0.28).move_to(ORIGIN)

        self.play(FadeIn(fix, shift=UP * 0.2), run_time=0.4)
        self.wait(1.5)
        self.play(FadeIn(env, shift=UP * 0.2), run_time=0.4)
        self.wait(1.9)
        self.play(FadeIn(ask, shift=UP * 0.2), run_time=0.4)
        self.wait(3.3)
        self.mark("5")
        self.fade_clear()

    def s6_close(self):
        mark = emblem(1.15, UP * 1.1)
        title = spaced_title(52, 2000).move_to(DOWN * 1.0)
        tagline = T("What to fix first, and why", 30, DIM).move_to(DOWN * 1.95)
        cover = self.curtain()
        self.add(mark, cover, title, tagline)
        self.play(FadeOut(cover), run_time=0.5)
        self.wait(2.7)
        self.mark("6")
