"""Opening screen: a glowing reactor emblem inside a rotating HUD, drawn entirely in SVG + CSS.

No external fonts, images or scripts, so it works offline. Motion stops for viewers who ask for reduced motion.
"""
from __future__ import annotations

import math

CX, CY = 300, 300


def _polar(r: float, deg: float) -> tuple[float, float]:
    a = math.radians(deg - 90)
    return CX + r * math.cos(a), CY + r * math.sin(a)


def _ticks(r: float, length: float, n: int, every: int, width: float = 1.2) -> str:
    """Tick ring; every `every`-th tick is longer."""
    out = []
    for i in range(n):
        d = i * 360 / n
        ln = length * (2.2 if i % every == 0 else 1)
        x1, y1 = _polar(r, d)
        x2, y2 = _polar(r - ln, d)
        out.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke-width="{width}"/>')
    return "".join(out)


def _arc(r: float, start: float, end: float) -> str:
    x1, y1 = _polar(r, start)
    x2, y2 = _polar(r, end)
    large = 1 if (end - start) % 360 > 180 else 0
    return f"M{x1:.1f} {y1:.1f}A{r} {r} 0 {large} 1 {x2:.1f} {y2:.1f}"


def _arcs(r: float, spans: list[tuple[float, float]], width: float) -> str:
    return "".join(f'<path d="{_arc(r, a, b)}" stroke-width="{width}"/>' for a, b in spans)


def _coils(n: int = 12, r_in: float = 78, r_out: float = 122, gap: float = 7) -> str:
    """Wedge-shaped coil blocks around the core."""
    out = []
    step = 360 / n
    for i in range(n):
        a, b = i * step + gap / 2, (i + 1) * step - gap / 2
        p = [_polar(r_out, a), _polar(r_out, b), _polar(r_in, b - 3), _polar(r_in, a + 3)]
        d = (f"M{p[0][0]:.1f} {p[0][1]:.1f}A{r_out} {r_out} 0 0 1 {p[1][0]:.1f} {p[1][1]:.1f}"
             f"L{p[2][0]:.1f} {p[2][1]:.1f}A{r_in} {r_in} 0 0 0 {p[3][0]:.1f} {p[3][1]:.1f}Z")
        out.append(f'<path d="{d}" style="animation-delay:{i * 0.14:.2f}s"/>')
    return "".join(out)


def splash_html(ring_text: str) -> str:
    bx, by = _polar(236, 52)  # the "breach point": one marked node on the rotating ring
    return f"""<!doctype html><meta charset="utf-8">
<style>
  :root {{ --glow:#6fe9ff; --ink:#d9f7ff; --dim:#7fa9b8; --bg:#04070d; --breach:#ffb020; }}
  * {{ box-sizing:border-box; }}
  html,body {{ margin:0; height:100%; background:var(--bg); overflow:hidden; }}
  body {{ font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace; color:var(--ink); }}
  .stage {{ position:relative; height:100%; display:flex; flex-direction:column; align-items:center; justify-content:center;
    background:radial-gradient(circle at 50% 42%, rgba(60,190,230,.20), transparent 46%); }}
  .stage::before {{ content:""; position:absolute; inset:0; pointer-events:none;
    background:linear-gradient(rgba(111,233,255,.06) 1px, transparent 1px) 0 0/100% 34px,
               linear-gradient(90deg, rgba(111,233,255,.06) 1px, transparent 1px) 0 0/34px 100%;
    -webkit-mask-image:radial-gradient(ellipse at 50% 45%, #000 40%, transparent 74%);
            mask-image:radial-gradient(ellipse at 50% 45%, #000 40%, transparent 74%); }}
  .stage > * {{ position:relative; }}
  svg.hud {{ width:min(70vh,520px); height:auto; flex:none; overflow:visible; animation:boot 1.3s cubic-bezier(.2,.8,.2,1) both; }}
  .spin {{ transform-origin:{CX}px {CY}px; animation:spin var(--t) linear infinite; }}
  .rev {{ animation-direction:reverse; }}
  .line {{ fill:none; stroke:var(--glow); }}
  .sweep {{ transform-origin:{CX}px {CY}px; animation:spin 5s linear infinite; }}
  .coils path {{ fill:rgba(111,233,255,.34); stroke:var(--glow); stroke-width:1.2; animation:coil 1.7s ease-in-out infinite; }}
  .core {{ animation:pulse 2.6s ease-in-out infinite; transform-origin:{CX}px {CY}px; }}
  .ringtext {{ fill:var(--glow); font-size:12px; letter-spacing:.34em; }}
  .breach {{ fill:var(--breach); }}
  .breach-ring {{ fill:none; stroke:var(--breach); stroke-width:1.5; transform-box:fill-box; transform-origin:center; animation:ping 2.2s ease-out infinite; }}
  h1 {{ margin:6px 0 0; font:300 clamp(38px,7vh,60px)/1 "Avenir Next","Helvetica Neue",Arial,sans-serif; letter-spacing:.14em;
       color:#effcff; text-shadow:0 0 14px rgba(111,233,255,.85),0 0 42px rgba(111,233,255,.45); animation:fade 1.2s .5s both; }}
  .powered {{ margin-top:14px; font:700 16px/1.2 "Avenir Next","Helvetica Neue",Arial,sans-serif; letter-spacing:.08em; color:var(--ink); animation:fade 1.2s 1s both; }}
  @keyframes spin {{ to {{ transform:rotate(360deg); }} }}
  @keyframes pulse {{ 0%,100% {{ opacity:.82; transform:scale(.97); }} 50% {{ opacity:1; transform:scale(1.04); }} }}
  @keyframes coil {{ 0%,100% {{ fill:rgba(111,233,255,.22); }} 50% {{ fill:rgba(160,242,255,.72); }} }}
  @keyframes ping {{ from {{ transform:scale(.6); opacity:1; }} to {{ transform:scale(2.6); opacity:0; }} }}
  @keyframes boot {{ from {{ opacity:0; transform:scale(.72) rotate(-24deg); }} to {{ opacity:1; transform:none; }} }}
  @keyframes fade {{ from {{ opacity:0; transform:translateY(8px); }} to {{ opacity:1; transform:none; }} }}
  @media (max-width:760px) {{ svg.hud {{ width:min(82vw,56vh); }} h1 {{ letter-spacing:.08em; }} }}
  @media (prefers-reduced-motion:reduce) {{ * {{ animation:none !important; }} }}
</style>
<div class="stage" role="img" aria-label="BreachPoint opening screen: a glowing reactor emblem inside a rotating display">
    <svg class="hud" viewBox="0 0 600 600" aria-hidden="true">
      <defs>
        <radialGradient id="core"><stop offset="0" stop-color="#fff"/><stop offset=".34" stop-color="#d6fbff"/>
          <stop offset=".68" stop-color="#6fe9ff" stop-opacity=".85"/><stop offset="1" stop-color="#6fe9ff" stop-opacity="0"/></radialGradient>
        <radialGradient id="halo"><stop offset=".45" stop-color="#6fe9ff" stop-opacity=".34"/><stop offset="1" stop-color="#6fe9ff" stop-opacity="0"/></radialGradient>
        <linearGradient id="sw" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#6fe9ff" stop-opacity="0"/><stop offset="1" stop-color="#6fe9ff" stop-opacity=".42"/></linearGradient>
        <filter id="g" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="3.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
        <path id="tp" d="{_arc(258, 0, 358)}"/>
      </defs>
      <circle cx="{CX}" cy="{CY}" r="290" fill="url(#halo)"/>

      <g class="spin line" style="--t:64s" opacity=".75">{_ticks(292, 8, 120, 10)}</g>
      <g class="spin rev" style="--t:46s"><text class="ringtext"><textPath href="#tp">{ring_text}{ring_text}</textPath></text></g>
      <g class="spin line" style="--t:26s" filter="url(#g)">{_arcs(236, [(8, 74), (98, 128), (150, 232), (262, 300), (322, 348)], 3)}
        <circle class="breach" cx="{bx:.1f}" cy="{by:.1f}" r="6"/><circle class="breach-ring" cx="{bx:.1f}" cy="{by:.1f}" r="8"/></g>
      <g class="spin rev line" style="--t:18s" opacity=".85">{_arcs(212, [(20, 150), (190, 250), (280, 340)], 1.4)}{_ticks(204, 7, 72, 6, 1)}</g>
      <g class="sweep"><path d="M{CX} {CY}L{CX} {CY - 196}A196 196 0 0 1 {_polar(196, 42)[0]:.1f} {_polar(196, 42)[1]:.1f}Z" fill="url(#sw)"/></g>
      <g class="spin line" style="--t:12s" filter="url(#g)">{_arcs(158, [(0, 52), (60, 112), (120, 172), (180, 232), (240, 292), (300, 352)], 5)}</g>
      <circle class="line" cx="{CX}" cy="{CY}" r="134" stroke-width="1.5" filter="url(#g)"/>

      <g class="spin coils" style="--t:30s" filter="url(#g)">{_coils()}</g>
      <circle class="line" cx="{CX}" cy="{CY}" r="70" stroke-width="2.5" filter="url(#g)"/>
      <g class="spin rev line" style="--t:9s" filter="url(#g)">{_arcs(58, [(10, 110), (130, 230), (250, 350)], 3)}</g>
      <circle class="core" cx="{CX}" cy="{CY}" r="48" fill="url(#core)" filter="url(#g)"/>
    </svg>
  <h1>BreachPoint</h1>
  <div class="powered">Powered by IBM Granite</div>
</div>"""
