#!/usr/bin/env python3
"""Generate website/web/templates/_pandora_box.html: the Pandora box icon, inline, with its 4 flaps animated.

Run from the repository root:  python3 doc/web-ui/generate_pandora_box.py

The logo (website/web/static/images/pandora-icon.svg) is drawn in isometric view. Each flap is a thin slab hinged on
a top edge of the box. For the animation, each flap is rotated *in 3D* around its hinge, from closed (lying inward
over the top, the 4 flaps meeting) through upright to open (as drawn in the logo), and every frame is projected
back to the logo's isometric axes. The frames become SMIL <animate attributeName="points"> keyframes, so the
browser only interpolates between close, real positions.

Two modes, chosen in the template with `box_mode`:
  - "once": the closed box is shown still, then opens once when ui.js calls beginElement() (top pair of
            opposite flaps first, like a real box, then the pair underneath); CSS then raises the layers.
  - "loop": loader; opens, stays open while the layers rise, closes again.
"""
from __future__ import annotations

import math
import re
from pathlib import Path
from typing import TypedDict

Point = tuple[float, float]
Vertex = tuple[int, bool, float]  # hinge corner index, is it an outer corner, thickness offset


class Flap(TypedDict):
    hinge: list[Point]
    out: Point
    first: bool
    lift: float


ROOT = Path(__file__).resolve().parents[2]
ICON = ROOT / 'website/web/static/images/pandora-icon.svg'
OUT = ROOT / 'website/web/templates/_pandora_box.html'

# Isometric axes of the drawing, in px for one box edge: X = back→right, Y = back→left, Z = up.
X = (72.0, 42.0)
Y = (-72.0, 42.0)
Z = (0.0, -83.4)  # same projected length as X / Y (isometric)

OPEN_DEPTH = 26 / 72      # flap depth as drawn (open), in box edges
CLOSED_DEPTH = 0.5        # closed, two opposite flaps meet in the middle of the top


def add(a: Point, b: Point, k: float=1.0) -> Point:
    return (a[0] + k * b[0], a[1] + k * b[1])


# 'first' = top pair (two opposite flaps, opened first); the other two are folded underneath.
# 'lift' = the back rim is drawn 12 px higher than the front one: closed flaps meet half-way.
# Each flap: hinge corners (as drawn), outward axis (unit), and its polygons as drawn (open).
# 'out' = direction away from the box centre along the top plane. Closed = rotated 180° around the hinge.
FLAPS: dict[str, Flap] = {
    'back-left': {'hinge': [(46, 150), (118, 108)], 'out': (-X[0], -X[1]), 'first': True, 'lift': 6},
    'back-right': {'hinge': [(190, 150), (118, 108)], 'out': (-Y[0], -Y[1]), 'first': False, 'lift': 6},
    'front-left': {'hinge': [(46, 162), (118, 204)], 'out': Y, 'first': False, 'lift': -6},
    'front-right': {'hinge': [(190, 162), (118, 204)], 'out': X, 'first': True, 'lift': -6},
}
POLYS = {  # polygon points as drawn → flap name
    '46,150 118,108 92,92 20,134': 'back-left',
    '46,150 20,134 20,144 46,160': 'back-left',
    '190,150 118,108 144,92 216,134': 'back-right',
    '190,150 216,134 216,144 190,160': 'back-right',
    '46,162 118,204 92,220 20,178': 'front-left',
    '20,178 92,220 92,228 20,186': 'front-left',
    '190,162 118,204 144,220 216,178': 'front-right',
    '118,204 144,220 144,228 118,212': 'front-right',
}


def classify(points: list[Point], flap: Flap) -> list[Vertex]:
    """Describe each vertex as (hinge corner index, is_outer, thickness_dy) so it can be re-projected."""
    hinge, out = flap['hinge'], flap['out']
    desc: list[Vertex] = []
    for (x, y) in points:
        for i, h in enumerate(hinge):
            for outer in (False, True):
                base = add(h, out, OPEN_DEPTH) if outer else h
                if abs(base[0] - x) < 1.5 and abs(base[1] - y) < 3:      # same point (drawing is rounded)
                    desc.append((i, outer, 0.0))
                    break
                if abs(base[0] - x) < 1.5 and 0 < y - base[1] <= 12:     # thickness edge below it
                    desc.append((i, outer, y - base[1]))
                    break
            else:
                continue
            break
        else:
            raise ValueError(f'vertex {x},{y} not understood for {flap}')
    return desc


def frame(desc: list[Vertex], flap: Flap, theta: float, part: str='all') -> str:
    """Points of a flap polygon at angle theta (0 = open as drawn, pi = closed over the top).

    part: 'inner' is only drawn while the flap leans inward, 'outer' once it is past upright; 'all' always.
    A part that is not drawn is collapsed on its hinge, so the front flaps can be painted inside the box, then in front.
    """
    hinge, out = flap['hinge'], flap['out']
    depth = OPEN_DEPTH + (CLOSED_DEPTH - OPEN_DEPTH) * (theta / math.pi)   # flaps are a bit longer than drawn
    vec = add((math.cos(theta) * out[0], math.cos(theta) * out[1]), Z, math.sin(theta))  # 3D rotation, projected
    lift = flap['lift'] * max(-math.cos(theta), 0)
    pts = []
    for i, outer, dy in desc:
        p = hinge[i] if part == 'hidden' or not outer else add(add(hinge[i], vec, depth), (0, lift))
        pts.append((p[0], p[1] + (0 if part == 'hidden' else dy * max(math.cos(theta), 0))))
    return ' '.join(f'{x:.1f},{y:.1f}' for x, y in pts)


def ease(t: float) -> float:  # ease-in-out
    return t * t * (3 - 2 * t)


STEPS = 14  # even: the middle step is exactly upright


def motion(flap: Flap, mode: str) -> list[tuple[float, float]]:
    """List of (time, theta) for one flap."""
    def swing(start: float, end: float, opening: bool) -> list[tuple[float, float]]:
        return [(start + (end - start) * k / STEPS, math.pi * ((1 - ease(k / STEPS)) if opening else ease(k / STEPS)))
                for k in range(STEPS + 1)]
    if mode == 'once':
        # 1.6 s: closed and still for 0.4 s, top pair opens 0.4-1.0 s, under pair 0.9-1.5 s; CSS then raises the layers
        o = (0.25, 0.625) if flap['first'] else (0.5625, 0.9375)
        return [(0.0, math.pi)] + swing(*o, True) + [(1.0, 0.0)]
    # loop, 2.4 s: top pair then under pair open, stay open, under pair then top pair close
    o, c = ((0.04, 0.19), (0.84, 0.98)) if flap['first'] else ((0.17, 0.32), (0.74, 0.87))
    return [(0.0, math.pi)] + swing(*o, True) + swing(*c, False) + [(1.0, math.pi)]


def keyframes(desc: list[Vertex], flap: Flap, mode: str, part: str) -> tuple[str, str]:
    def shown(theta: float, entering: bool) -> str:
        if part == 'all':
            return 'all'
        upright = abs(theta - math.pi / 2) < 1e-6
        inner = entering if upright else theta > math.pi / 2
        return 'all' if inner == (part == 'inner') else 'hidden'
    out: list[tuple[float, str]] = []
    path = motion(flap, mode)
    for n, (t, th) in enumerate(path):
        if part != 'all' and abs(th - math.pi / 2) < 1e-6:   # hand over between the inner and the outer drawing
            from_inner = path[n - 1][1] > th
            out.append((t, frame(desc, flap, th, shown(th, from_inner))))
            out.append((t + 0.0002, frame(desc, flap, th, shown(th, not from_inner))))
        else:
            out.append((t, frame(desc, flap, th, shown(th, True))))
    return ';'.join(f'{round(t, 4):g}' for t, _ in out), ';'.join(v for _, v in out)


def parse(points_attr: str) -> list[Point]:
    pairs = (p.split(',') for p in points_attr.split())
    return [(float(x), float(y)) for x, y in pairs]


def animate(points_attr: str, flap_name: str, part: str='all') -> str:
    flap = FLAPS[flap_name]
    desc = classify(parse(points_attr), flap)
    kt_o, v_o = keyframes(desc, flap, 'once', part)
    kt_l, v_l = keyframes(desc, flap, 'loop', part)
    once = (f'<animate class="pdr-box-anim" attributeName="points" begin="indefinite" dur="1.6s" fill="freeze" '
            f'keyTimes="{kt_o}" values="{v_o}"/>')
    loop = (f'<animate attributeName="points" begin="0s" dur="2.4s" repeatCount="indefinite" '
            f'keyTimes="{kt_l}" values="{v_l}"/>')
    return '{% if box_mode == "loop" %}' + loop + '{% else %}' + once + '{% endif %}'


def inner_copy(points_attr: str, name: str, fill: str) -> str:
    """The front flap while it leans over the box: painted with the back flaps, nothing to see once open."""
    flap = FLAPS[name]
    desc = classify(parse(points_attr), flap)
    return (f'    <polygon class="pdr-box-flap-inner" points="{frame(desc, flap, 0, "hidden")}" fill="{fill}">'
            f'{animate(points_attr, name, "inner")}</polygon>\n')


def main() -> None:
    svg = ICON.read_text()
    # gradients: unique id prefix per copy on a page
    for name in ('layerTop', 'layerMid', 'layerLow'):
        short = name[5:].lower()
        svg = svg.replace(f'id="{name}"', f'id="{{{{ box_id | default("pdrbox") }}}}-{short}"')
        svg = svg.replace(f'url(#{name})', f'url(#{{{{ box_id | default("pdrbox") }}}}-{short})')
    svg = svg.replace('<svg xmlns="http://www.w3.org/2000/svg" viewBox="36 49 236 236" width="236" height="236">',
                      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="36 49 236 236" class="pdr-box {{ class }}" '
                      'role="img" aria-label="Pandora">')
    # layers: the 4 bare <g> in drawing order, bottom → top
    parts = svg.split('    <g>\n')
    assert len(parts) == 5, 'expected 4 layer groups'
    svg = parts[0] + ''.join(f'    <g class="pdr-box-layer pdr-box-layer-{i}">\n' + p for i, p in enumerate(parts[1:], 1))
    # flaps: animate their polygons, group them per flap
    for points_attr, name in POLYS.items():
        pat = re.compile(r'<polygon points="' + re.escape(points_attr) + r'"([^>]*?)\s*/>')
        m = pat.search(svg)
        assert m, points_attr
        svg = svg[:m.start()] + f'<polygon points="{points_attr}"{m.group(1)}>{animate(points_attr, name, 'outer' if name.startswith('front') else 'all')}</polygon>' + svg[m.end():]
    for name, first_poly in (('back-left', '46,150 118,108 92,92 20,134'), ('back-right', '190,150 118,108 144,92 216,134'),
                             ('front-left', '46,162 118,204 92,220 20,178'), ('front-right', '190,162 118,204 144,220 216,178')):
        polys = [p for p, n in POLYS.items() if n == name]
        start = svg.index(f'<polygon points="{first_poly}"')
        last = svg.index(f'<polygon points="{polys[-1]}"')
        end = svg.index('</polygon>', last) + len('</polygon>')
        line_start = svg.rindex('\n', 0, start) + 1
        svg = (svg[:line_start] + f'    <g class="pdr-box-flap pdr-box-flap-{name}">\n' + svg[line_start:end]
               + '\n    </g>' + svg[end:])
    # painting order inside the box: under pair (front-left, back-right), then top pair (back-left, front-right)

    def group(name: str) -> tuple[int, int]:
        a = svg.index(f'    <g class="pdr-box-flap pdr-box-flap-{name}">')
        b = svg.index('    </g>', a) + len('    </g>')
        return a, b
    a, b = group('back-left')
    left = svg[a:b]
    svg = svg[:a] + inner_copy('46,162 118,204 92,220 20,178', 'front-left', '#5EA6F0') + svg[b:]
    a, b = group('back-right')
    svg = (svg[:b] + '\n' + left + '\n' + inner_copy('190,162 118,204 144,220 216,178', 'front-right', '#225BA6') + svg[b:])
    header = ('{#- GENERATED by doc/web-ui/generate_pandora_box.py from static/images/pandora-icon.svg: do not edit by hand.\n'
              '    Pandora box, inline so it can be animated. Set before the include: `class`, `box_id` (gradient id prefix,\n'
              '    unique per copy on a page) and `box_mode` ("once": opens when ui.js starts it; "loop": loader).\n'
              '    The 4 flaps rotate in 3D around their hinge (closed over the top → open), projected in the logo\'s view. -#}\n')
    OUT.write_text('\n'.join(line.rstrip() for line in (header + svg).splitlines()) + '\n')
    print(f'written {OUT.relative_to(ROOT)}')


if __name__ == '__main__':
    main()
