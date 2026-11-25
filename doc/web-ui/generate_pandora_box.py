#!/usr/bin/env python3
"""Generate website/web/templates/_pandora_box.html: the Pandora box icon, inline, with its 4 flaps animated.

Run from the repository root:  python3 doc/web-ui/generate_pandora_box.py

The logo (website/web/static/images/pandora-icon.svg) is drawn in isometric view. Each flap is a thin slab hinged on
a top edge of the box. For the animation, each flap is rotated *in 3D* around its hinge, from closed (lying inward
over the top, the 4 flaps meeting) through upright to open (as drawn in the logo), and every frame is projected
back to the logo's isometric axes. The frames become SMIL <animate attributeName="points"> keyframes, so the
browser only interpolates between close, real positions.

Two modes, chosen in the template with `box_mode`:
  - "once": the closed box opens once when ui.js calls beginElement() (front flaps first, like a real box,
            then the back ones); CSS then raises the layers.
  - "loop": loader; opens, stays open while the layers rise, closes again.
"""
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ICON = ROOT / 'website/web/static/images/pandora-icon.svg'
OUT = ROOT / 'website/web/templates/_pandora_box.html'

# Isometric axes of the drawing, in px for one box edge: X = back→right, Y = back→left, Z = up.
X = (72.0, 42.0)
Y = (-72.0, 42.0)
Z = (0.0, -83.4)  # same projected length as X / Y (isometric)

OPEN_DEPTH = 26 / 72      # flap depth as drawn (open), in box edges
CLOSED_DEPTH = 0.5        # closed, two opposite flaps meet in the middle of the top


def add(a, b, k=1.0):
    return (a[0] + k * b[0], a[1] + k * b[1])


# Each flap: hinge corners (as drawn), outward axis (unit), and its polygons as drawn (open).
# 'out' = direction away from the box centre along the top plane. Closed = rotated 180° around the hinge.
FLAPS = {
    'back-left':   {'hinge': [(46, 150), (118, 108)], 'out': (-X[0], -X[1]), 'first': False},
    'back-right':  {'hinge': [(190, 150), (118, 108)], 'out': (-Y[0], -Y[1]), 'first': False},
    'front-left':  {'hinge': [(46, 162), (118, 204)], 'out': Y, 'first': True},
    'front-right': {'hinge': [(190, 162), (118, 204)], 'out': X, 'first': True},
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


def classify(points, flap):
    """Describe each vertex as (hinge corner index, is_outer, thickness_dy) so it can be re-projected."""
    hinge, out = flap['hinge'], flap['out']
    desc = []
    for (x, y) in points:
        for i, h in enumerate(hinge):
            for outer in (False, True):
                base = add(h, out, OPEN_DEPTH) if outer else h
                if abs(base[0] - x) < 1.5 and abs(base[1] - y) < 3:      # same point (drawing is rounded)
                    desc.append((i, outer, 0.0)); break
                if abs(base[0] - x) < 1.5 and 0 < y - base[1] <= 12:     # thickness edge below it
                    desc.append((i, outer, y - base[1])); break
            else:
                continue
            break
        else:
            raise ValueError(f'vertex {x},{y} not understood for {flap}')
    return desc


def frame(desc, flap, theta):
    """Points of a flap polygon at angle theta (0 = open as drawn, pi = closed over the top)."""
    hinge, out = flap['hinge'], flap['out']
    depth = OPEN_DEPTH + (CLOSED_DEPTH - OPEN_DEPTH) * (theta / math.pi)   # flaps are a bit longer than drawn
    vec = add((math.cos(theta) * out[0], math.cos(theta) * out[1]), Z, math.sin(theta))  # rotation in 3D, projected
    pts = []
    for i, outer, dy in desc:
        p = add(hinge[i], vec, depth) if outer else hinge[i]
        pts.append((p[0], p[1] + dy * max(math.cos(theta), 0)))  # slab edge only seen while open-ish
    return ' '.join(f'{x:.1f},{y:.1f}' for x, y in pts)


def ease(t):  # ease-in-out
    return t * t * (3 - 2 * t)


def keyframes(desc, flap, mode):
    steps = 14
    if mode == 'once':
        # front flaps (on top) open during 0–0.55, back flaps during 0.35–0.9 of 0.9 s
        start, end = (0.0, 0.55) if flap['first'] else (0.35, 0.9)
        times = [0.0] + [start + (end - start) * k / steps for k in range(steps + 1)] + [1.0]
        thetas = [math.pi] + [math.pi * (1 - ease(k / steps)) for k in range(steps + 1)] + [0.0]
    else:
        # loop 2.4 s: open (front then back), stay open, close (back then front), stay closed
        o0, o1 = (0.05, 0.25) if flap['first'] else (0.15, 0.35)
        c0, c1 = (0.80, 0.95) if flap['first'] else (0.70, 0.85)
        times, thetas = [0.0], [math.pi]
        for k in range(steps + 1):
            times.append(o0 + (o1 - o0) * k / steps); thetas.append(math.pi * (1 - ease(k / steps)))
        for k in range(steps + 1):
            times.append(c0 + (c1 - c0) * k / steps); thetas.append(math.pi * ease(k / steps))
        times.append(1.0); thetas.append(math.pi)
    # SMIL needs strictly increasing keyTimes
    clean_t, clean_v = [], []
    for t, th in zip(times, thetas):
        t = round(t, 4)
        if clean_t and t <= clean_t[-1]:
            clean_v[-1] = frame(desc, flap, th); continue
        clean_t.append(t); clean_v.append(frame(desc, flap, th))
    return ';'.join(f'{t:g}' for t in clean_t), ';'.join(clean_v)


def animate(points_attr, flap_name):
    flap = FLAPS[flap_name]
    pts = [tuple(map(float, p.split(','))) for p in points_attr.split()]
    desc = classify(pts, flap)
    kt_o, v_o = keyframes(desc, flap, 'once')
    kt_l, v_l = keyframes(desc, flap, 'loop')
    once = (f'<animate class="pdr-box-anim" attributeName="points" begin="indefinite" dur="0.9s" fill="freeze" '
            f'keyTimes="{kt_o}" values="{v_o}"/>')
    loop = (f'<animate attributeName="points" begin="0s" dur="2.4s" repeatCount="indefinite" '
            f'keyTimes="{kt_l}" values="{v_l}"/>')
    return '{% if box_mode == "loop" %}' + loop + '{% else %}' + once + '{% endif %}'


def main():
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
        svg = svg[:m.start()] + f'<polygon points="{points_attr}"{m.group(1)}>{animate(points_attr, name)}</polygon>' + svg[m.end():]
    for name, first_poly in (('back-left', '46,150 118,108 92,92 20,134'), ('back-right', '190,150 118,108 144,92 216,134'),
                             ('front-left', '46,162 118,204 92,220 20,178'), ('front-right', '190,162 118,204 144,220 216,178')):
        polys = [p for p, n in POLYS.items() if n == name]
        start = svg.index(f'<polygon points="{first_poly}"')
        last = svg.index(f'<polygon points="{polys[-1]}"')
        end = svg.index('</polygon>', last) + len('</polygon>')
        line_start = svg.rindex('\n', 0, start) + 1
        svg = (svg[:line_start] + f'    <g class="pdr-box-flap pdr-box-flap-{name}">\n' + svg[line_start:end]
               + '\n    </g>' + svg[end:])
    header = ('{#- GENERATED by doc/web-ui/generate_pandora_box.py from static/images/pandora-icon.svg: do not edit by hand.\n'
              '    Pandora box, inline so it can be animated. Set before the include: `class`, `box_id` (gradient id prefix,\n'
              '    unique per copy on a page) and `box_mode` ("once": opens when ui.js starts it; "loop": loader).\n'
              '    The 4 flaps rotate in 3D around their hinge (closed over the top → open), projected in the logo\'s view. -#}\n')
    OUT.write_text(header + svg)
    print(f'written {OUT.relative_to(ROOT)}')


if __name__ == '__main__':
    main()
