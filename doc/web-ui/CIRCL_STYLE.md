# CIRCL visual style — reference for the Pandora web UI rework

Taken from https://www.circl.lu/ on 2026-11-23 (`root.min.css`, `custom.min.css`, home page HTML).
Goal: Pandora should look like a sibling of circl.lu. Values below are the ones the site uses.

## Logos

| File | Use |
|---|---|
| `website/web/static/images/circl-logo-h.png` (210×78, from `/assets/images/logo.png`) | Horizontal "circl.lu — Computer Incident Response Center LUXEMBOURG"; header/footer brand |
| `website/web/static/images/circl-logo.png` (150×150, from `/assets/images/circl-logo.png`) | Square mark; favicon-like / small placements |
| `website/web/static/images/pandora-logo-new.svg` (920×300) | **New Pandora logo**: layered blue box + "pandora / analysis framework"; title #1A3A6A, sub #4A5A70, box #1E569B→#A8D3FA. Use it as the product brand |
| `website/web/static/images/logo-h.svg`, `logo.svg` | Old Pandora logo — being replaced |

circl.lu header pattern: logo at 140×52, then a label "Computer Incident Response Center Luxembourg"
separated by `border-left: 1px solid #dce4e8`, label color `#52636d`.
Proposed for Pandora: Pandora logo as product brand + "by CIRCL" logo in header or footer (to decide).

## Colors (light theme, the one actually used on body)

| Token | Value | Where circl.lu uses it |
|---|---|---|
| `--body-text-color` | `#23313a` | Main text |
| `--body-background-color` | `#f7f9fa` | Page background |
| `--primary-color` | `#315e73` | Links, buttons text, primary accents (most used color) |
| primary dark | `#254f63` / `#254d60` / `#294f61` | Hover/active primary |
| primary mid | `#446d80` | Secondary accent |
| accent red | `#de2d38` | `h2` left border (4px), active nav underline (`inset 0 -2px`), hero bar |
| red dark | `#b8242e` / `#b5222c` | Red hover |
| focus yellow | `#e4a526` | `:focus-visible` outline 3px (accessibility) |
| border | `#dce4e8` (also `#ccd9df`, `#cbd8dd`, `#e2e8eb`) | Card/header/dropdown borders |
| hover bg | `#edf3f5` | Nav/link/button hover background |
| muted text | `#52636d` / `#53646e` | Labels, captions |
| surface | `#fff` | Cards, header, dropdowns |
| subtle surfaces | `#f7fafb`, `#eaf1f4` | Alternating rows / panels |

Also defined in `root.min.css` (theme variables, light/dark): `--primary-color:#cd5c5c`, light background `#f0efea`,
dark background `#222`, code background `#333030` / code text `#f0efea`. The body-level variables above override them on the main site.

## Typography

- Root variables: `"Bricolage Grotesque", sans-serif`, weight 500 (main, content, summary).
- `custom.min.css` also loads `raleway` (local woff) and uses Arial as fallback.
- Pandora must not load fonts from third-party CDNs at runtime (SRI + self-hosted policy): self-host or use a system stack.

## Shapes & details

- Border radius: 9–10px for cards (most common), 5–6px for buttons/inputs, 12px large panels, 50% avatars.
- Header: white, `border-bottom: 1px solid #dce4e8`, sticky top.
- Nav links: padding ~.7rem, hover bg `#edf3f5`, active = bg `#edf3f5` + red underline `#de2d38`.
- Section titles: `h2 { border-left: 4px solid #de2d38 }`.
- Respect `prefers-reduced-motion` (no transitions).
- Light flat look, few shadows.

## Design decisions

Taken after comparing header variants (logo colours, CIRCL logo placement, font):
- **Pandora logo: keep its original colours.** The version re-tinted to CIRCL's blue-grey turns dull grey and loses contrast,
  and the original blues already go well with `#315e73` links and the red `#de2d38` accents.
- **CIRCL logo in the footer, not the header.** Two logos side by side in the header compete, and the CIRCL tagline
  is unreadable at header size; the header stays focused on Pandora + navigation (easier to read).
  The footer carries "Pandora — operated by CIRCL" + CIRCL logo + links.
- **Font: Bricolage Grotesque** (CIRCL's font) for the UI, self-hosted woff2 (SIL OFL), with system sans as fallback.
  Hashes, file names, rule names and errors go in a **monospace** font for readability and copy/paste when debugging.

## Accent lines are always straight

Red or blue accent lines (menu underline, top bar of a card, left edge of a message box, active tab) must be
**perfectly straight**, never curved at the ends. On the side where such a line sits, the corners are square
(radius 0). Corners on the other sides may stay rounded.

## Page width

Not a narrow centred column, not the full screen either: content up to **1600px**, centred, side margins
`clamp(16px, 4vw, 72px)` (16px on phones). Header, content and footer use the same width so they line up.
The upload page (1280px) and the login / error boxes keep a narrower readable width.

## Pandora-specific status colors (keep the meaning, restyle)

Current `style.css`: overwrite `#808080`, error `#000`, alert `#c9302c`, warn, … Keep the 5 states
(clean / warning / alert / error / overwrite) but harmonise with the palette (red = CIRCL red for alert).

## Dark theme

Three choices in the header: **Light** (default), **Match browser** (`prefers-color-scheme`, read when the page loads)
and **Dark**. The choice is stored per browser (`localStorage`, key `pdr-theme`) and applied by an inline script in
`base.html` before the first paint. Only the `--pdr-*` tokens change (`html[data-theme="dark"]` in `theme.css`);
Bootstrap follows through `data-bs-theme`. `--pdr-primary` is the text colour and `--pdr-primary-solid` the colour
used under white text (buttons, current page, progress bars). All text pairs keep WCAG AA contrast (≥ 4.5:1).
The Pandora logo has a light-text variant (`pandora-logo-new-dark.svg`); the CIRCL logo sits on a light badge.
