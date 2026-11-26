"use strict";
// Shared UI helpers, loaded on every page (templates/base.html).

// Copy buttons: <button type="button" class="pdr-copy" data-copy="value">. One listener for the whole page,
// so it also works for content added later (tables, results loaded by analysis.js).
// data-copy-from="#id" copies the text of that element instead (whole text of a file).
function pdrWriteClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) { return navigator.clipboard.writeText(text); }
    // Plain http instance: the clipboard API is not available
    return new Promise((resolve, reject) => {
        const area = document.createElement("textarea");
        area.value = text;
        area.className = "visually-hidden";
        document.body.appendChild(area);
        area.select();
        const ok = document.execCommand("copy");
        area.remove();
        if (ok) { resolve(); } else { reject(new Error("copy refused")); }
    });
}
document.addEventListener("click", (event) => {
    const button = event.target.closest(".pdr-copy[data-copy], [data-copy-from]");
    if (!button) { return; }
    const source = button.dataset.copyFrom ? document.querySelector(button.dataset.copyFrom) : null;
    const title = button.getAttribute("title");
    // Feedback is a colour change plus a small "Copied" bubble (CSS ::after on .is-copied).
    const done = (ok) => {
        button.classList.add(ok ? "is-copied" : "is-failed");
        button.setAttribute("title", ok ? "Copied" : "Copy failed");
        setTimeout(() => {
            button.classList.remove("is-copied", "is-failed");
            button.setAttribute("title", button.matches(".pdr-copy") ? "Copy" : (title || ""));
        }, 1500);
    };
    pdrWriteClipboard(source ? source.textContent : button.dataset.copy).then(() => done(true), () => done(false));
});

// Escape a value before putting it in HTML.
function pdrEscape(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
}

// Same markup from JavaScript (used by render_tables.js). Value is escaped.
function pdrCopyButton(value) {
    const safe = String(value ?? "").replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
    return `<button type="button" class="pdr-copy" data-copy="${safe}" title="Copy" aria-label="Copy ${safe}">` +
           `<svg class="bi" width="14" height="14" fill="currentColor" aria-hidden="true"><use href="/bootstrap/static/icons/bootstrap-icons.svg#copy"/></svg></button>`;
}

// Page loader (see templates/base.html): reveal the page in one go once it is ready, instead of letting
// parts pop in. Ready = everything loaded + web font ready + (pages with data-pdr-wait="content") the first
// data drawn, announced by the page's script with document.dispatchEvent(new Event("pdr:content-ready")).
// Capped at 3 s; the inline timer in <head> is a second safety net at 4 s.
(function () {
    const root = document.documentElement;
    if (!root.classList.contains("pdr-loading")) { return; }
    const waits = [
        new Promise((resolve) => (document.readyState === "complete") ? resolve() : window.addEventListener("load", resolve, {once: true})),
        (document.fonts && document.fonts.ready) ? document.fonts.ready : Promise.resolve(),
    ];
    if (document.body && document.body.dataset.pdrWait === "content") {
        waits.push(new Promise((resolve) => document.addEventListener("pdr:content-ready", resolve, {once: true})));
    }
    Promise.race([Promise.all(waits), new Promise((resolve) => setTimeout(resolve, 3000))])
        .then(() => {
            root.classList.remove("pdr-loading"); root.classList.add("pdr-ready");
            // Home box: open the 4 flaps now that the page is visible (SMIL, templates/_pandora_box.html).
            // Reduced motion: don't start them, the box stays in its drawn (open) state.
            if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
                document.querySelectorAll(".pdr-box-animated animate.pdr-box-anim").forEach((a) => { try { a.beginElement(); } catch (e) { /* SMIL not supported */ } });
            }
        });
})();

// Pandora dialogs, replacing the browser's confirm() / alert() boxes (which can't be styled).
// pdrConfirm(message, {title, confirmLabel, cancelLabel, danger}) -> Promise<boolean>
// pdrAlert(message, {title, kind: "error" | "info"})               -> Promise<void>
// Forms: <form data-pdr-confirm="Message" [data-pdr-confirm-title] [data-pdr-confirm-label] [data-pdr-danger]>
//        asks first, and only submits on "yes".
const PDR_ICONS = {danger: "exclamation-octagon-fill", error: "x-octagon-fill", info: "info-circle-fill", question: "question-circle-fill"};

function pdrDialog({title, message, kind = "question", confirmLabel = "OK", cancelLabel = null}) {
    return new Promise((resolve) => {
        const el = document.createElement("div");
        el.className = `modal fade pdr-dialog pdr-dialog--${kind}`;
        el.tabIndex = -1;
        el.setAttribute("aria-hidden", "true");
        el.setAttribute("aria-labelledby", "pdrDialogTitle");
        el.innerHTML = `
          <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
              <div class="modal-header">
                <span class="pdr-dialog-icon"><svg class="bi" width="22" height="22" fill="currentColor" aria-hidden="true">
                  <use href="/bootstrap/static/icons/bootstrap-icons.svg#${PDR_ICONS[kind] || PDR_ICONS.question}"/></svg></span>
                <h4 class="modal-title" id="pdrDialogTitle">${pdrEscape(title)}</h4>
              </div>
              <div class="modal-body"><p class="mb-0">${pdrEscape(message)}</p></div>
              <div class="modal-footer">
                ${cancelLabel ? `<button type="button" class="btn btn-secondary" data-pdr-answer="no">${pdrEscape(cancelLabel)}</button>` : ""}
                <button type="button" class="btn ${kind === "danger" ? "btn-danger" : "btn-primary"}" data-pdr-answer="yes">${pdrEscape(confirmLabel)}</button>
              </div>
            </div>
          </div>`;
        document.body.appendChild(el);
        let answer = false;
        el.addEventListener("click", (e) => {
            const b = e.target.closest("[data-pdr-answer]");
            if (b) { answer = b.dataset.pdrAnswer === "yes"; modal.hide(); }
        });
        // Focus the safe choice: "Cancel" when there is one (dangerous actions), else the only button.
        el.addEventListener("shown.bs.modal", () => (el.querySelector('[data-pdr-answer="no"]') || el.querySelector('[data-pdr-answer="yes"]')).focus());
        el.addEventListener("hidden.bs.modal", () => { el.remove(); resolve(answer); });
        const modal = new bootstrap.Modal(el, {backdrop: cancelLabel ? true : "static"});
        modal.show();
    });
}

function pdrConfirm(message, {title = "Please confirm", confirmLabel = "Yes", cancelLabel = "Cancel", danger = false} = {}) {
    return pdrDialog({title, message, kind: danger ? "danger" : "question", confirmLabel, cancelLabel});
}

function pdrAlert(message, {title = "Something went wrong", kind = "error"} = {}) {
    return pdrDialog({title, message, kind, confirmLabel: "OK"}).then(() => undefined);
}

document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!form.dataset || !form.dataset.pdrConfirm || form.dataset.pdrConfirmed === "1") { return; }
    event.preventDefault();
    const ok = await pdrConfirm(form.dataset.pdrConfirm, {
        title: form.dataset.pdrConfirmTitle || "Please confirm",
        confirmLabel: form.dataset.pdrConfirmLabel || "Yes",
        danger: "pdrDanger" in form.dataset,
    });
    if (ok) { form.dataset.pdrConfirmed = "1"; form.submit(); }
});

// Colour theme switcher (header). The theme itself is applied before the first paint by the inline script in base.html.
(function () {
    const root = document.documentElement;
    function apply(choice) {
        const dark = choice === "dark" || (choice === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
        root.setAttribute("data-theme", dark ? "dark" : "light");
        root.setAttribute("data-bs-theme", dark ? "dark" : "light");
        root.setAttribute("data-theme-choice", choice);
        document.querySelectorAll("[data-pdr-theme-set]").forEach((b) => {
            const on = b.dataset.pdrThemeSet === choice;
            b.classList.toggle("active", on);
            b.setAttribute("aria-pressed", on ? "true" : "false");
        });
    }
    document.addEventListener("click", (event) => {
        const b = event.target.closest("[data-pdr-theme-set]");
        if (!b) { return; }
        try { localStorage.setItem("pdr-theme", b.dataset.pdrThemeSet); } catch (e) { /* storage blocked: still apply for this page */ }
        apply(b.dataset.pdrThemeSet);
    });
    // No live watching: "Match browser" reads the browser's preference when the page loads or when the mode is chosen.
    apply(root.getAttribute("data-theme-choice") || "light");
})();

// Page viewer (templates/previews.html): one page at a time, arrows on the sides, thumbnails, ← / → keys.
// The current page is remembered on the container, so a refresh of the HTML (analysis.js) keeps it.
function pdrPagerShow(pager, index) {
    const pages = pager.querySelectorAll(".pdr-page");
    if (!pages.length) { return; }
    const i = Math.max(0, Math.min(pages.length - 1, index));
    const target = pages[i];
    const img = target.querySelector("img");
    const token = String(Date.now() + Math.random());
    pager.dataset.pdrToken = token;
    // Update the controls at once (counter, arrows, thumbnails), the page itself only when its image is ready
    pager.querySelectorAll(".pdr-pager-thumb").forEach((t, k) => {
        t.classList.toggle("is-current", k === i);
        if (k === i) { t.setAttribute("aria-current", "true"); t.scrollIntoView({block: "nearest", inline: "nearest", behavior: "instant"}); }
        else { t.removeAttribute("aria-current"); }
    });
    const prev = pager.querySelector(".pdr-pager-prev"), next = pager.querySelector(".pdr-pager-next");
    if (prev) { prev.disabled = i === 0; }
    if (next) { next.disabled = i === pages.length - 1; }
    const cur = pager.querySelector("[data-pdr-pager-current]");
    if (cur) { cur.textContent = i + 1; }
    pager.dataset.current = i;
    if (pager.parentElement) { pager.parentElement.dataset.pdrPage = i; }   // survives an innerHTML refresh of the parent
    // Main preview: write the page in the address (#page=3) so a shared link opens on it. replaceState: no history spam.
    if (pager.closest("#previews_images") && !pager.dataset.pdrRestoring) {
        const hash = i > 0 ? `#page=${i + 1}` : " ";
        if (location.hash !== hash.trim()) { history.replaceState(null, "", hash === " " ? location.pathname + location.search : hash); }
    }

    const swap = () => {
        if (pager.dataset.pdrToken !== token) { return; }   // another page was asked meanwhile
        pages.forEach((p, k) => p.classList.toggle("is-current", k === i));
        pager.classList.remove("is-loading");
        const stage = pager.querySelector(".pdr-pager-stage");
        if (stage) { stage.style.minHeight = ""; }
        pager.dispatchEvent(new CustomEvent("pdr:page-shown", {bubbles: true}));
        // preload the neighbours so the next arrow click is instant
        [i - 1, i + 1].forEach((k) => { const n = pages[k] && pages[k].querySelector("img"); if (n) { n.loading = "eager"; } });
    };
    if (!img || (img.complete && img.naturalWidth > 0)) { swap(); return; }
    // Not loaded yet: keep the current page on screen (held height + loading veil) until the new one has arrived
    const stage = pager.querySelector(".pdr-pager-stage");
    if (stage) { stage.style.minHeight = stage.offsetHeight + "px"; }
    pager.classList.add("is-loading");
    img.loading = "eager";
    img.addEventListener("load", swap, {once: true});
    img.addEventListener("error", swap, {once: true});
}
function pdrPagerRestore(container) {
    const pager = container && container.querySelector("[data-pdr-pager]");
    if (pager && container.dataset.pdrPage) { pdrPagerShow(pager, parseInt(container.dataset.pdrPage, 10)); }
}
document.addEventListener("click", (event) => {
    const go = event.target.closest("[data-pdr-pager-go], [data-pdr-pager-to]");
    if (!go) { return; }
    const pager = go.closest("[data-pdr-pager]");
    const current = parseInt(pager.dataset.current || "0", 10);
    pdrPagerShow(pager, go.dataset.pdrPagerTo !== undefined ? parseInt(go.dataset.pdrPagerTo, 10) : current + parseInt(go.dataset.pdrPagerGo, 10));
});
document.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") { return; }
    const target = event.target instanceof Element ? event.target : null;   // can be the document itself
    if (target && target.closest("input, textarea, select, [contenteditable], .modal")) { return; }
    // the visible pager (the tab that is shown)
    const pager = [...document.querySelectorAll("[data-pdr-pager]")].find((p) => p.offsetParent !== null);
    if (!pager) { return; }
    event.preventDefault();
    pdrPagerShow(pager, parseInt(pager.dataset.current || "0", 10) + (event.key === "ArrowRight" ? 1 : -1));
});

// Open on the page given in the address (#page=3), now or once the previews arrive (analysis.js calls pdrPagerRestore).
document.addEventListener("DOMContentLoaded", () => {
    const m = /^#page=(\d+)$/.exec(location.hash);
    if (!m) { return; }
    document.querySelectorAll("#previews_images").forEach((box) => {
        box.dataset.pdrPage = Math.max(0, parseInt(m[1], 10) - 1);
        const pager = box.querySelector("[data-pdr-pager]");
        if (pager) { pager.dataset.pdrRestoring = "1"; pdrPagerShow(pager, parseInt(box.dataset.pdrPage, 10)); delete pager.dataset.pdrRestoring; }
    });
});

// Buttons that open a tab: <button data-pdr-open-tab="#panel-id">
document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-pdr-open-tab]");
    const tab = button && document.querySelector(`[data-bs-toggle="tab"][data-bs-target="${button.dataset.pdrOpenTab}"]`);
    if (tab) { bootstrap.Tab.getOrCreateInstance(tab).show(); }
});

// Text preview: the server cuts the picture at 2000 x 5000 px (pandora/file.py, text_preview). At that size, text is missing.
(function () {
    document.querySelectorAll(".pdr-text-preview img").forEach((img) => {
        const check = () => img.closest(".pdr-text-preview").classList.toggle("is-cut", img.naturalHeight >= 5000 || img.naturalWidth >= 2000);
        if (img.complete) { check(); } else { img.addEventListener("load", check, {once: true}); }
    });
})();

// Full screen viewer: only the page, with the arrows and all the pages below. The class is set on the container, which
// survives a refresh of the pages (analysis.js). The browser's own full screen is used when it is available.
// Zoom: buttons, wheel, pinch, + / - keys, double click. Move: drag, up / down keys. Also whole page, full width, rotate.
const pdrView = {box: null, fit: "page", scale: 1, x: 0, y: 0, turn: 0, pointers: new Map()};

function pdrViewParts() {
    const figure = pdrView.box && pdrView.box.querySelector(".pdr-page.is-current");
    const img = figure && figure.querySelector("img");
    if (!img || !img.naturalWidth || !figure.clientWidth) { return null; }
    const side = pdrView.turn % 180 !== 0;
    return {figure, img, w: side ? img.naturalHeight : img.naturalWidth, h: side ? img.naturalWidth : img.naturalHeight,
            vw: figure.clientWidth, vh: figure.clientHeight};
}
function pdrViewRender() {
    const p = pdrViewParts();
    if (!p) { return; }
    const margin = 24;
    if (pdrView.fit === "page") { pdrView.scale = Math.min((p.vw - margin) / p.w, (p.vh - margin) / p.h); }
    if (pdrView.fit === "width") { pdrView.scale = (p.vw - margin) / p.w; }
    // Keep the page in the window: centred when it is smaller, never dragged past its edges otherwise
    const maxX = Math.max(0, (p.w * pdrView.scale + margin - p.vw) / 2), maxY = Math.max(0, (p.h * pdrView.scale + margin - p.vh) / 2);
    pdrView.x = Math.max(-maxX, Math.min(maxX, pdrView.x));
    pdrView.y = Math.max(-maxY, Math.min(maxY, pdrView.y));
    p.img.style.transform = `translate(-50%, -50%) translate(${pdrView.x}px, ${pdrView.y}px) rotate(${pdrView.turn}deg) scale(${pdrView.scale})`;
    p.figure.classList.toggle("can-move", maxX > 0 || maxY > 0);
    const out = pdrView.box.querySelector("[data-pdr-view-zoom]");
    if (out) { out.textContent = `${Math.round(pdrView.scale * 100)}%`; }
    pdrView.box.querySelectorAll("[data-pdr-view=page], [data-pdr-view=width]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.pdrView === pdrView.fit));
}
// px, py: the point that must not move, from the centre of the window
function pdrViewZoom(factor, px = 0, py = 0) {
    const p = pdrViewParts();
    if (!p) { return; }
    const smallest = Math.min(1, p.vw / p.w, p.vh / p.h) / 2;
    const scale = Math.max(smallest, Math.min(8, pdrView.scale * factor));
    const k = scale / pdrView.scale;
    pdrView.x = px - (px - pdrView.x) * k;
    pdrView.y = py - (py - pdrView.y) * k;
    pdrView.scale = scale;
    pdrView.fit = "";
    pdrViewRender();
}
function pdrViewFit(fit) {
    pdrView.fit = fit;
    pdrView.x = 0;
    pdrView.y = 1e6;   // top of the page (limited by pdrViewRender)
    pdrViewRender();
}
function pdrViewAction(action) {
    if (action === "in") { pdrViewZoom(1.25); }
    if (action === "out") { pdrViewZoom(0.8); }
    if (action === "page" || action === "width") { pdrViewFit(action); }
    if (action === "rotate") { pdrView.turn = (pdrView.turn + 90) % 360; pdrViewFit("page"); }
}
function pdrViewPoint(event) {
    const r = pdrView.box.querySelector(".pdr-page.is-current").getBoundingClientRect();
    return [event.clientX - r.left - r.width / 2, event.clientY - r.top - r.height / 2];
}
function pdrFullscreen(box, on) {
    box.classList.toggle("pdr-fullscreen", on);
    document.documentElement.classList.toggle("pdr-has-fullscreen", on);
    pdrView.box = on ? box : null;
    pdrView.pointers.clear();
    pdrView.turn = 0;
    if (on && box.requestFullscreen) { box.requestFullscreen().catch(() => { /* refused: the overlay is enough */ }); }
    if (!on) {
        box.querySelectorAll(".pdr-page img").forEach((img) => { img.style.transform = ""; });
        if (document.fullscreenElement) { document.exitFullscreen().catch(() => { /* already out */ }); }
    } else { pdrViewFit("page"); }
    const focus = on ? box.querySelector("[data-pdr-fullscreen-exit]") : document.querySelector("[data-pdr-fullscreen]");
    if (focus) { focus.focus({preventScroll: true}); }
}
document.addEventListener("click", (event) => {
    const open = event.target.closest("[data-pdr-fullscreen]");
    if (open) { pdrFullscreen(document.querySelector(open.dataset.pdrFullscreen), true); return; }
    if (!pdrView.box) { return; }
    if (event.target.closest("[data-pdr-fullscreen-exit]")) { pdrFullscreen(pdrView.box, false); return; }
    const tool = event.target.closest("[data-pdr-view]");
    if (tool) { pdrViewAction(tool.dataset.pdrView); return; }
    if (event.target.closest(".pdr-fullscreen .pdr-page")) { event.preventDefault(); }   // the page is a link outside the viewer
});
document.addEventListener("dblclick", (event) => {
    if (!pdrView.box || !event.target.closest(".pdr-fullscreen .pdr-page")) { return; }
    if (pdrView.fit === "page") { pdrViewZoom(2.5, ...pdrViewPoint(event)); } else { pdrViewFit("page"); }
});
document.addEventListener("wheel", (event) => {
    if (!pdrView.box || !event.target.closest(".pdr-fullscreen .pdr-page")) { return; }
    event.preventDefault();
    const step = event.deltaMode === 1 ? event.deltaY * 20 : event.deltaY;
    pdrViewZoom(Math.exp(-Math.max(-150, Math.min(150, step)) * 0.002), ...pdrViewPoint(event));
}, {passive: false});
document.addEventListener("dragstart", (event) => { if (pdrView.box && event.target.closest(".pdr-fullscreen .pdr-page")) { event.preventDefault(); } });
document.addEventListener("pointerdown", (event) => {
    const figure = pdrView.box && event.target.closest(".pdr-fullscreen .pdr-page");
    if (!figure || event.button !== 0) { return; }
    pdrView.pointers.set(event.pointerId, [event.clientX, event.clientY]);
    figure.setPointerCapture(event.pointerId);
    figure.classList.add("is-moving");
});
document.addEventListener("pointermove", (event) => {
    const last = pdrView.box && pdrView.pointers.get(event.pointerId);
    if (!last) { return; }
    const others = [...pdrView.pointers].filter(([id]) => id !== event.pointerId).map(([, point]) => point);
    if (others.length === 1) {   // pinch: zoom around the middle of the two fingers
        const before = Math.hypot(last[0] - others[0][0], last[1] - others[0][1]), after = Math.hypot(event.clientX - others[0][0], event.clientY - others[0][1]);
        const middle = pdrViewPoint({clientX: (event.clientX + others[0][0]) / 2, clientY: (event.clientY + others[0][1]) / 2});
        if (before > 0) { pdrViewZoom(after / before, ...middle); }
    } else if (!others.length) {
        pdrView.x += event.clientX - last[0];
        pdrView.y += event.clientY - last[1];
        pdrViewRender();
    }
    pdrView.pointers.set(event.pointerId, [event.clientX, event.clientY]);
});
["pointerup", "pointercancel"].forEach((name) => document.addEventListener(name, (event) => {
    if (!pdrView.pointers.delete(event.pointerId) || pdrView.pointers.size) { return; }
    document.querySelectorAll(".pdr-page.is-moving").forEach((f) => f.classList.remove("is-moving"));
}));
document.addEventListener("keydown", (event) => {
    if (!pdrView.box || event.ctrlKey || event.metaKey || event.altKey) { return; }
    const actions = {"+": "in", "=": "in", "-": "out", "0": "page", "w": "width", "r": "rotate"};
    const action = actions[event.key.toLowerCase()];
    if (action) { event.preventDefault(); pdrViewAction(action); }
    if (event.key === "ArrowUp" || event.key === "ArrowDown") { event.preventDefault(); pdrView.y += event.key === "ArrowUp" ? 80 : -80; pdrViewRender(); }
    if (event.key === "Escape") { pdrFullscreen(pdrView.box, false); }
});
document.addEventListener("fullscreenchange", () => {
    if (pdrView.box && !document.fullscreenElement) { pdrFullscreen(pdrView.box, false); }
});
document.addEventListener("pdr:page-shown", () => {   // another page: same zoom, from its top
    if (pdrView.box) { pdrView.x = 0; pdrView.y = 1e6; pdrViewRender(); }
});
window.addEventListener("resize", pdrViewRender);
document.addEventListener("load", (event) => { if (pdrView.box && event.target.matches && event.target.matches(".pdr-page img")) { pdrViewRender(); } }, true);

// Text box: as long as there is more to scroll, a button tells how many lines are left; a click goes one screen down.
document.querySelectorAll(".pdr-text-box").forEach((box) => {
    const text = box.querySelector(".pdr-text"), next = box.querySelector(".pdr-text-next");
    const update = () => {
        const left = text.scrollHeight - text.scrollTop - text.clientHeight;
        const more = left > 16;   // more than the bottom padding
        box.classList.toggle("has-more", more);
        next.hidden = !more;
        if (more) { next.querySelector("span").textContent = next.dataset.text.replace("{n}", Math.ceil(left / parseFloat(getComputedStyle(text).lineHeight))); }
    };
    next.addEventListener("click", () => {
        const calm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        text.scrollBy({top: text.clientHeight - 60, behavior: calm ? "instant" : "smooth"});
    });
    text.addEventListener("scroll", update, {passive: true});
    if (window.ResizeObserver) { new ResizeObserver(update).observe(text); }   // window resized, tab shown
    update();
});

// Clickable rows (<tr data-pdr-row>): a click anywhere follows the row's link, except on a button or a link,
// and except when text is being selected. Ctrl / Cmd / middle click opens a new tab, like a link.
["click", "auxclick"].forEach((name) => document.addEventListener(name, (event) => {
    const row = event.target.closest("tr[data-pdr-row]");
    if (!row || event.button > 1 || event.target.closest("a, button, input, label")) { return; }
    if (window.getSelection().toString().trim()) { return; }
    const link = row.querySelector("a[href]");
    if (!link) { return; }
    if (event.button === 1 || event.ctrlKey || event.metaKey) { window.open(link.href, "_blank", "noopener"); } else { location.href = link.href; }
}));
