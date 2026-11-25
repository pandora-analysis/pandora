"use strict";
// Shared UI helpers, loaded on every page (templates/base.html).

// Copy buttons: <button type="button" class="pdr-copy" data-copy="value">. One listener for the whole page,
// so it also works for content added later (tables, results loaded by analysis.js).
document.addEventListener("click", (event) => {
    const button = event.target.closest(".pdr-copy[data-copy]");
    if (!button) { return; }
    // Icon-only button: feedback is a colour change plus a small "Copied" bubble (CSS ::after on .is-copied).
    const done = (ok) => {
        button.classList.add(ok ? "is-copied" : "is-failed");
        button.setAttribute("title", ok ? "Copied" : "Copy failed");
        setTimeout(() => {
            button.classList.remove("is-copied", "is-failed");
            button.setAttribute("title", "Copy");
        }, 1500);
    };
    navigator.clipboard.writeText(button.dataset.copy).then(() => done(true), () => done(false));
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
