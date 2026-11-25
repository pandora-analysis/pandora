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
