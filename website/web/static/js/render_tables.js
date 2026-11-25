"use strict";

function render_datetime_with_tz(data) {
    if(! isNaN(data)){
        data = parseInt(data);
    }
    const date = new Date(data);
    const pad = (n) => n.toString().padStart(2, "0");
    // Short local time with its UTC offset, e.g. "2026-11-23 16:23 UTC+01:00" (full date in the tooltip).
    const offset = -date.getTimezoneOffset();
    const tz = `UTC${offset >= 0 ? "+" : "-"}${pad(Math.floor(Math.abs(offset) / 60))}:${pad(Math.abs(offset) % 60)}`;
    return `<span title="${date.toString()}">${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())} <small class="text-body-secondary">${tz}</small></span>`;
};

// Escape text before putting it in HTML.
function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
}

// Long identifiers (hashes, UUIDs): shown in full, wrapped, with a copy button (pdrCopyButton is in ui.js).
DataTable.render.full_id = function () {
    return function (data, type) {
        if (type !== 'display') { return data; }
        return `<div class="pdr-id-wrap"><span class="pdr-mono pdr-full-id">${escapeHTML(data)}</span>${pdrCopyButton(data)}</div>`;
    };
}

// Owner: a logged-in user name, or "Anonymous visitor" + its full session UUID.
DataTable.render.owner = function () {
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return function (data, type) {
        if (type !== 'display') { return data; }
        if (uuid.test(String(data))) {
            return `<span class="pdr-visitor">Anonymous visitor</span><div class="pdr-id-wrap"><span class="pdr-mono pdr-full-id">${escapeHTML(data)}</span>${pdrCopyButton(data)}</div>`;
        }
        return escapeHTML(data);
    };
}

DataTable.render.datetime_with_tz = function () {
    return function ( data, type, row ) {
        if ( type === 'display' ) {
            return render_datetime_with_tz(data);
        }
        if ( type === 'filter' ) {
            return new Date(isNaN(data) ? data : parseInt(data)).toISOString();
        }
        return data;
    };
}

function renderTables() {
    if (document.getElementById('TasksTable')) {
        let csrf_token = document.getElementById('TasksTable').dataset.csrf;
        new DataTable('#TasksTable', {
          processing: true,
          serverSide: true,
          retrieve: true,
          ordering: false,
          searching: true,
          order: [[ 2, "desc" ]],
          ajax: {
            url: `/tables/tasksTable/${window.location.search}`,
            type: 'POST',
            headers: {"X-CSRF-Token" : csrf_token}
          },
          // Reading order: status first, then what the file is. Keep in sync with the <thead> in templates/tasks.html.
          // Cells marked "display" are HTML rendered by the server; the others are plain text, escaped here.
          columns : [
              { data: {_: 'status.display', filter: 'status.filter'}, width: '9%' },
              { data: {_: 'name.display', filter: 'name.filter'}, width: '30%', className: 'pdr-name-cell' },
              { data: 'date', width: '14%', className: 'text-nowrap', render: DataTable.render.datetime_with_tz() },
              { data: 'sha256', width: '22%', className: 'pdr-sha-cell', render: DataTable.render.full_id() },
              { data: 'owner', width: '10%', render: DataTable.render.owner() },
              { data: 'id', width: '14%', render: DataTable.render.full_id() },
              { data: {_: 'buttons.display', filter: 'buttons.filter'}, width: '10%', className: 'text-nowrap' }
          ],
          // First data drawn: let the page loader reveal the page (static/js/ui.js)
          initComplete: function () { document.dispatchEvent(new Event("pdr:content-ready")); },
          // Label each cell with its column name: on phones the rows are shown as cards (CSS uses data-label).
          createdRow: function (row) {
              const headers = Array.from(document.querySelectorAll('#TasksTable thead th')).map((th) => th.textContent.trim());
              row.querySelectorAll('td').forEach((td, i) => { td.dataset.label = headers[i] || ''; });
          },
          language: {
              emptyTable: 'No analysis yet. Submit a file to start.',
              zeroRecords: 'No analysis matches this search.',
              search: 'Search:',
              info: 'Showing <strong>_START_–_END_</strong> of <strong>_TOTAL_</strong> analyses',
              // Pandora pagination (theme.css "Pagination"): icon + word for previous / next, icons for first / last
              paginate: {
                  first: '<svg class="bi" width="14" height="14" fill="currentColor" aria-hidden="true"><use href="/bootstrap/static/icons/bootstrap-icons.svg#chevron-double-left"/></svg><span class="visually-hidden">First page</span>',
                  previous: '<svg class="bi" width="14" height="14" fill="currentColor" aria-hidden="true"><use href="/bootstrap/static/icons/bootstrap-icons.svg#chevron-left"/></svg><span class="pdr-page-word">Previous</span>',
                  next: '<span class="pdr-page-word">Next</span><svg class="bi" width="14" height="14" fill="currentColor" aria-hidden="true"><use href="/bootstrap/static/icons/bootstrap-icons.svg#chevron-right"/></svg>',
                  last: '<svg class="bi" width="14" height="14" fill="currentColor" aria-hidden="true"><use href="/bootstrap/static/icons/bootstrap-icons.svg#chevron-double-right"/></svg><span class="visually-hidden">Last page</span>'
              },
              infoEmpty: 'No analysis',
              lengthMenu: '_MENU_ per page',
              // Placeholder rows while the first page loads (shape of the table, not a spinner)
              loadingRecords: '<div class="pdr-skeleton" aria-busy="true">' +
                  '<span class="pdr-skel-line"></span><span class="pdr-skel-line w-80"></span>' +
                  '<span class="pdr-skel-line w-60"></span><span class="pdr-skel-line w-80"></span>' +
                  '<span class="pdr-skel-line"></span><span class="pdr-skel-line w-60"></span></div>',
              // Page change / search: the animated Pandora box instead of the default dots (template in tasks.html)
              processing: (document.getElementById('pdr-table-loading') || {innerHTML: 'Loading…'}).innerHTML
          },
        })
    }
}

document.addEventListener("DOMContentLoaded", () => {
    renderTables();
});
