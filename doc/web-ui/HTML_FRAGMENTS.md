# Endpoints that return HTML fragments

The web interface fetches these and injects the HTML as is (`innerHTML`); the frontend does not parse it.
Moving them to JSON would let the frontend render them itself (and keep the layout in one place).
Listed November 2026, during the web UI rework (PR #1055).

| # | Route (GET unless noted) | Returns | Used by | Data a JSON version would need |
|---|---|---|---|---|
| 1 | `/previews/<task_id>` (+ `/seed-<seed>`) | `previews.html`: the page images (viewer with arrows / thumbnails) | `analysis.js` `refreshTabs()` → `#previews_images` | number of pages (or a list of image URLs), maybe page sizes; the image URLs exist already (`/task-download/<id>/img/<idx>`) |
| 2 | `/observables/<task_id>` (+ seed) | `observables_list.html`: table of observables | `analysis.js` → `#observables_content` | per observable: `type`, `value`, `status`, `sha256`, warning lists (names); plus `lookyloo_url` |
| 3 | `/extracted/<task_id>` (+ seed) | `extracted.html`: table of extracted files | `analysis.js` → `#extracted_content` | per extracted task: `uuid`, `file_original_name`, `file_icon` (or mime type), `file_size`, `file_sha256`, `status`, `save_date` (ISO) |
| 4 | `/workers_results_html/<task_id>/<worker_name>` (+ seed) | one module's result (`<worker>.html` or `default_worker.html`) | `analysis.js` → appended into `#workers_results_<status>` | worker `name`, `description`, `status`, `details` (dict), `extras` (e.g. `no_password` for the extractor), and for some workers a link (`permaurl`) |
| 5 | `POST /tables/tasksTable/` | JSON, but with **HTML strings** in `status.display`, `name.display`, `buttons.display` (inline templates in `website/web/__init__.py`) | DataTables in `render_tables.js` | `status` (name), `file_icon` / mime type, `original_filename`, `deleted`, `report_url`, `delete_url`, `file_uuid`, and whether the user is admin |

Also worth knowing:

- `POST /task-action/<task_id>/refresh` (JSON) drives the live updates; the page then calls 1–4 above to get the HTML.
  If 1–4 became JSON, `refresh` could return everything in one call.
