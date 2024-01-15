#!/usr/bin/env python3

from __future__ import annotations

import functools
import json
import logging
import logging.config
import operator

from collections import defaultdict
from datetime import datetime, timedelta
import email.utils
from importlib.metadata import version
from io import BytesIO
from pathlib import Path
from typing import Any, Callable

import flask_moment  # type: ignore
import flask_login  # type: ignore
import flask_wtf  # type: ignore
import pyzipper  # type: ignore

from flask import (Flask, request, session, abort, render_template,
                   redirect, send_file, url_for, flash, Request)
from flask_restx import Api  # type: ignore
from flask_bootstrap import Bootstrap5  # type: ignore
from pymisp import MISPEvent, PyMISP  # type: ignore[attr-defined]
from pymisp.abstract import describe_types
from werkzeug.security import check_password_hash
from werkzeug.exceptions import Forbidden
from werkzeug import Response as WerkzeugResponse

from pandora.default import get_config, PandoraException, get_homedir
from pandora.exceptions import Unsupported
from pandora.helpers import workers, Status, get_disclaimers
from pandora.pandora import Pandora
from pandora.role import Action
from pandora.user import User

from .generic_api import api as generic_api
from .helpers import (get_secret_key, update_user_role, admin_required,
                      src_request_ip, load_user_from_request, build_users_table,
                      sri_load, sizeof_fmt)
from .proxied import ReverseProxied
from .redisserverssession import Session

logging.config.dictConfig(get_config('logging'))
pandora: Pandora = Pandora()

app: Flask = Flask(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)  # type: ignore

app.config['SECRET_KEY'] = get_secret_key()
app.config['UPLOAD_FOLDER'] = get_homedir() / 'upload'
app.config['CACHE_TYPE'] = 'simple'
app.config['SESSION_REDIS'] = pandora.redis_bytes
app.config['SESSION_KEY_PREFIX'] = 'pandora_session:'

if not app.template_folder:
    raise PandoraException('Folder template not defined')
template_dir: Path = Path(app.root_path) / app.template_folder

Bootstrap5(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.debug = get_config('generic', 'debug_web')

app.config['SESSION_COOKIE_NAME'] = 'pandora'
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
Session(app=app)
login_manager = flask_login.LoginManager(app=app)
flask_moment.Moment(app=app)

app.config['WTF_CSRF_CHECK_DEFAULT'] = False
csrf = flask_wtf.CSRFProtect(app=app)


# Query API

authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    }
}

api = Api(title='Pandora API',
          description='API to query Pandora.',
          doc='/doc/',
          authorizations=authorizations,
          version=version('pandora'))

api.add_namespace(generic_api)


def default_icon() -> str:
    return 'question'


status_icons = defaultdict(default_icon, {
    Status.OVERWRITE: 'question-octagon',
    Status.ERROR: 'exclamation-octagon',
    Status.ALERT: 'x-circle',
    Status.WARN: 'exclamation-triangle',
    Status.CLEAN: 'check-circle'
})


@app.context_processor
def inject_enums() -> dict[str, Any]:
    '''All the templates have the Action and Status enum'''
    return {"action": Action, "status": Status, "status_icons": status_icons}

# ##### Global methods passed to jinja


def get_sri(directory: str, filename: str) -> str:
    sha512 = functools.reduce(operator.getitem, directory.split('/'), sri_load())[filename]  # type: ignore
    return f'sha512-{sha512}'


app.jinja_env.globals.update(get_sri=get_sri)
app.jinja_env.globals.update(sizeof_fmt=sizeof_fmt)


@login_manager.user_loader  # type: ignore[misc]
def load_user(user_id: str) -> User | None:
    return pandora.get_user(user_id)


@login_manager.request_loader  # type: ignore[misc]
def _load_user_from_request(req: Request) -> User | None:
    user_name = load_user_from_request(req)
    if user_name:
        if last_ip := src_request_ip(req):
            return User(session.sid, last_ip=last_ip, name=user_name, role='admin')  # type: ignore[attr-defined]
        raise Exception('No IP in request Oo.')
    return None


@app.before_request
def update_user() -> None:
    if (user := _load_user_from_request(request)):
        flask_login.login_user(user)
    elif flask_login.current_user.is_authenticated:
        if flask_login.current_user.name:
            # If the user doesn't have a name, it is session based, no need to check
            csrf.protect()
        flask_login.current_user.last_ip = src_request_ip(request)
        flask_login.current_user.last_seen = datetime.now()
        flask_login.current_user.store()
    else:
        # Note: session.sid comes from the redis session
        user = User(session_id=session.sid, last_ip=src_request_ip(request))  # type: ignore
        user.store()
        flask_login.login_user(user)


@app.template_filter()
def to_datetime(iso: str) -> datetime:
    return datetime.fromisoformat(str(iso)) if iso else datetime.now()


def html_answer(func) -> Callable[..., Any]:  # type: ignore[no-untyped-def]
    @functools.wraps(func)
    def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
        try:
            res = func(*args, **kwargs)
        except (PandoraException, Exception):
            logging.exception('Error in Web call.')
            return abort(404)
        return res

    return wrapper


@app.errorhandler(404)
def api_error_404(_) -> tuple[str, int]:  # type: ignore[no-untyped-def]
    return render_template('error.html',
                           show_project_page=get_config('generic', 'show_project_page'),
                           status=404), 404


@app.errorhandler(403)
def api_error_403(_) -> tuple[str, int]:  # type: ignore[no-untyped-def]
    return render_template('error.html',
                           show_project_page=get_config('generic', 'show_project_page'),
                           status=403), 403


@app.route('/', strict_slashes=False)
def api_root() -> Any:
    if request.method == 'HEAD':
        # Just returns ack if the webserver is running
        return 'Ack'
    return redirect(url_for('api_submit_page'), 301)


@app.route('/toggle_detailed_view', methods=['POST'], strict_slashes=False)
def api_toggle_detailed_view() -> str:
    try:
        flask_login.current_user.toggle_detailed_view()
        flask_login.current_user.store()
        return json.dumps(True)
    except Exception as e:
        logging.warning(f'Unable to toggle view: {e}')
        return json.dumps(False)


@app.route('/submit', methods=['GET'], strict_slashes=False)
@html_answer
def api_submit_page() -> str:
    if not flask_login.current_user.role.can(Action.submit_file):
        raise Forbidden('User not allowed to submit a file')
    enaled_workers = pandora.get_enabled_workers()
    disclaimers = get_disclaimers()
    return render_template(
        'submit.html', error=request.args.get('error', ''),
        show_project_page=get_config('generic', 'show_project_page'),
        max_file_size=get_config('generic', 'max_file_size'),
        workers={worker_name: config for worker_name, config in workers().items() if worker_name in enaled_workers},
        generic_disclaimer=disclaimers['disclaimer'],
        special_disclaimer=disclaimers['special_disclaimer']
    )


@app.route('/analysis/<task_id>', methods=['GET'], strict_slashes=False)
@app.route('/analysis/<task_id>/seed-<seed>', methods=['GET'], strict_slashes=False)
@html_answer
def api_analysis(task_id: str, seed: str | None=None) -> str:
    task = pandora.get_task(task_id=task_id)
    if not task:
        raise PandoraException('analysis not found')

    update_user_role(pandora, task, seed)
    if not flask_login.current_user.role.can(Action.read_analysis):
        raise Forbidden('Not allowed to read the report')

    task.linked_tasks = []  # type: ignore[assignment]

    if hasattr(task, 'parent') and task.parent and seed and not pandora.is_seed_valid(task.parent, seed):
        task.parent = None

    email_config = get_config('generic', 'email')
    admin_name = ''
    if 'to' in email_config and email_config['to']:
        admin_name, _ = email.utils.parseaddr(email_config['to'][0])
    if not admin_name:
        admin_name = 'Administrator'

    return render_template('analysis.html', task=task, seed=seed,
                           zip_passwd=get_config('generic', 'sample_password'),
                           default_share_time=get_config('generic', 'default_share_time'),
                           show_project_page=get_config('generic', 'show_project_page'),
                           admin_name=admin_name)


@app.route('/task-misp-submit/<task_id>', methods=['GET'], strict_slashes=False)
@app.route('/task-misp-submit/<task_id>/seed-<seed>', methods=['GET'], strict_slashes=False)
@html_answer
def task_misp_submit(task_id: str, seed: str | None=None) -> WerkzeugResponse:
    task = pandora.get_task(task_id=task_id)
    if not task:
        raise PandoraException('analysis not found')
    update_user_role(pandora, task, seed)

    if not flask_login.current_user.role.can(Action.submit_to_misp):
        raise Forbidden('Not allowed to submit the report to MISP')

    event: MISPEvent = task.misp_export()
    misp_settings = get_config('generic', 'misp')
    pymisp = PyMISP(misp_settings['url'], misp_settings['apikey'], ssl=misp_settings['tls_verify'])
    pymisp.add_event(event)
    flash('Task successfully submitted to MISP', 'success')
    return redirect(url_for('api_analysis', task_id=task_id, seed=seed))


@app.route('/task-download/<task_id>/seed-<seed>/<source>', methods=['GET'], strict_slashes=False)
@app.route('/task-download/<task_id>/seed-<seed>/<source>/<int:idx>', methods=['GET'], strict_slashes=False)
@app.route('/task-download/<task_id>/<source>', methods=['GET'], strict_slashes=False)
@app.route('/task-download/<task_id>/<source>/<int:idx>', methods=['GET'], strict_slashes=False)
@html_answer
def api_task_download(task_id: str, source: str, seed: str | None=None, idx: int | None=None) -> WerkzeugResponse:
    if source not in ('img', 'pdf', 'txt', 'zip', 'txt_preview', 'misp'):
        raise Unsupported(f"unexpected source '{source}'")
    task = pandora.get_task(task_id=task_id)
    if not task:
        raise PandoraException('analysis not found')
    update_user_role(pandora, task, seed)

    if source == 'img' and flask_login.current_user.role.can(Action.download_images):
        if not task.file.previews:
            raise PandoraException('content not available')
        if idx is not None:
            return send_file(task.file.previews[idx])
        if task.file.previews_archive:
            return send_file(task.file.previews_archive)

    if source == 'pdf' and flask_login.current_user.role.can(Action.download_pdf):
        # NOTE: need to also return a PDF of office doc.
        if not task.file.is_pdf:
            raise Unsupported('PDF not available')
        return send_file(task.file.path)

    if source == 'txt' and flask_login.current_user.role.can(Action.download_text):
        if not task.file.text:
            raise Unsupported('text content not available')
        return send_file(BytesIO(task.file.text.encode()), download_name=f'{task.file.path.name}.txt', mimetype='plain/text')

    if source == 'txt_preview' and flask_login.current_user.role.can(Action.see_text_preview):
        return send_file(task.file.text_preview, download_name=f'{task.file.path.name}.png', mimetype='image/png')

    if source == 'zip' and flask_login.current_user.role.can(Action.download_zip):
        # download the original file, zipped, with password
        to_return = BytesIO()
        with pyzipper.AESZipFile(to_return, 'w', encryption=pyzipper.WZ_AES) as archive:
            archive.setpassword(get_config('generic', 'sample_password').encode())
            if task.file.data:
                archive.writestr(task.file.original_filename, task.file.data.getvalue())
        to_return.seek(0)
        return send_file(to_return, download_name=f'{task.file.path.name}.zip')

    if source == 'misp' and flask_login.current_user.role.can(Action.download_misp):
        event = task.misp_export()
        return send_file(BytesIO(event.to_json().encode()), download_name=f'{task.uuid}.json', mimetype='application/json', as_attachment=True)

    raise Forbidden('You do not have the right to get {source}')


@app.route('/admin/<int:error>', methods=['GET'], strict_slashes=False)
@app.route('/admin', methods=['GET'], strict_slashes=False)
@html_answer
def api_admin_page(error: int | None=None) -> str:
    error_messages: dict[int, str] = {1: 'Invalid Credentials', 2: 'Unable to initialize credentials, see logs.'}
    if error is not None:
        msg = error_messages.get(error, 'Unknown error')
    else:
        msg = 'Unknown error'
    return render_template('admin.html',
                           show_project_page=get_config('generic', 'show_project_page'),
                           error=msg)


@app.route('/admin', methods=['POST'], strict_slashes=False)
@html_answer
def api_admin_submit() -> WerkzeugResponse:
    if flask_login.current_user.is_admin:
        return redirect(url_for('api_admin_page'))

    try:
        if 'username' not in request.form:
            raise Unsupported("missing mandatory key 'username'")
        if 'password' not in request.form:
            raise Unsupported("missing mandatory key 'password'")
        try:
            users_table = build_users_table()
        except Exception:
            logging.exception('Failed to load the users.')
            return redirect(url_for('api_admin_page', error=2), 302)
        username = request.form['username']
        if username in users_table and check_password_hash(users_table[username]['password'], request.form['password']):
            flask_login.current_user.name = username
            flask_login.current_user.role = pandora.get_role('admin')
            flask_login.current_user.store()
            flask_login.login_user(flask_login.current_user)
            return redirect(url_for('api_admin_page'))
        return redirect(url_for('api_admin_page', error=1), 302)

    except PandoraException:
        return redirect(url_for('api_admin_page', error=1), 302)


@app.route('/admin/logout', methods=['GET'], strict_slashes=False)
@html_answer
def api_logout() -> WerkzeugResponse:
    flask_login.logout_user()
    flask_login.current_user.name = None
    session.clear()
    return redirect(url_for('api_root'), 302)


@app.route('/tasks', methods=['GET'], strict_slashes=False)
@html_answer
def api_tasks() -> str:

    if not flask_login.current_user.role.can([Action.list_own_tasks, Action.list_all_tasks], 'or'):
        raise Forbidden('Not allowed to list tasks')
    search = request.args.get('query')
    search = search.strip() if search is not None else None
    if not search:
        # filter results by date, keep last 3 days,
        # TODO: up to a max amount of tasks
        first_date: datetime | int = datetime.now() - timedelta(days=get_config('generic', 'max_days_index'))
    else:
        # FIXME: This will be slow and the way to search must be improved.
        first_date = 0
    tasks = pandora.get_tasks(user=flask_login.current_user, first_date=first_date)
    if search:
        filtered_tasks = []
        # filter results
        for task in tasks:
            if flask_login.current_user.role.can(Action.search_file_hash):
                if search in [task.file.md5, task.file.sha1, task.file.sha256]:
                    filtered_tasks.append(task)
                    continue
            if flask_login.current_user.role.can(Action.search_file_name):
                if [name for name in [task.file.original_filename, task.file.path.name] if search in name]:
                    filtered_tasks.append(task)
                    continue
        tasks = filtered_tasks
    return render_template('tasks.html', tasks=tasks, search=search or '',
                           show_project_page=get_config('generic', 'show_project_page'),
                           status=Status)


@app.route('/users', methods=['GET'], strict_slashes=False)
@admin_required
@html_answer
def api_users() -> str:

    if not flask_login.current_user.role.can(Action.list_users):
        raise Forbidden('Not allowed to list users')
    users = pandora.get_users()
    return render_template('users.html',
                           show_project_page=get_config('generic', 'show_project_page'),
                           users=users)


@app.route('/users/clear', methods=['GET'], strict_slashes=False)
@admin_required
@html_answer
def api_clear_users() -> WerkzeugResponse:

    if not flask_login.current_user.role.can(Action.list_users):
        raise Forbidden('Not allowed to list users')
    pandora.storage.del_users()
    return redirect(url_for('api_submit_page'))


@app.route('/roles', methods=['GET'], strict_slashes=False)
@admin_required
@html_answer
def api_roles() -> str:

    if not flask_login.current_user.role.can(Action.list_roles):
        raise Forbidden('Not allowed to list roles')
    roles = pandora.get_roles()
    return render_template('roles.html',
                           show_project_page=get_config('generic', 'show_project_page'),
                           roles=roles)


@app.route('/observables_lists', methods=['GET'], strict_slashes=False)
@admin_required
@html_answer
def observables_lists() -> str:

    if not flask_login.current_user.role.can(Action.manage_observables_lists):
        raise Forbidden('Not allowed to manage observables list')
    suspicious = pandora.get_suspicious_observables()
    legitimate = pandora.get_legitimate_observables()
    observable_types = [t for t in describe_types['types'] if '|' not in t]
    return render_template('observables_lists.html',
                           show_project_page=get_config('generic', 'show_project_page'),
                           types=observable_types, suspicious=suspicious, legitimate=legitimate)


@app.route('/observables_lists/insert', methods=['POST'], strict_slashes=False)
@admin_required
@html_answer
def observables_lists_insert() -> WerkzeugResponse:

    data = request.form
    if 'observable' not in data:
        raise Unsupported("missing mandatory key 'observable'")
    if 'type' not in data:
        raise Unsupported("missing mandatory key 'type'")
    if data['type'].strip() not in [t for t in describe_types['types'] if '|' not in t]:
        raise Unsupported(f"invalid type: {data['type'].strip()}")
    if 'list_type' not in data:
        raise Unsupported("missing mandatory key 'list_type'")
    if int(data['list_type']) == 0:
        pandora.add_legitimate_observable(data['observable'].strip(), data['type'].strip())
    else:
        pandora.add_suspicious_observable(data['observable'].strip(), data['type'].strip())
    return redirect(url_for('observables_lists'))


@app.route('/observables_lists/delete/<int:list_type>/<string:observable>', strict_slashes=False)
@admin_required
@html_answer
def observables_lists_delete(list_type: int, observable: str) -> WerkzeugResponse:
    if list_type == 0:
        pandora.delete_legitimate_observable(observable.strip())
    else:
        pandora.delete_suspicious_observable(observable.strip())
    return redirect(url_for('observables_lists'))


@app.route('/previews/<task_id>', methods=['GET'], strict_slashes=False)
@app.route('/previews/<task_id>/seed-<seed>', methods=['GET'], strict_slashes=False)
@html_answer
def html_previews(task_id: str, seed: str | None=None) -> str:
    task = pandora.get_task(task_id=task_id)
    if not task:
        raise PandoraException('analysis not found')
    update_user_role(pandora, task, seed)
    if not flask_login.current_user.role.can(Action.download_images):
        raise Forbidden('Not allowed to download images')
    report = pandora.get_report(task_id, 'preview')
    return render_template('previews.html', task=task, seed=seed, report=report)


@app.route('/observables/<task_id>', methods=['GET'], strict_slashes=False)
@app.route('/observables/<task_id>/seed-<seed>', methods=['GET'], strict_slashes=False)
@html_answer
def html_observables(task_id: str, seed: str | None=None) -> str:
    task = pandora.get_task(task_id=task_id)
    if not task:
        raise PandoraException('analysis not found')
    update_user_role(pandora, task, seed)
    return render_template('observables_list.html',
                           lookyloo_url=get_config('generic', 'lookyloo_url'),
                           task=task, seed=seed)


@app.route('/extracted/<task_id>', methods=['GET'], strict_slashes=False)
@app.route('/extracted/<task_id>/seed-<seed>', methods=['GET'], strict_slashes=False)
@html_answer
def html_extracted(task_id: str, seed: str | None=None) -> str:
    task = pandora.get_task(task_id=task_id)
    if not task:
        raise PandoraException('analysis not found')
    update_user_role(pandora, task, seed)
    report = pandora.get_report(task_id, 'extractor')
    return render_template('extracted.html', task=task, seed=seed, report=report)


@app.route('/workers_results_html/<task_id>/<worker_name>', methods=['GET'], strict_slashes=False)
@app.route('/workers_results_html/<task_id>/<worker_name>/seed-<seed>', methods=['GET'], strict_slashes=False)
@html_answer
def html_workers_result(task_id: str, worker_name: str, seed: str | None=None) -> str:
    task = pandora.get_task(task_id=task_id)
    if not task:
        raise PandoraException('analysis not found')
    if worker_name not in workers():
        raise Unsupported(f'unknown worker name: {worker_name}')
    update_user_role(pandora, task, seed)
    if not flask_login.current_user.role.can(Action.read_analysis):
        raise Forbidden('Not allowed to read the report')
    report = pandora.get_report(task_id, worker_name)
    if (template_dir / f'{worker_name}.html').exists():
        template_file = f'{worker_name}.html'
    else:
        template_file = 'default_worker.html'
    return render_template(template_file,
                           worker_name=worker_name,
                           worker_meta=workers()[worker_name]['meta'],
                           task=task, seed=seed, report=report)


@app.route('/manual_trigger_worker/<task_id>/<worker_name>', methods=['GET'], strict_slashes=False)
@app.route('/manual_trigger_worker/<task_id>/<worker_name>/seed-<seed>', methods=['GET'], strict_slashes=False)
@html_answer
def manual_trigger_worker(task_id: str, worker_name: str, seed: str | None=None) -> WerkzeugResponse:
    task = pandora.get_task(task_id=task_id)
    if not task:
        raise PandoraException('analysis not found')
    if worker_name not in workers():
        raise Unsupported(f'unknown worker name: {worker_name}')
    update_user_role(pandora, task, seed)
    if not flask_login.current_user.role.can(Action.read_analysis):
        raise Forbidden('Not allowed to read the report')
    pandora.trigger_manual_worker(task, worker_name)
    return redirect(url_for('api_analysis', task_id=task_id, seed=seed))


@app.route('/stats', methods=['GET'], strict_slashes=False)
@admin_required
@html_answer
def api_stats() -> str:
    if not flask_login.current_user.role.can(Action.list_stats):
        raise Forbidden('Not allowed to show stats')
    return render_template('stats.html',
                           show_project_page=get_config('generic', 'show_project_page'))


# NOTE: this one must be at the end, it adds a route to / that will break the default one.
api.init_app(app)
