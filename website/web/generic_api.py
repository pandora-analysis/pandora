#!/usr/bin/env python3

from __future__ import annotations

import calendar
import functools
import logging
import logging.config

from collections import defaultdict
from datetime import datetime, time, timedelta
from io import BytesIO
from typing import Any, Callable, Literal

import flask_login  # type: ignore

from dateutil import rrule
from flask import request, url_for
from flask_restx import Namespace, Resource, abort  # type: ignore
from werkzeug.datastructures import FileStorage
from werkzeug.security import check_password_hash
from werkzeug.exceptions import Forbidden

from pandora.default import get_config, PandoraException
from pandora.exceptions import Unsupported
from pandora.pandora import Pandora
from pandora.mail import Mail
from pandora.role import Action
from pandora.task import Task
from pandora.file import File
from pandora.helpers import roles_from_config, Status, Seed, email_blocklist

from .helpers import (admin_required, update_user_role, build_users_table,
                      load_user_from_request, sizeof_fmt, src_request_ip)

logging.config.dictConfig(get_config('logging'))

API_VERBOSE_JSON = get_config('generic', 'debug_web')

pandora: Pandora = Pandora()
api = Namespace('PandoraAPI', description='Pandora API', path='/')
seed_manager = Seed()


def api_auth_check(method):  # type: ignore[no-untyped-def]
    if load_user_from_request(request) or flask_login.current_user.is_authenticated:
        return method
    abort(403, 'Authentication required.')


@api.route('/redis_up')
@api.doc(description='Check if redis is up and running')
class RedisUp(Resource):  # type: ignore[misc]

    def get(self) -> bool:
        return pandora.check_redis_up()


def json_answer(func) -> Callable[[str], Any]:  # type: ignore[no-untyped-def]
    @functools.wraps(func)
    def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
        try:
            res = func(*args, **kwargs)
        except PandoraException as e:
            return {'success': False, 'error': str(e)}, 400
        except Forbidden as e:
            return {'success': False, 'error': str(e)}, 403
        except Exception as e:
            logging.exception('Error in API call.')
            err = repr(e) if API_VERBOSE_JSON else 'Not returning the error to the user, the stacktrace is in the logs.'
            return {'success': False, 'error': err}, 400
        return res

    return wrapper


@api.route('/api/get_token')
@api.doc(description='Get the API token required for authenticated calls')
class AuthToken(Resource):  # type: ignore[misc]

    users_table = build_users_table()

    @api.param('username', 'Your username')  # type: ignore[misc]
    @api.param('password', 'Your password')  # type: ignore[misc]
    def get(self) -> dict[str, str] | tuple[dict[str, str], int]:
        username: str = request.args['username'] if request.args.get('username') else ''
        password: str = request.args['password'] if request.args.get('password') else ''
        if username and username in self.users_table and check_password_hash(self.users_table[username]['password'], password):
            return {'authkey': self.users_table[username]['authkey']}
        return {'error': 'User/Password invalid.'}, 401


@api.route('/role/<action>', methods=['POST'], strict_slashes=False, doc=False)
@api.doc(description='Update or reload roles')
class ApiRole(Resource):  # type: ignore[misc]

    @admin_required
    @json_answer
    def post(self, action: str) -> dict[str, bool]:

        if action not in ('update', 'reload'):
            raise Unsupported(f"unknown action '{action}'")
        if not flask_login.current_user.role.can(Action.update_role):
            raise Forbidden("Your user isn't allowed to edit the roles.")
        if action == 'update' and flask_login.current_user.role.can(Action.update_role):
            data: dict[str, str] = request.get_json()
            if 'role_name' not in data:
                raise Unsupported("missing mandatory key 'role_name'")
            if 'permission' not in data:
                raise Unsupported("missing mandatory key 'permission'")
            if 'value' not in data:
                raise Unsupported("missing mandatory key 'value'")
            role = pandora.get_role(data['role_name'])
            role.actions[Action[data['permission']]] = bool(int(data['value']))
            role.store()
            return {'success': True}

        if action == 'reload' and flask_login.current_user.role.can(Action.update_role):
            for role in roles_from_config().values():
                role.store()
            return {'success': True}
        return {'success': False}


upload_parser = api.parser()
upload_parser.add_argument('file', location='files',
                           type=FileStorage, required=True,
                           help="The file you want to analyze")
upload_parser.add_argument('validity', type=int, required=False,
                           location='args',
                           help="Number of seconds the seed will be valid (0 means forever, empty doesn't create a seed).")
upload_parser.add_argument('password', type=str, required=False,
                           location='args',
                           help="User defined password to decrypt the file (generally used for archives).")


@api.route('/submit', methods=['POST'], strict_slashes=False)
@api.expect(upload_parser)
class ApiSubmit(Resource):  # type: ignore[misc]

    @json_answer
    def post(self) -> dict[str, Any] | tuple[dict[str, Any], int]:
        if not flask_login.current_user.role.can(Action.submit_file):
            raise Forbidden('User not allowed to submit a file')
        args = upload_parser.parse_args(request)
        submitted_file = args['file']
        if not submitted_file.filename:
            raise Unsupported('file required')

        file_bytes = BytesIO(submitted_file.read())
        if file_bytes.getvalue().strip() == b'':
            return {'success': False, 'error': 'You attempted to submit an empty file. Wait for the page to reload...'}, 400
        disabled_workers = request.form["workersDisabled"].split(",") if request.form.get("workersDisabled") else []
        password = request.form['password'] if request.form.get('password') else args.get('password')
        try:
            task = Task.new_task(flask_login.current_user, sample=file_bytes,
                                 filename=submitted_file.filename,
                                 password=password,
                                 disabled_workers=disabled_workers)
        except PandoraException as e:
            return {'success': False, 'error': str(e)}, 400
        pandora.enqueue_task(task)
        if args.get('validity') is not None:
            seed, expire = seed_manager.add(task.uuid, args['validity'])
            link = url_for('api_analysis', task_id=task.uuid, seed=seed)
            return {'success': True, 'taskId': task.uuid, 'seed': seed,
                    'lifetime': expire, 'link': link}
        link = url_for('api_analysis', task_id=task.uuid)
        return {'success': True, 'taskId': task.uuid, 'link': link}


status_parser = api.parser()
status_parser.add_argument('task_id', required=True,
                           location='args',
                           help="The id of the task you'd like to get the status of")
status_parser.add_argument('seed', required=False,
                           location='args',
                           help="The seed of the task you'd like to get the status of")
status_parser.add_argument('details', type=int, required=False,
                           location='args',
                           help="Do you want details about the report status of every worker? 1 for yes, 0 for no")


@api.route('/task_status', methods=['GET'], strict_slashes=False)
@api.expect(status_parser)
class ApiTaskStatus(Resource):  # type: ignore[misc]

    @json_answer
    def get(self) -> dict[str, Any] | tuple[dict[str, Any], int]:
        args = status_parser.parse_args(request)
        task_id = args['task_id']
        seed = args['seed'] if args.get('seed') else None
        details = bool(args.get('details'))
        task = pandora.get_task(task_id=task_id)
        update_user_role(pandora, task, seed)
        if not flask_login.current_user.role.can(Action.read_analysis):
            raise Forbidden('Not allowed to read the report')
        to_return = {'success': True, 'taskId': task.uuid, 'status': task.status.name}
        if details:
            to_return['workersStatus'] = task.workers_status
        return to_return


worker_parser = api.parser()
worker_parser.add_argument('task_id', required=True,
                           location='args',
                           help="The id of the task you'd like to get the status of")
worker_parser.add_argument('seed', required=False,
                           location='args',
                           help="The seed of the task you'd like to get the status of")
worker_parser.add_argument('all_workers', type=int, required=False,
                           location='args',
                           help="Do you want details about the report status of every worker? 1 for yes, 0 for no")
worker_parser.add_argument('worker_name', required=False,
                           location='args',
                           help="The name of the worker you want to get the report of")
worker_parser.add_argument('details', type=int, required=False,
                           location='args',
                           help="Do you want details about the report status of every worker? 1 for yes, 0 for no")


@api.route('/worker_status', methods=['GET'], strict_slashes=False)
@api.expect(worker_parser)
class ApiWorkerDetails(Resource):  # type: ignore[misc]

    @json_answer
    def get(self) -> dict[str, Any]:
        args = worker_parser.parse_args(request)
        task_id = args['task_id']
        seed = args['seed'] if args.get('seed') else None
        worker_name: str | None = args['worker_name'] if args.get('worker_name') else None
        details = bool(args.get('details'))
        all_workers = bool(args.get('all_workers'))

        if not any((worker_name, all_workers)):
            return {'error': 'either all_workers must be set, or we need a worker name'}

        task = pandora.get_task(task_id=task_id)
        update_user_role(pandora, task, seed)
        if not flask_login.current_user.role.can(Action.read_analysis):
            raise Forbidden('Not allowed to read the report')
        to_return: dict[str, Any] = {}
        if all_workers:
            for r in task.reports.values():
                to_return[r.worker_name] = {'status': r.status.name}
                if details:
                    to_return[r.worker_name]['details'] = r.details
        elif worker_name:
            report = pandora.get_report(task_id, worker_name)
            to_return[report.worker_name] = {'status': report.status.name}
            if details:
                to_return[report.worker_name]['details'] = report.details
        return to_return


# TODO: make that different endpoints.
@api.route('/task-action/<task_id>/<action>',
           '/task-action/<task_id>/seed-<seed>/<action>', methods=['POST'],
           strict_slashes=False, doc=False)
class ApiTaskAction(Resource):  # type: ignore[misc]

    @json_answer
    def post(self, task_id: str, action: str, seed: str | None=None) -> dict[str, Any] | tuple[dict[str, Any], int]:
        if action not in ('refresh', 'share', 'notify', 'rescan', 'delete'):
            raise Unsupported(f"unexpected action '{action}'")
        task = pandora.get_task(task_id=task_id)
        if not task:
            raise PandoraException('analysis not found')
        update_user_role(pandora, task, seed)

        if action == 'refresh' and flask_login.current_user.role.can(Action.refresh_analysis):
            # task.reports = mysql.get_task_reports(task=task, config=get_config())
            # task.extracted_tasks = mysql.get_tasks(extracted_from=task, user=flask_login.current_user)
            # task.linked_tasks = mysql.get_tasks(linked_with=task, user=flask_login.current_user)
            # task.store()
            return {'success': True, 'task': task.to_dict, 'workers_done': task.workers_done,
                    'seed': seed, 'workers_status': task.workers_status,
                    'number_observables': len(task.observables),
                    'number_extracted': len(task.extracted),
                    'file': task.file.to_web}

        if action == 'share' and flask_login.current_user.role.can(Action.share_analysis):
            data: dict[str, Any] = request.get_json()
            if "validity" not in data:
                data['validity'] = get_config('generic', 'default_share_time')
            seed, expire = seed_manager.add(task.uuid, data['validity'])
            link = url_for('api_analysis', task_id=task.uuid, seed=seed)
            return {'success': True, 'seed': seed, 'lifetime': expire, 'link': link}

        if action == 'notify' and flask_login.current_user.role.can(Action.notify_cert):
            data = request.get_json()
            if 'email' not in data:
                raise Unsupported("missing mandatory key 'email'")
            if data['email'] in email_blocklist():
                # the email address is in the blocklist, silently dropping the request.
                logging.warning(f'IP {src_request_ip(request)} tried to send a notification as {data["email"]} for task {task.uuid} but the email is in the blocklist.')
                return {'success': True}
            if 'message' not in data:
                raise Unsupported("missing mandatory key 'message'")
            if not seed:
                seed = pandora.seed.add(task.uuid, time=90000)[0]  # Just a bit over a day
            domain = get_config('generic', 'public_url')
            permaurl = f'{domain}/analysis/{task.uuid}/seed-{seed}'
            message = '\n'.join([
                f'-- Message from {data["email"]} ({src_request_ip(request)})--',
                f'-- Page {permaurl} --',
                '',
                data['message']
            ])
            sent = Mail.send(
                subject='Pandora - Analysis Notify',
                message=message,
                reply_to=data['email'] if data.get('email') else None
            )
            if not sent:
                raise PandoraException("an error has occurred when trying to send message")
            return {'success': True}

        if action == 'rescan' and flask_login.current_user.role.can(Action.rescan_file):
            try:
                data = request.get_json()
            except Exception:
                data = {}
            # Here we create a brand new task.
            if task.file.data is None:
                return {'success': False, 'error': 'No Data, unable to rescan'}, 400
            try:
                new_task = Task.new_task(flask_login.current_user,
                                         sample=task.file.data,
                                         filename=task.file.original_filename,
                                         password=data.get('password'),
                                         disabled_workers=task.disabled_workers)
            except PandoraException as e:
                return {'success': False, 'error': str(e)}, 400
            pandora.enqueue_task(new_task)
            pubsub_config = get_config('generic', 'channels')
            if pubsub_config['enabled'] and pubsub_config['channel_submission']:
                misp_file_objs = new_task.file.misp_export()
                if misp_file_objs:
                    pandora.publish_on_channel(pubsub_config['channel_submission'], misp_file_objs[0].to_json())
            link = url_for('api_analysis', task_id=new_task.uuid)
            return {'success': True, 'task_id': new_task.uuid, 'link': link}

        if action == 'delete' and flask_login.current_user.role.can(Action.delete_file):
            task.file.delete()
            return {'success': True, 'file_id': task.file.uuid}

        raise Forbidden('You are not allowed to do that')


@api.route('/api/search/<query>',
           '/api/search/<query>/<int:days>', methods=['GET'],
           strict_slashes=False)
@api.doc(description="Search a task by hash or name. The 'days' parameter (10 by default) is there to limit how far in the past we go for the search", security='apikey')
class ApiSearch(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @admin_required
    @json_answer
    def get(self, query: str, days: int=10) -> dict[str, Any]:
        first_date: datetime | int = datetime.now() - timedelta(days=days)
        to_return: dict[str, Any] = {'matching_tasks': []}
        for task in pandora.get_tasks(user=flask_login.current_user, first_date=first_date):
            if (query in [task.file.md5, task.file.sha1, task.file.sha256]
                    or [name for name in [task.file.original_filename, task.file.path.name] if query in name]):
                to_return['matching_tasks'].append(task.uuid)
        return to_return


# Stats related API stuff
def _intervals(freq: Literal[0, 1, 2, 3, 4, 5, 6], first: datetime, last: datetime) -> list[tuple[datetime, datetime]]:
    to_return = []
    first = datetime.combine(first.date(), time.min)
    last = datetime.combine(last.date(), time.max)

    if freq == rrule.MONTHLY:
        dates = rrule.rrule(freq, bymonthday=1, dtstart=first, until=last)
    elif freq == rrule.WEEKLY:
        dates = rrule.rrule(freq, byweekday=0, dtstart=first, until=last)
    elif freq == rrule.DAILY:
        dates = rrule.rrule(freq, byhour=0, dtstart=first, until=last)
    elif freq == rrule.HOURLY:
        dates = rrule.rrule(freq, byminute=0, dtstart=first, until=last)
    else:
        raise Unsupported(f"unsupported frequency '{freq}'")

    begin = dates[0]
    for dt in dates[1:]:
        to_return.append((begin, dt))
        begin = dt
    to_return.append((begin, last))
    return to_return


def _normalize_year(year: str | None) -> tuple[datetime, datetime]:
    if year:
        last_date = datetime(int(year), 12, 31)
    else:
        last_date = datetime.now()
    first_date = last_date.replace(month=1, day=1)
    return first_date, last_date


def _normalize_month(year: str | int | None, month: str | int | None) -> tuple[datetime, datetime]:
    if month:
        if not year:
            year = datetime.now().year
        last_date = datetime(int(year), int(month), calendar.monthrange(int(year), int(month))[1])
    else:
        last_date = datetime.now()
    first_date = last_date.replace(day=1)
    return first_date, last_date


def _normalize_week(year: str | int | None, week: str | int | None) -> tuple[datetime, datetime]:
    if week:
        if not year:
            year = datetime.now().year
        first_date = datetime.fromisocalendar(int(year), int(week), 1)
        last_date = datetime.fromisocalendar(int(year), int(week), 7)
    else:
        now = datetime.now()
        # FIXME Starting in python 3.9, we can do now.isocalendar().week
        first_date = datetime.fromisocalendar(now.year, now.isocalendar()[1], 1)
        last_date = datetime.fromisocalendar(now.year, now.isocalendar()[1], 7)
    return first_date, last_date


def _normalize_day(year: str | int | None, month: str | int | None,
                   day: str | int | None) -> tuple[datetime, datetime]:
    if day:
        if not month:
            month = datetime.now().month
        if not year:
            year = datetime.now().year
        last_date = datetime(int(year), int(month), int(day))
    else:
        last_date = datetime.now()
    return last_date, last_date


@api.route('/api/stats/submit/year',
           '/api/stats/submit/year/<string:year>', methods=['GET'],
           strict_slashes=False)
@api.doc(description="Get the yearly submit stats", security='apikey')
class ApiSubmitStatsYear(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @admin_required
    @json_answer
    def get(self, year: str | None=None) -> dict[str, Any]:
        first_date, last_date = _normalize_year(year)
        to_return: dict[str, Any] = {'date_start': first_date.date().isoformat(),
                                     'date_end': last_date.date().isoformat(),
                                     'sub_months': []}
        for first, last in _intervals(rrule.MONTHLY, first_date, last_date):
            tasks_count = pandora.storage.count_tasks(first_date=first.timestamp(), last_date=last.timestamp())
            to_return['sub_months'].append((first.month, tasks_count))
        to_return['total'] = sum(number for _, number in to_return['sub_months'])
        return to_return


@api.route('/api/stats/submit/month',
           '/api/stats/submit/month/<string:month>',
           '/api/stats/submit/month/<string:month>/<string:year>', methods=['GET'],
           strict_slashes=False)
@api.doc(description="Get the monthly submit stats", security='apikey')
class ApiSubmitStatsMonth(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @admin_required
    @json_answer
    def get(self, year: str | None=None, month: str | None=None) -> dict[str, Any]:
        first_date, last_date = _normalize_month(year, month)
        to_return: dict[str, Any] = {'date_start': first_date.date().isoformat(),
                                     'date_end': last_date.date().isoformat(),
                                     'sub_weeks': []}
        for first, last in _intervals(rrule.DAILY, first_date, last_date):
            tasks_count = pandora.storage.count_tasks(first_date=first.timestamp(), last_date=last.timestamp())
            to_return['sub_weeks'].append((first.day, tasks_count))
        to_return['total'] = sum(number for _, number in to_return['sub_weeks'])
        return to_return


@api.route('/api/stats/submit/week',
           '/api/stats/submit/week/<string:week>',
           '/api/stats/submit/week/<string:week>/<string:year>', methods=['GET'],
           strict_slashes=False)
@api.doc(description="Get the weekly submit stats", security='apikey')
class ApiSubmitStatsWeek(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @admin_required
    @json_answer
    def get(self, year: str | None=None, week: str | None=None) -> dict[str, Any]:
        first_date, last_date = _normalize_week(year, week)
        to_return: dict[str, Any] = {'date_start': first_date.date().isoformat(),
                                     'date_end': last_date.date().isoformat(),
                                     'sub_days': []}
        for first, last in _intervals(rrule.DAILY, first_date, last_date):
            tasks_count = pandora.storage.count_tasks(first_date=first.timestamp(), last_date=last.timestamp())
            to_return['sub_days'].append((first.strftime('%A'), tasks_count))
        to_return['total'] = sum(number for _, number in to_return['sub_days'])
        return to_return


@api.route('/api/stats/submit/day',
           '/api/stats/submit/day/<string:day>',
           '/api/stats/submit/day/<string:day>/<string:month>',
           '/api/stats/submit/day/<string:day>/<string:month>/<string:year>', methods=['GET'],
           strict_slashes=False)
@api.doc(description="Get the daily submit stats", security='apikey')
class ApiSubmitStatsDay(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @admin_required
    @json_answer
    def get(self, year: str | None=None, month: str | None=None, day: str | None=None) -> dict[str, Any]:
        first_date, last_date = _normalize_day(year, month, day)
        to_return: dict[str, Any] = {'date_start': first_date.date().isoformat(),
                                     'date_end': last_date.date().isoformat(),
                                     'sub_hours': []}
        for first, last in _intervals(rrule.HOURLY, first_date, last_date):
            tasks_count = pandora.storage.count_tasks(first_date=first.timestamp(), last_date=last.timestamp())
            to_return['sub_hours'].append((first.hour, tasks_count))
        to_return['total'] = sum(number for _, number in to_return['sub_hours'])
        return to_return


def _stats(intervals: list[tuple[datetime, datetime]]) -> dict[str, Any]:
    to_return: dict[str, Any] = {'date_start': intervals[0][0].date().isoformat(),
                                 'date_end': intervals[-1][1].date().isoformat()}
    # NOTE: the actual source of the submission isn't stored yet.
    to_return['submit'] = defaultdict(int)
    to_return['file'] = defaultdict(int)
    to_return['metrics'] = {'alert_ratio': 0, 'submits': 0, 'malicious': 0, 'suspicious': 0, 'clean': 0, 'overwritten': 0, 'error': 0}
    to_return['submit_size'] = {'min': 0, 'max': 0, 'avg': 0}
    for first, last in intervals:
        tasks = pandora.storage.get_tasks(first_date=first.timestamp(), last_date=last.timestamp())
        to_return['submit']['unknown'] += len(tasks)
        to_return['submit']['total'] += len(tasks)
        for t in tasks:
            f = pandora.storage.get_file(t['file_id'])
            if 'mime_type' not in f or 'size' not in f:
                # old caching format, re-store the thing
                file = File(**f)
                file.store()
                f = pandora.storage.get_file(t['file_id'])
            to_return['file'][f['mime_type']] += 1
            size = int(f['size'])
            to_return['submit_size']['min'] = min(to_return['submit_size']['min'], size)
            to_return['submit_size']['max'] = max(to_return['submit_size']['max'], size)
            to_return['submit_size']['avg'] += size
            if 'status' in t:
                if Status[t['status']] == Status.CLEAN:
                    to_return['metrics']['clean'] += 1
                elif Status[t['status']] == Status.WARN:
                    to_return['metrics']['suspicious'] += 1
                elif Status[t['status']] == Status.ALERT:
                    to_return['metrics']['malicious'] += 1
                elif Status[t['status']] == Status.OVERWRITE:
                    to_return['metrics']['overwritten'] += 1
                elif Status[t['status']] == Status.ERROR:
                    to_return['metrics']['error'] += 1
    nb_alert = to_return['metrics']['malicious'] + to_return['metrics']['suspicious']
    if to_return['submit']['total']:
        to_return['submit_size']['avg'] = sizeof_fmt(to_return['submit_size']['avg'] / to_return['submit']['total'])
        to_return['submit_size']['min'] = sizeof_fmt(to_return['submit_size']['min'])
        to_return['submit_size']['max'] = sizeof_fmt(to_return['submit_size']['max'])
        to_return['metrics']['alert_ratio'] = nb_alert / to_return['submit']['total'] * 100
    to_return['metrics']['submits'] = to_return['submit']['total']
    return to_return


@api.route('/api/stats/year',
           '/api/stats/year/<string:year>', methods=['GET'],
           strict_slashes=False)
@api.doc(description="Get the yearly stats", security='apikey')
class ApiStatsYear(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @admin_required
    @json_answer
    def get(self, year: str | None=None) -> dict[str, Any]:
        first_date, last_date = _normalize_year(year)
        intervals = _intervals(rrule.MONTHLY, first_date, last_date)
        return _stats(intervals)


@api.route('/api/stats/month',
           '/api/stats/month/<string:month>',
           '/api/stats/month/<string:month>/<string:year>', methods=['GET'],
           strict_slashes=False)
@api.doc(description="Get the monthly stats", security='apikey')
class ApiStatsMonth(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @admin_required
    @json_answer
    def get(self, year: str | None=None, month: str | None=None) -> dict[str, Any]:
        first_date, last_date = _normalize_month(year, month)
        intervals = _intervals(rrule.DAILY, first_date, last_date)
        return _stats(intervals)


@api.route('/api/stats/week',
           '/api/stats/week/<string:week>',
           '/api/stats/week/<string:week>/<string:year>', methods=['GET'],
           strict_slashes=False)
@api.doc(description="Get the weekly stats", security='apikey')
class ApiStatsWeek(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @admin_required
    @json_answer
    def get(self, year: str | None=None, week: str | None=None) -> dict[str, Any]:
        first_date, last_date = _normalize_week(year, week)
        intervals = _intervals(rrule.WEEKLY, first_date, last_date)
        return _stats(intervals)


@api.route('/api/stats/day',
           '/api/stats/day/<string:day>',
           '/api/stats/day/<string:day>/<string:month>',
           '/api/stats/day/<string:day>/<string:month>/<string:year>', methods=['GET'],
           strict_slashes=False)
@api.doc(description="Get the daily stats", security='apikey')
class ApiStatsDay(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @admin_required
    @json_answer
    def get(self, year: str | None=None, month: str | None=None, day: str | None=None) -> dict[str, Any]:
        first_date, last_date = _normalize_day(year, month, day)
        intervals = _intervals(rrule.HOURLY, first_date, last_date)
        return _stats(intervals)


@api.route('/api/enabled_workers', methods=['GET'], strict_slashes=False)
@api.doc(description="Get the list of enabled workers")
class ApiEnabledWorkers(Resource):  # type: ignore[misc]

    @json_answer
    def get(self) -> list[str]:
        return list(pandora.get_enabled_workers())


def _workers_stats(intervals: list[tuple[datetime, datetime]]) -> dict[str, Any]:
    to_return: dict[str, Any] = {'date_start': intervals[0][0].date().isoformat(),
                                 'date_end': intervals[-1][1].date().isoformat()}
    to_return['workers_stats'] = {name: defaultdict(dict) for name in pandora.get_enabled_workers()}
    for first, last in intervals:
        tasks = pandora.storage.get_tasks(first_date=first.timestamp(), last_date=last.timestamp())
        for t in tasks:
            f = pandora.storage.get_file(t['file_id'])
            for name in to_return['workers_stats'].keys():
                report = pandora.storage.get_report(t['uuid'], name)
                if not report:
                    continue
                if report['status'] not in to_return['workers_stats'][name][f['mime_type']]:
                    to_return['workers_stats'][name][f['mime_type']][report['status']] = 0
                to_return['workers_stats'][name][f['mime_type']][report['status']] += 1
    return to_return


@api.route('/api/workers_stats/year',
           '/api/workers_stats/year/<string:year>', methods=['GET'],
           strict_slashes=False)
@api.doc(description="Get the yearly stats for each workers", security='apikey')
class ApiWorkersStatsYear(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @admin_required
    @json_answer
    def get(self, year: str | None=None) -> dict[str, Any]:
        first_date, last_date = _normalize_year(year)
        intervals = _intervals(rrule.MONTHLY, first_date, last_date)
        return _workers_stats(intervals)


@api.route('/api/workers_stats/month',
           '/api/workers_stats/month/<string:month>',
           '/api/workers_stats/month/<string:month>/<string:year>', methods=['GET'],
           strict_slashes=False)
@api.doc(description="Get the monthly stats for each workers", security='apikey')
class ApiWorkersStatsMonth(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @admin_required
    @json_answer
    def get(self, year: str | None=None, month: str | None=None) -> dict[str, Any]:
        first_date, last_date = _normalize_month(year, month)
        intervals = _intervals(rrule.DAILY, first_date, last_date)
        return _workers_stats(intervals)


@api.route('/api/workers_stats/week',
           '/api/workers_stats/week/<string:week>',
           '/api/workers_stats/week/<string:week>/<string:year>', methods=['GET'],
           strict_slashes=False)
@api.doc(description="Get the weekly stats for each workers", security='apikey')
class ApiWorkersStatsWeek(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @admin_required
    @json_answer
    def get(self, year: str | None=None, week: str | None=None) -> dict[str, Any]:
        first_date, last_date = _normalize_week(year, week)
        intervals = _intervals(rrule.WEEKLY, first_date, last_date)
        return _workers_stats(intervals)


@api.route('/api/workers_stats/day',
           '/api/workers_stats/day/<string:day>',
           '/api/workers_stats/day/<string:day>/<string:month>',
           '/api/workers_stats/day/<string:day>/<string:month>/<string:year>', methods=['GET'],
           strict_slashes=False)
@api.doc(description="Get the daily stats for each workers", security='apikey')
class ApiWorkersStatsDay(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @admin_required
    @json_answer
    def get(self, year: str | None=None, month: str | None=None, day: str | None=None) -> dict[str, Any]:
        first_date, last_date = _normalize_day(year, month, day)
        intervals = _intervals(rrule.HOURLY, first_date, last_date)
        return _workers_stats(intervals)
