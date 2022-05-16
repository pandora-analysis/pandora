#!/usr/bin/env python3
import functools
import traceback

from collections import defaultdict
from datetime import datetime, timedelta, time
from io import BytesIO
from typing import Dict, List, Tuple

import flask_login  # type: ignore

from dateutil import rrule
from flask import request, url_for
from flask_restx import Namespace, Resource  # type: ignore
from werkzeug.datastructures import FileStorage

from pandora.default import get_config, PandoraException
from pandora.pandora import Pandora
from pandora.mail import Mail
from pandora.role import Action
from pandora.task import Task
from pandora.helpers import roles_from_config, workers, Status

from .helpers import admin_required, update_user_role

API_LOG_TRACEBACK = get_config('generic', 'debug_web')
API_VERBOSE_JSON = get_config('generic', 'debug_web')

pandora: Pandora = Pandora()
api = Namespace('PandoraAPI', description='Pandora API', path='/')


@api.route('/redis_up')
@api.doc(description='Check if redis is up and running')
class RedisUp(Resource):

    def get(self):
        return pandora.check_redis_up()


def json_answer(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            res = func(*args, **kwargs)
        except AssertionError as e:
            err = str(e) if API_VERBOSE_JSON else None
            return {'success': False, 'error': err}, 400
        except BaseException as e:
            if API_LOG_TRACEBACK:
                traceback.print_exc()
            err = repr(e) if API_VERBOSE_JSON else None
            return {'success': False, 'error': err}, 400
        else:
            return res

    return wrapper


@api.route('/role/<action>', methods=['POST'], strict_slashes=False, doc=False)
@api.doc(description='Update or reload roles')
class ApiRole(Resource):

    @admin_required
    @json_answer
    def post(self, action):

        assert action in ('update', 'reload'), f"unknown action '{action}'"
        if action == 'update' and flask_login.current_user.role.can(Action.update_role):
            data: Dict[str, str] = request.get_json()  # type: ignore
            assert 'role_name' in data, "missing mandatory key 'role_name'"
            assert 'permission' in data, "missing mandatory key 'permission'"
            assert 'value' in data, "missing mandatory key 'value'"
            role = pandora.get_role(data['role_name'])
            role.actions[Action[data['permission']]] = bool(int(data['value']))
            role.store()
            return {'success': True}

        if action == 'reload' and flask_login.current_user.role.can(Action.update_role):
            for role in roles_from_config().values():
                role.store()
            return {'success': True}

        raise AssertionError('forbidden')


upload_parser = api.parser()
upload_parser.add_argument('file', location='files',
                           type=FileStorage, required=True,
                           help="The file you want to analyze")
upload_parser.add_argument('validity', type=int, required=False,
                           location='args',
                           help="Number of seconds the seed will be valid (0 means forever, empty doesn't create a seed).")


@api.route('/submit', methods=['POST'], strict_slashes=False)
@api.expect(upload_parser)
class ApiSubmit(Resource):

    @json_answer
    def post(self):
        assert flask_login.current_user.role.can(Action.submit_file), 'forbidden'
        args = upload_parser.parse_args(request)
        submitted_file = args['file']
        assert submitted_file.filename, 'file required'

        file_bytes = BytesIO(submitted_file.read())
        # check if file is empty. Do not run any worker if it is the case.
        if file_bytes.getvalue().strip() == b'':
            disabled_workers = list(workers())
        disabled_workers = request.form["workersDisabled"].split(",") if request.form.get("workersDisabled") else []
        try:
            task = Task.new_task(flask_login.current_user, sample=file_bytes,
                                 filename=submitted_file.filename,
                                 disabled_workers=disabled_workers)
        except PandoraException as e:
            return {'success': False, 'error': str(e)}, 400
        pandora.enqueue_task(task)
        if args.get('validity'):
            seed, expire = pandora.add_seed(task, args['validity'])
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
                           help="Do you want details about the report status of every worker ? If yes, print 1, else print 0")


@api.route('/task_status', methods=['GET'], strict_slashes=False)
@api.expect(status_parser)
class ApiTaskStatus(Resource):

    @json_answer
    def get(self):
        args = status_parser.parse_args(request)
        task_id = args['task_id']
        seed = args['seed'] if args.get('seed') else None
        details = True if args.get('details') else False
        task = pandora.get_task(task_id=task_id)
        update_user_role(pandora, task, seed)
        assert flask_login.current_user.role.can(Action.read_analysis), 'forbidden'
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
                           help="Do you want the details of every workers ? If yes, print 1, else print 0")
worker_parser.add_argument('worker_name', required=False,
                           location='args',
                           help="The name of the worker you want to get the report of")
worker_parser.add_argument('details', type=int, required=False,
                           location='args',
                           help="Do you want the details of the worker status ? If yes, print 1, else print 0")


@api.route('/worker_status', methods=['GET'], strict_slashes=False)
@api.expect(worker_parser)
class ApiWorkerDetails(Resource):

    @json_answer
    def get(self):
        args = worker_parser.parse_args(request)
        task_id = args['task_id']
        seed = args['seed'] if args.get('seed') else None
        worker_name = args['worker_name'] if args.get('worker_name') else None
        details = True if args.get('details') else False
        all_workers = True if args.get('all_workers') else False

        if not any(worker_name, all_workers):
            return {'error': 'either all_workers must be set, or we need a worker name'}

        task = pandora.get_task(task_id=task_id)
        update_user_role(pandora, task, seed)
        assert flask_login.current_user.role.can(Action.read_analysis), 'forbidden'
        to_return = {}
        if all_workers:
            for r in task.reports.values():
                to_return[r.worker_name] = {'status': r.status.name}
                if details:
                    to_return[r.worker_name]['details'] = r.details
        else:
            # FIXME: this will fail if the worker_name is incorrect and doesn't exists.
            report = pandora.get_report(task_id, worker_name)
            to_return[report.worker_name] = {'status': report.status.name}
            if details:
                to_return[report.worker_name]['details'] = report.details
        return to_return


# TODO: make that different endpoints.
@api.route('/task-action/<task_id>/<action>',
           '/task-action/<task_id>/seed-<seed>/<action>', methods=['POST'],
           strict_slashes=False, doc=False)
class ApiTaskAction(Resource):

    @json_answer
    def post(self, task_id, action, seed=None):
        assert action in ('refresh', 'share', 'notify', 'rescan', 'delete'), f"unexpected action '{action}'"
        task = pandora.get_task(task_id=task_id)
        assert task is not None, 'analysis not found'
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
            data: Dict[str, str] = request.get_json()  # type: ignore
            assert 'validity' in data, "missing mandatory argument 'validity'"
            seed, expire = pandora.add_seed(task, data['validity'])
            link = url_for('api_analysis', task_id=task.uuid, seed=seed)
            return {'success': True, 'seed': seed, 'lifetime': expire, 'link': link}

        if action == 'notify' and flask_login.current_user.role.can(Action.notify_cert):
            data: Dict[str, str] = request.get_json()  # type: ignore
            assert 'email' in data, "missing mandatory argument 'email'"
            assert 'message' in data, "missing mandatory argument 'message'"
            message = '\n'.join([
                f'-- Message from {data["email"]} --',
                f'-- Page {url_for("api_analysis", task_id=task.uuid, seed=seed)} --',
                '',
                data['message']
            ])
            sent = Mail.send(
                subject='Pandora - Analysis Notify',
                message=message,
            )
            assert sent, "an error has occurred when trying to send message"
            return {'success': True}

        if action == 'rescan' and flask_login.current_user.role.can(Action.rescan_file):
            # Here we create a brand new task.
            try:
                new_task = Task.new_task(flask_login.current_user,
                                         sample=task.file.data,
                                         filename=task.file.original_filename,
                                         disabled_workers=task.disabled_workers)
            except PandoraException as e:
                return {'success': False, 'error': str(e)}, 400
            pandora.enqueue_task(new_task)
            link = url_for('api_analysis', task_id=new_task.uuid)
            return {'success': True, 'task_id': new_task.uuid, 'link': link}

        if action == 'delete' and flask_login.current_user.role.can(Action.delete_file):
            task.file.delete()
            task.file.store
            return {'success': True}

        raise AssertionError('forbidden')


# Add stats related API stuff
def check_year(year):
    """
    check numeric string year validity and return None if not valid or -1 if '-1' is sent
    :param year: string numeric
    :return: int
    """
    if year == '-1':
        return -1
    try:
        year_ = int(year)
        if year_ > 2100 or year_ < 1990:
            return
        else:
            return year_
    except ValueError:
        return


def _intervals(freq: int, first: datetime, last: datetime) -> List[Tuple[datetime, datetime]]:
    to_return = []
    if freq in [rrule.MONTHLY, rrule.WEEKLY, rrule.DAILY]:
        first = datetime.combine(first.date(), time.min)
        last = datetime.combine(last.date(), time.max)
    elif freq == rrule.HOURLY:
        first = first.replace(minute=0, second=0, microsecond=0)
        last = first.replace(minute=59, second=59, microsecond=999999)

    if freq == rrule.MONTHLY:
        dates = rrule.rrule(freq, bymonthday=1, dtstart=first, until=last)
    elif freq == rrule.WEEKLY:
        dates = rrule.rrule(freq, byweekday=0, dtstart=first, until=last)
    elif freq == rrule.DAILY:
        dates = rrule.rrule(freq, byhour=0, dtstart=first, until=last)
    elif freq == rrule.HOURLY:
        dates = rrule.rrule(freq, byminute=0, dtstart=first, until=last)

    begin = dates[0]
    for dt in dates[1:]:
        to_return.append((begin, dt))
        begin = dt
    to_return.append((begin, last))
    return to_return


@api.route('/api/stats/submit/year',
           '/api/stats/submit/year/<string:year>', methods=['GET'],
           strict_slashes=False)
class ApiSubmitStatsYear(Resource):

    @json_answer
    def get(self, year="-1"):
        last_date = datetime.now()
        first_date = last_date.replace(month=1, day=1)
        to_return = {'date_start': first_date.date().isoformat(),
                     'date_end': last_date.date().isoformat(),
                     'sub_months': []}
        for first, last in _intervals(rrule.MONTHLY, first_date, last_date):
            tasks = pandora.storage.get_tasks(first_date=first.timestamp(), last_date=last.timestamp())
            to_return['sub_months'].append((first.month, len(tasks)))
        to_return['total'] = sum(number for _, number in to_return['sub_months'])
        return to_return


@api.route('/api/stats/year',
           '/api/stats/year/<string:year>', methods=['GET'],
           strict_slashes=False)
class ApiStatsYear(Resource):

    @json_answer
    def get(self, year="-1"):
        last_date = datetime.now()
        first_date = last_date.replace(month=1, day=1)
        to_return = {'date_start': first_date.date().isoformat(),
                     'date_end': last_date.date().isoformat()}
        # NOTE: the actual source of the submission isn't stored yet.
        to_return['submit'] = defaultdict(int)
        to_return['file'] = defaultdict(int)
        to_return['metrics'] = defaultdict()
        to_return['submit_size'] = {'min': 0, 'max': 0, 'avg': 0}
        nb_alert = 0
        for first, last in _intervals(rrule.MONTHLY, first_date, last_date):
            tasks = pandora.storage.get_tasks(first_date=first.timestamp(), last_date=last.timestamp())
            to_return['submit']['unknown'] += len(tasks)
            to_return['submit']['total'] += len(tasks)
            for t in tasks:
                task = Task(**t)
                to_return['file'][task.file.mime_type] += 1
                to_return['submit_size']['min'] = min(to_return['submit_size']['min'], task.file.size)
                to_return['submit_size']['max'] = max(to_return['submit_size']['max'], task.file.size)
                to_return['submit_size']['avg'] += task.file.size
                if task.status >= Status.WARN:
                    nb_alert += 1
        to_return['submit_size']['avg'] = to_return['submit_size']['avg'] / to_return['submit']['total']
        to_return['metrics']['submits'] = to_return['submit']['total']
        to_return['metrics']['malicious'] = nb_alert
        to_return['metrics']['alert_ratio'] = nb_alert / to_return['submit']['total'] * 100
        return to_return


@api.route('/api/stats/submit/week',
           '/api/stats/submit/week/<string:week>',
           '/api/stats/submit/week/<string:week>/<string:year>', methods=['GET'],
           strict_slashes=False)
class ApiSubmitStatsWeek(Resource):

    @json_answer
    def get(self, year="-1", week="-1"):
        last_date = datetime.now()
        first_date = last_date - timedelta(days=datetime.today().weekday() % 7)
        to_return = {'date_start': first_date.date().isoformat(),
                     'date_end': last_date.date().isoformat(),
                     'sub_days': []}
        for first, last in _intervals(rrule.DAILY, first_date, last_date):
            tasks = pandora.storage.get_tasks(first_date=first.timestamp(), last_date=last.timestamp())
            to_return['sub_days'].append((first.isocalendar().weekday, len(tasks)))
        to_return['total'] = sum(number for _, number in to_return['sub_days'])
        return to_return


@api.route('/api/stats/week',
           '/api/stats/week/<string:week>',
           '/api/stats/week/<string:week>/<string:year>', methods=['GET'],
           strict_slashes=False)
class ApiStatsWeek(Resource):

    @json_answer
    def get(self, year="-1", week="-1"):
        last_date = datetime.now()
        first_date = last_date - timedelta(days=datetime.today().weekday() % 7)
        to_return = {'date_start': first_date.date().isoformat(),
                     'date_end': last_date.date().isoformat()}
        # NOTE: the actual source of the submission isn't stored yet.
        to_return['submit'] = defaultdict(int)
        to_return['file'] = defaultdict(int)
        to_return['metrics'] = defaultdict()
        to_return['submit_size'] = {'min': 0, 'max': 0, 'avg': 0}
        nb_alert = 0
        for first, last in _intervals(rrule.WEEKLY, first_date, last_date):
            if first.year != last_date.year:
                continue
            tasks = pandora.storage.get_tasks(first_date=first.timestamp(), last_date=last.timestamp())
            to_return['submit']['unknown'] += len(tasks)
            to_return['submit']['total'] += len(tasks)
            for t in tasks:
                task = Task(**t)
                to_return['file'][task.file.mime_type] += 1
                to_return['submit_size']['min'] = min(to_return['submit_size']['min'], task.file.size)
                to_return['submit_size']['max'] = max(to_return['submit_size']['max'], task.file.size)
                to_return['submit_size']['avg'] += task.file.size
                if task.status >= Status.WARN:
                    nb_alert += 1
        to_return['submit_size']['avg'] = to_return['submit_size']['avg'] / to_return['submit']['total']
        to_return['metrics']['submits'] = to_return['submit']['total']
        to_return['metrics']['malicious'] = nb_alert
        to_return['metrics']['alert_ratio'] = nb_alert / to_return['submit']['total'] * 100
        return to_return


@api.route('/api/stats/submit/month',
           '/api/stats/submit/month/<string:month>',
           '/api/stats/submit/month/<string:month>/<string:year>', methods=['GET'],
           strict_slashes=False)
class ApiSubmitStatsMonth(Resource):

    @json_answer
    def get(self, year="-1", month="-1"):
        last_date = datetime.now()
        first_date = last_date.replace(day=1)
        to_return = {'date_start': first_date.date().isoformat(),
                     'date_end': last_date.date().isoformat(),
                     'sub_weeks': []}
        for first, last in _intervals(rrule.DAILY, first_date, last_date):
            if first.year != last_date.year:
                continue
            tasks = pandora.storage.get_tasks(first_date=first.timestamp(), last_date=last.timestamp())
            to_return['sub_weeks'].append((first.day, len(tasks)))
        to_return['total'] = sum(number for _, number in to_return['sub_weeks'])
        return to_return


@api.route('/api/stats/month',
           '/api/stats/month/<string:month>',
           '/api/stats/month/<string:month>/<string:year>', methods=['GET'],
           strict_slashes=False)
class ApiStatsMonth(Resource):

    @json_answer
    def get(self, year="-1", month="-1"):
        last_date = datetime.now()
        first_date = last_date.replace(day=1)
        to_return = {'date_start': first_date.date().isoformat(),
                     'date_end': last_date.date().isoformat()}
        # NOTE: the actual source of the submission isn't stored yet.
        to_return['submit'] = defaultdict(int)
        to_return['file'] = defaultdict(int)
        to_return['metrics'] = defaultdict()
        to_return['submit_size'] = {'min': 0, 'max': 0, 'avg': 0}
        nb_alert = 0
        for first, last in _intervals(rrule.DAILY, first_date, last_date):
            if first.year != last_date.year:
                continue
            tasks = pandora.storage.get_tasks(first_date=first.timestamp(), last_date=last.timestamp())
            to_return['submit']['unknown'] += len(tasks)
            to_return['submit']['total'] += len(tasks)
            for t in tasks:
                task = Task(**t)
                to_return['file'][task.file.mime_type] += 1
                to_return['submit_size']['min'] = min(to_return['submit_size']['min'], task.file.size)
                to_return['submit_size']['max'] = max(to_return['submit_size']['max'], task.file.size)
                to_return['submit_size']['avg'] += task.file.size
                if task.status >= Status.WARN:
                    nb_alert += 1
        to_return['submit_size']['avg'] = to_return['submit_size']['avg'] / to_return['submit']['total']
        to_return['metrics']['submits'] = to_return['submit']['total']
        to_return['metrics']['malicious'] = nb_alert
        to_return['metrics']['alert_ratio'] = nb_alert / to_return['submit']['total'] * 100
        return to_return
