#!/usr/bin/env python3
import functools
import traceback

from io import BytesIO
from typing import Dict

from flask import request, url_for
import flask_login  # type: ignore
from flask_restx import Namespace, Resource  # type: ignore

from pandora.default import get_config, PandoraException
from pandora.pandora import Pandora
from pandora.mail import Mail
from pandora.role import Action
from pandora.task import Task
from pandora.helpers import roles_from_config, workers

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


@api.route('/role/<action>', methods=['POST'], strict_slashes=False)
@api.doc(description='Update or reload roles')
class ApiRole(Resource):

    @admin_required
    @json_answer
    def post(self, action):
        data: Dict[str, str] = request.get_json()  # type: ignore

        assert action in ('update', 'reload'), f"unknown action '{action}'"
        if action == 'update' and flask_login.current_user.role.can(Action.update_role):
            assert 'role_name' in data, "missing mandatory key 'role_name'"
            assert 'permission' in data, "missing mandatory key 'permission'"
            assert 'value' in data, "missing mandatory key 'value'"
            role = pandora.get_role(data['role_name'])
            role.actions[Action[data['permission']]] = bool(int(data['value']))
            role.store
            return {'success': True}

        if action == 'reload' and flask_login.current_user.role.can(Action.update_role):
            for role in roles_from_config().values():
                role.store
            return {'success': True}

        raise AssertionError('forbidden')


@api.route('/submit', methods=['POST'], strict_slashes=False)
class ApiSubmit(Resource):

    @json_answer
    def post(self):
        assert flask_login.current_user.role.can(Action.submit_file), 'forbidden'
        submitted_file = request.files['file']
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
        return {'success': True, 'taskId': task.uuid}


@api.route('/task-action/<task_id>/<action>',
           '/task-action/<task_id>/seed-<seed>/<action>', methods=['POST'], strict_slashes=False)
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
