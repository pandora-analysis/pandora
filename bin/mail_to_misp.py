#!/usr/bin/env python

from __future__ import annotations

import email
import logging
import logging.config
import ssl
import time

from email.message import EmailMessage, Message
from email import policy
from io import BytesIO
from smtplib import SMTP

from imapclient import imapclient, IMAPClient  # type: ignore

from pymisp import PyMISP, MISPAttribute, MISPEvent


from pandora.default import AbstractManager, get_config, ConfigError, get_homedir
from pandora.pandora import Pandora
from pandora.task import Task
from pandora.user import User

logging.config.dictConfig(get_config('logging'))

"""
This script needs a dedicated configuration file in the config directory.
See config/misptest_local.json.sample for an example.

You need to pass the name of that file to the MailToMISP class in the main method below.

Example: the file name is misptest_local.json, you will call MailToMISP('misptest_local')

The email_template_path must point to a file in the config directory.
"""


def main() -> None:
    f = MailToMISP('misptest_local')
    f.run(sleep_in_sec=10)


class MailToMISP(AbstractManager):

    def __init__(self, configname: str, loglevel: int | None=None) -> None:
        super().__init__(loglevel)
        self.configname = configname
        self.script_name = f'MailToMISP_{self.configname}'
        self.imap_server = get_config(self.configname, 'imap_server')
        self.imap_login = get_config(self.configname, 'imap_login')
        self.imap_password = get_config(self.configname, 'imap_password')
        self.imap_folder = get_config(self.configname, 'imap_folder')
        if not self.imap_server or not self.imap_login or not self.imap_password:
            raise ConfigError(f'Missing configuration for Mail to MISP {self.configname}.')
        self.pandora = Pandora()

        # Prepare MISP submitter
        misp_settings = get_config(self.configname, 'misp')
        self.misp = PyMISP(misp_settings['url'], misp_settings['apikey'], ssl=misp_settings['tls_verify'])
        self.misp_autopublish = misp_settings.get('auto_publish')

        self.timeout = 60

        self.redis_queue = f'mail_to_misp:{self.configname}'

    def _to_run_forever(self) -> None:
        self._imap_fetcher()
        self._misp_submitter()
        self._email_responder()

    def _prepare_reply(self, reply_config: dict[str, str], initial_message: Message, permaurl: str, permaurl_misp: str) -> EmailMessage | None:
        msg = EmailMessage()
        msg['From'] = reply_config['from']
        if initial_message.get('reply-to'):
            msg['to'] = initial_message['reply-to']
        else:
            msg['To'] = initial_message['from']
        msg['subject'] = f'Re: {initial_message["subject"]}'
        msg['message-id'] = initial_message['message-id']
        recipient = msg['to']
        if recipient.addresses[0].username == reply_config['from']:
            # this is going to cause a loop.
            self.logger.warning(f'The recipient if the same as the sender ({recipient.addresses[0].username}), do not send a reply')
            return None
        try:
            if recipient.addresses[0].display_name:
                recipient = recipient.addresses[0].display_name
        except Exception as e:
            self.logger.warning(e)

        with (get_homedir() / reply_config['email_template_path']).open() as f:
            template = f.read()
        body = template.format(recipient=recipient, permaurl=permaurl,
                               permaurl_misp=permaurl_misp,
                               sender=msg['From'].addresses[0].display_name)
        msg.set_content(body)
        return msg

    def _imap_fetcher(self) -> None:
        self.logger.debug('fetching mails...')
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        with IMAPClient(host=self.imap_server, ssl_context=ssl_context) as client:
            client.login(self.imap_login, self.imap_password)
            client.select_folder(self.imap_folder, readonly=False)

            messages = client.search("UNSEEN")
            # FIXME: make that cleaner
            user = User('email_submitter', last_ip='127.0.0.1', name='email')
            user.store()
            for uid, message_data in client.fetch(messages, "RFC822").items():
                self.logger.info('Processing new mail...')
                email_message = email.message_from_bytes(message_data[b"RFC822"], policy=policy.default)
                # TODO: Add disabled workers? set filename to some identifier?
                new_task = Task.new_task(user=user, sample=BytesIO(email_message.as_bytes()),
                                         disabled_workers=[],
                                         filename=f'{email_message["subject"]}.eml'
                                         )
                self.pandora.enqueue_task(new_task)
                client.add_flags(uid, ('\\Seen'))
                self.pandora.redis.zadd(self.redis_queue, {new_task.uuid: time.time()})
                self.pandora.redis.hset(f'{self.redis_queue}:{new_task.uuid}', 'email_uid', uid)

    def _task_on_misp(self, internal_ref: str) -> bool:
        attributes = self.misp.search('attributes', value=internal_ref, limit=1, page=1, pythonify=True)
        if not attributes or not isinstance(attributes, list) or not isinstance(attributes[0], MISPAttribute):
            return False
        return True

    def _misp_submitter(self) -> None:
        for task_uuid, rank in self.pandora.redis.zscan_iter(self.redis_queue):
            task: Task = self.pandora.get_task(task_uuid)
            if not task.workers_done:
                # task is still ongoing
                continue
            if not self._task_on_misp(task_uuid):
                # task is not on misp yet
                events = task.misp_export(with_extracted_tasks=True)
                root_event = events[0]
                new_root_event = self.misp.add_event(root_event, pythonify=True)
                if not isinstance(new_root_event, MISPEvent):
                    self.logger.warning(f'Unable to add root event to MISP: {new_root_event}')
                    self.pandora.redis.zrem(self.redis_queue, task_uuid)
                    self.pandora.redis.delete(f'{self.redis_queue}:{task_uuid}')
                else:
                    to_publish = [new_root_event]
                    self.logger.info(f'Root event {new_root_event.uuid} added to MISP.')
                    for event in events[1:]:
                        new_event = self.misp.add_event(event, pythonify=True)
                        if not isinstance(new_event, MISPEvent):
                            self.logger.warning(f'Unable to add event to MISP: {new_event}')
                        else:
                            to_publish.append(new_event)
                            self.logger.info(f'Event {new_event.uuid} added to MISP.')
                    if self.misp_autopublish:
                        for event in to_publish:
                            self.misp.publish(event.uuid)
                    self.pandora.redis.hset(f'{self.redis_queue}:{task_uuid}', 'misp_uuid', new_root_event.uuid)

    def _email_responder(self) -> None:
        reply_config = get_config(self.configname, 'reply')
        smtp_server = reply_config['smtp_server']
        smtp_port = reply_config['smtp_port']
        if not smtp_server:
            smtp_server = self.imap_server
        smtp_requires_login = reply_config['smtp_requires_login']
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        for task_uuid, rank in self.pandora.redis.zscan_iter(self.redis_queue):
            task: Task = self.pandora.get_task(task_uuid)
            if not task.workers_done:
                # task is still ongoing
                continue

            seed, _ = self.pandora.seed.add(task_uuid, '0')
            domain = get_config('generic', 'public_url')
            permaurl = f'{domain}/analysis/{task_uuid}/seed-{seed}'
            if misp_uuid := self.pandora.redis.hget(f'{self.redis_queue}:{task_uuid}', 'misp_uuid'):
                permaurl_misp = f'{self.misp.root_url}/events/view/{misp_uuid}'
            else:
                permaurl_misp = ''

            submitted_file = task.file.data
            if not submitted_file:
                # NOTE: This should really not happen
                self.logger.critical(f'Unable to get the mail for task {task_uuid}')
                self.pandora.redis.zrem(self.redis_queue, task_uuid)
                self.pandora.redis.delete(f'{self.redis_queue}:{task_uuid}')
                continue
            email_message = email.message_from_bytes(submitted_file.getvalue(), policy=policy.default)

            reply = self._prepare_reply(reply_config, email_message, permaurl, permaurl_misp)

            with IMAPClient(host=self.imap_server, ssl_context=ssl_context) as client:
                client.login(self.imap_login, self.imap_password)
                client.select_folder(self.imap_folder, readonly=False)
                if reply:
                    try:
                        with SMTP(smtp_server, port=smtp_port) as smtp:
                            if smtp_requires_login:
                                smtp.starttls(context=ssl_context)
                                smtp.login(self.imap_login, self.imap_password)
                            smtp.send_message(reply)
                    except Exception as e:
                        self.logger.exception(e)
                        self.logger.warning(reply.as_string())
                    sent_dir = client.find_special_folder(imapclient.SENT)
                    if sent_dir:
                        client.append(sent_dir, reply.as_string())
                if email_uid := self.pandora.redis.hget(f'{self.redis_queue}:{task_uuid}', 'email_uid'):
                    client.add_flags(email_uid, ('\\Answered'))
            self.pandora.redis.zrem(self.redis_queue, task_uuid)
            self.pandora.redis.delete(f'{self.redis_queue}:{task_uuid}')

        self.logger.debug('Done with responding to mails.')


if __name__ == '__main__':
    main()
