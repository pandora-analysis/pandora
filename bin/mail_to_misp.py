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


from pandora.default import AbstractManager, get_config, ConfigError
from pandora.helpers import get_email_template
from pandora.pandora import Pandora
from pandora.task import Task
from pandora.user import User

logging.config.dictConfig(get_config('logging'))


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
        self.smtp_server = get_config(self.configname, 'smtp_server')
        self.smtp_port = get_config(self.configname, 'smtp_port')
        if not self.smtp_server:
            self.smtp_server = self.imap_server
        self.smtp_requires_login = get_config(self.configname, 'smtp_requires_login')
        self.pandora = Pandora()

        # Prepare MISP submitter
        misp_settings = get_config(self.configname, 'misp')
        self.misp = PyMISP(misp_settings['url'], misp_settings['apikey'], ssl=misp_settings['tls_verify'])
        self.misp_autopublish = misp_settings['autosubmit'].get('autopublish')

        self.timeout = 60

        self.redis_queue = f'mail_to_misp:{self.configname}'

    def _to_run_forever(self) -> None:
        self._imap_fetcher()
        self._misp_submitter()
        self._email_responder()

    def _prepare_reply(self, initial_message: Message, permaurl: str, permaurl_misp: str) -> EmailMessage | None:
        msg = EmailMessage()
        msg['From'] = get_config(self.configname, 'from')
        if initial_message.get('reply-to'):
            msg['to'] = initial_message['reply-to']
        else:
            msg['To'] = initial_message['from']
        msg['subject'] = f'Re: {initial_message["subject"]}'
        msg['message-id'] = initial_message['message-id']
        body = get_email_template(self.configname)
        recipient = msg['to']
        if recipient.addresses[0].username == get_config(self.configname, 'from'):
            # this is going to cause a loop.
            self.logger.warning(f'The recipient if the same as the sender ({recipient.addresses[0].username}), do not send a reply')
            return None
        try:
            if recipient.addresses[0].display_name:
                recipient = recipient.addresses[0].display_name
        except Exception as e:
            self.logger.warning(e)
        body = body.format(recipient=recipient, permaurl=permaurl,
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
                event = task.misp_export()
                new_event = self.misp.add_event(event, pythonify=True)
                if not isinstance(new_event, MISPEvent):
                    self.logger.warning(f'Unable to add event to MISP: {new_event}')
                    # NOTE: tell the user something went wrong
                    self.pandora.redis.zrem(self.redis_queue, task_uuid)
                    self.pandora.redis.delete(f'{self.redis_queue}:{task_uuid}')
                else:
                    self.logger.info(f'Event {new_event.uuid} added to MISP.')
                    self.pandora.redis.hset(f'{self.redis_queue}:{task_uuid}', 'misp_uuid', new_event.uuid)
                    if self.misp_autopublish:
                        self.misp.publish(new_event)

    def _email_responder(self) -> None:
        # At this stage, all the tasks have been processed.
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
                # This should really not happen
                self.logger.critical(f'Unable to get the mail for task {task_uuid}')
                continue
            email_message = email.message_from_bytes(submitted_file.getvalue(), policy=policy.default)

            reply = self._prepare_reply(email_message, permaurl, permaurl_misp)

            with IMAPClient(host=self.imap_server, ssl_context=ssl_context) as client:
                if reply:
                    try:
                        with SMTP(self.smtp_server, port=self.smtp_port) as smtp:
                            if self.smtp_requires_login:
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

        self.logger.debug('Done with responding to mails.')


def main() -> None:
    if not get_config('generic', 'enable_imap_fetcher'):
        print('IMAP fetcher is disabled in config, quitting.')
        return

    f = MailToMISP('testing')
    f.run(sleep_in_sec=10)


if __name__ == '__main__':
    main()
