#!/usr/bin/env python

import email
import logging
import ssl

from email.message import EmailMessage
from email import policy
from io import BytesIO
from smtplib import SMTP
from typing import Optional

from imapclient import imapclient, IMAPClient  # type: ignore

from pandora.default import AbstractManager, get_config, ConfigError
from pandora.helpers import get_email_template
from pandora.pandora import Pandora
from pandora.task import Task
from pandora.user import User


class IMAPFetcher(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'imap_fetcher'
        self.imap_server = get_config('mail', 'imap_server')
        self.imap_login = get_config('mail', 'imap_login')
        self.imap_password = get_config('mail', 'imap_password')
        self.imap_folder = get_config('mail', 'imap_folder')
        if not self.imap_server or not self.imap_login or not self.imap_password:
            raise ConfigError('Missing configuration for the IMAP fetcher.')
        self.smtp_server = get_config('mail', 'smtp_server')
        self.smtp_port = get_config('mail', 'smtp_port')
        if not self.smtp_server:
            self.smtp_server = self.imap_server
        self.smtp_requires_login = get_config('mail', 'smtp_requires_login')
        self.pandora = Pandora()
        # FIXME: make that cleaner
        self.user = User('email_submitter', last_ip='127.0.0.1', name='email')
        self.user.store

    def _to_run_forever(self):
        self._imap_fetcher()

    def _prepare_reply(self, initial_message: EmailMessage, permaurl: str) -> Optional[EmailMessage]:
        msg = EmailMessage()
        msg['From'] = get_config('mail', 'from')
        if initial_message.get('reply-to'):
            msg['to'] = initial_message['reply-to']
        else:
            msg['To'] = initial_message['from']
        msg['subject'] = f'Re: {initial_message["subject"]}'
        msg['message-id'] = initial_message['message-id']
        body = get_email_template()
        recipient = msg['to']
        if recipient.addresses[0].username == get_config('mail', 'from'):
            # this is going to cause a loop.
            return None
        try:
            if recipient.addresses[0].display_name:
                recipient = recipient.addresses[0].display_name
        except Exception as e:
            self.logger.warning(e)
        sender = get_config('mail', 'from')
        body = body.format(recipient=recipient, permaurl=permaurl,
                           sender=sender)
        msg.set_content(body)
        return msg

    def _imap_fetcher(self):
        self.logger.info('fetching mails...')
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        with IMAPClient(host=self.imap_server, ssl_context=ssl_context) as client:
            client.login(self.imap_login, self.imap_password)
            client.select_folder(self.imap_folder, readonly=False)

            messages = client.search("UNSEEN")
            for uid, message_data in client.fetch(messages, "RFC822").items():
                email_message = email.message_from_bytes(message_data[b"RFC822"], policy=policy.default)
                # TODO: Add disabled workers? set filename to some identifier?
                new_task = Task.new_task(user=self.user, sample=BytesIO(email_message.as_bytes()),
                                         disabled_workers=[],
                                         filename=f'{email_message["subject"]}.eml'
                                         )
                self.pandora.enqueue_task(new_task)
                client.add_flags(uid, ('\\Seen'))

                seed, _ = self.pandora.add_seed(new_task, '0')
                domain = get_config('generic', 'public_url')
                permaurl = f'{domain}/analysis/{new_task.uuid}/seed-{seed}'
                reply = self._prepare_reply(email_message, permaurl)

                if reply:
                    try:
                        with SMTP(self.smtp_server, port=self.smtp_port) as smtp:
                            if self.smtp_requires_login:
                                smtp.login(self.imap_login, self.imap_password)
                            smtp.send_message(reply)
                    except Exception as e:
                        self.logger.exception(e)
                        self.logger.warning(reply.as_string())
                    sent_dir = client.find_special_folder(imapclient.SENT)
                    if sent_dir:
                        client.append(sent_dir, reply.as_string())
                client.add_flags(uid, ('\\Answered'))

        self.logger.info('Done with fetching mails.')


def main():
    if not get_config('generic', 'enable_imap_fetcher'):
        print('IMAP fetcher is disabled in config, quitting.')
        return

    f = IMAPFetcher()
    f.run(sleep_in_sec=10)


if __name__ == '__main__':
    main()
