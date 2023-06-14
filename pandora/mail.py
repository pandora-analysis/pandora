import smtplib
import ssl

from email.message import EmailMessage
from typing import Optional


from .default import get_config
from .exceptions import Unsupported


class Mail:
    @staticmethod
    def send(subject: str, message: str, reply_to: Optional[str]=None) -> bool:
        """
        Try to send a mail.
        :param (str) subject: email subject
        :param (str) message: email text content
        :param (str) from_address: valid email address
        :param (list) to_addresses: list of recipient emails
        :param (str) smtp_host: SMTP server host
        :param (int) smtp_port: SMTP server port
        :return (bool): whether if email has been correctly sent
        """
        email_config = get_config('generic', 'email')
        smtp_auth = get_config('generic', 'email_smtp_auth')

        if not subject:
            raise Unsupported('subject cannot be empty')

        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = email_config['from']
        msg['To'] = ', '.join(email_config['to'])
        if reply_to:
            msg['Reply-to'] = reply_to
        msg.set_content(message)

        try:
            with smtplib.SMTP(host=email_config['smtp_host'], port=email_config['smtp_port']) as server:
                if smtp_auth['auth']:
                    if 'smtp_use_tls' in smtp_auth:
                        print('please change the config name from smtp_use_tls to smtp_use_starttls')
                    if smtp_auth.get('smtp_use_tls') is True or smtp_auth['smtp_use_starttls']:
                        if smtp_auth['verify_certificate'] is False:
                            ssl_context = ssl.create_default_context()
                            ssl_context.check_hostname = False
                            ssl_context.verify_mode = ssl.CERT_NONE
                            server.starttls(context=ssl_context)
                        else:
                            server.starttls()
                    server.login(smtp_auth['smtp_user'], smtp_auth['smtp_pass'])
                server.send_message(msg)
        except smtplib.SMTPException:
            return False
        return True
