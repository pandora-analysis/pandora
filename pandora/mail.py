import smtplib

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
            server = smtplib.SMTP(host=email_config['smtp_host'], port=email_config['smtp_port'])
            if smtp_auth['auth']:
                server.login(smtp_auth['smtp_user'], smtp_auth['smtp_pass'])
                if smtp_auth['smtp_use_tls']:
                    server.starttls()
            server.send_message(msg)
            server.quit()
        except smtplib.SMTPException:
            return False
        return True
