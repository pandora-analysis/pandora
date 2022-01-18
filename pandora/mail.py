import smtplib

from email.message import EmailMessage

from .default import get_config


class Mail:
    @staticmethod
    def send(subject: str, message: str) -> bool:
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

        assert subject, 'subject cannot be empty'

        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = email_config['from']
        msg['To'] = ', '.join(email_config['to'])
        msg.set_content(message)

        try:
            server = smtplib.SMTP(host=email_config['smtp_host'], port=email_config['smtp_port'])
            server.send_message(msg)
            server.quit()
        except smtplib.SMTPException:
            return False
        else:
            return True
