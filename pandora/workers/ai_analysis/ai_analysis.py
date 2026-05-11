#!/usr/bin/env python3

from __future__ import annotations

import logging
import re

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Pattern

from ...helpers import Status
from ...report import Report
from ...task import Task
from ..base import BaseWorker

logger = logging.getLogger(__name__)

SEVERITY_WEIGHT = {'critical': 1.0, 'high': 0.8, 'medium': 0.5, 'low': 0.2}


@dataclass(frozen=True)
class DetectionRule:
    id: str
    category: str
    type: str
    pattern: Pattern[str]
    severity: str
    message: str


RULE_DATA = [
    ('hardcoded_password', 'auth_secrets', 'Hardcoded Password', r'\b(pass(word|wd)?|pwd)\s*[:=]\s*["\'`]([^"\'`\n]{1,64})["\'`]', re.I, 'critical', 'Password written directly into source.'),
    ('weak_password', 'auth_secrets', 'Weak / Common Password', r'["\'`](password|passw0rd|123456|123456789|qwerty|admin|letmein|welcome|iloveyou|P@ssw0rd)["\'`]', re.I, 'critical', 'Weak / common password literal.'),
    ('basic_auth_url', 'auth_secrets', 'Basic Auth in URL', r'\b(?:https?|ftp|ssh)://[A-Za-z0-9._-]+:[^@\s"\'`]+@[A-Za-z0-9.-]+', 0, 'critical', 'Username:password embedded in a URL.'),
    ('bearer_token', 'auth_secrets', 'Bearer Token', r'\bBearer\s+[A-Za-z0-9\-_\.=]{20,}', 0, 'high', 'Bearer token in an Authorization header.'),
    ('session_id', 'auth_secrets', 'Session / Cookie ID', r'\b(session[_\s-]?id|jsessionid|phpsessid|sess[_\s-]?id)\s*[:=]\s*["\'`]?([A-Za-z0-9_\-]{12,})["\'`]?', re.I, 'high', 'Session cookie / ID exposed.'),
    ('openai_key', 'api_keys', 'OpenAI API Key', r'\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b', 0, 'critical', 'OpenAI-style API key.'),
    ('aws_access_key', 'api_keys', 'AWS Access Key ID', r'\bAKIA[0-9A-Z]{16}\b', 0, 'critical', 'AWS Access Key ID.'),
    ('aws_secret_key', 'api_keys', 'AWS Secret Access Key', r'\b(aws[_\-]?secret[_\-]?access[_\-]?key)\s*[:=]\s*["\'`]([A-Za-z0-9/+=]{40})["\'`]', re.I, 'critical', 'AWS Secret Access Key.'),
    ('gcp_key', 'api_keys', 'Google API / GCP Key', r'\bAIza[0-9A-Za-z_\-]{35}\b', 0, 'critical', 'Google API / GCP key.'),
    ('github_token', 'api_keys', 'GitHub Token', r'\bgh[pousr]_[A-Za-z0-9]{30,}\b', 0, 'critical', 'GitHub personal / OAuth token.'),
    ('slack_token', 'api_keys', 'Slack Token', r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b', 0, 'critical', 'Slack API token.'),
    ('stripe_key', 'api_keys', 'Stripe Key', r'\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{16,}\b', 0, 'critical', 'Stripe API key.'),
    ('twilio_sid', 'api_keys', 'Twilio Account SID', r'\bAC[a-f0-9]{32}\b', 0, 'high', 'Twilio Account SID.'),
    ('sendgrid_key', 'api_keys', 'SendGrid Key', r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b', 0, 'critical', 'SendGrid API key.'),
    ('generic_api_key', 'api_keys', 'Generic API Key / Token', r'\b(api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token|client[_-]?secret|token)\s*[:=]\s*["\'`]([A-Za-z0-9_\-]{16,})["\'`]', re.I, 'critical', 'Hardcoded API key / secret / token.'),
    ('private_key_block', 'crypto_keys', 'Private Key (PEM)', r'-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----', 0, 'critical', 'PEM-formatted private key block.'),
    ('ssh_private_key', 'crypto_keys', 'SSH Private Key', r'-----BEGIN OPENSSH PRIVATE KEY-----', 0, 'critical', 'OpenSSH private key.'),
    ('pgp_private_key', 'crypto_keys', 'PGP Private Key', r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 0, 'critical', 'PGP private key block.'),
    ('jwt_token', 'crypto_keys', 'JWT Token', r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b', 0, 'high', 'JSON Web Token.'),
    ('jwt_secret', 'crypto_keys', 'JWT Signing Secret', r'\b(jwt[_\-]?secret|jwt[_\-]?signing[_\-]?key)\s*[:=]\s*["\'`]([A-Za-z0-9_\-]{8,})["\'`]', re.I, 'critical', 'Hardcoded JWT signing secret.'),
    ('cert_block', 'crypto_keys', 'Certificate Block', r'-----BEGIN (?:CERTIFICATE|CERTIFICATE REQUEST)-----', 0, 'low', 'X.509 certificate block.'),
    ('dotenv_value', 'source_secrets', '.env Style Secret', r'^\s*[A-Z][A-Z0-9_]{2,}_(KEY|TOKEN|SECRET|PASSWORD|PWD)\s*=\s*["\'`]?([^\s"\'`]{6,})["\'`]?', re.M, 'critical', '.env-style secret assignment.'),
    ('db_connection_string', 'source_secrets', 'Database Connection String', r'\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|mssql|jdbc:[a-z]+)://[^\s"\'`<>]+', re.I, 'critical', 'Database connection string.'),
    ('config_password_field', 'source_secrets', 'Config Password Field', r'\b(db[_\-]?password|mysql[_\-]?password|postgres[_\-]?password|redis[_\-]?password)\s*[:=]\s*["\'`]?([^"\'`\n]{3,})["\'`]?', re.I, 'critical', 'Database password in config.'),
    ('debug_flag', 'source_secrets', 'Debug Flag Enabled', r'\b(debug|DEBUG)\s*[:=]\s*(true|True|TRUE|1|"true"|\'true\')', 0, 'medium', 'Debug flag enabled.'),
    ('todo_secret', 'source_secrets', 'TODO Secret Note', r'\b(?:TODO|FIXME|HACK)[:\s][^\n]{0,80}(password|secret|key|token)[^\n]*', re.I, 'medium', 'TODO / FIXME comment referencing a secret.'),
    ('credit_card', 'financial', 'Credit Card Number', r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))(?:[ -]?\d{4}){2,3}(?:[ -]?\d{1,4})?\b', 0, 'critical', 'Credit / debit card number.'),
    ('cvv', 'financial', 'CVV / CVC', r'\b(cvv|cvc|cid)\s*[:=]\s*["\'`]?(\d{3,4})["\'`]?', re.I, 'critical', 'Card security code.'),
    ('iban', 'financial', 'IBAN', r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b', 0, 'high', 'International Bank Account Number.'),
    ('routing_number', 'financial', 'US Routing Number', r'\b(routing[_\s-]?number|aba)\s*[:=]\s*["\'`]?(\d{9})["\'`]?', re.I, 'high', 'US bank routing number.'),
    ('bank_account', 'financial', 'Bank Account Number', r'\b(account[_\s-]?number|acct[_\s-]?num|bank[_\s-]?account)\s*[:=]\s*["\'`]?(\d{6,17})["\'`]?', re.I, 'high', 'Bank account number.'),
    ('swift_bic', 'financial', 'SWIFT / BIC', r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b', 0, 'medium', 'SWIFT / BIC code.'),
    ('ssn_us', 'direct_id', 'US Social Security Number', r'\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b', 0, 'critical', 'US Social Security Number.'),
    ('passport', 'direct_id', 'Passport Number', r'\bpassport\s*(?:no\.?|number|#)?\s*[:=]?\s*([A-Z]?\d{6,9})\b', re.I, 'high', 'Passport number.'),
    ('drivers_license', 'direct_id', "Driver's License", r'\b(?:driver\'?s?\s*(?:license|licence)|DL|DLN)\s*[:#=]?\s*([A-Z0-9]{6,15})\b', re.I, 'high', "Driver's license number."),
    ('national_id', 'direct_id', 'National ID', r'\b(national[_\s-]?id|aadhaar|nric|pan[_\s-]?number|nin)\s*[:=]\s*["\'`]?([A-Z0-9]{6,16})["\'`]?', re.I, 'high', 'National identification number.'),
    ('full_name_labeled', 'direct_id', 'Full Name (labeled)', r'\b(?:full[_\s-]?name|customer[_\s-]?name|first[_\s-]?name|last[_\s-]?name)\s*[:=]\s*["\'`]([^"\'`\n]{2,64})["\'`]', re.I, 'medium', 'Personal name in a labeled field.'),
    ('dob', 'indirect_id', 'Date of Birth', r'\b(?:dob|date[_\s-]?of[_\s-]?birth|birth[_\s-]?date|birthday)\s*[:=]?\s*["\'`]?(\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4}|\d{4}-\d{2}-\d{2})["\'`]?', re.I, 'medium', 'Date of birth.'),
    ('zip_code', 'indirect_id', 'Postal / ZIP Code', r'\b(?:zip(?:code)?|postal[_\s-]?code|post[_\s-]?code)\s*[:=]\s*["\'`]?(\d{5}(?:-\d{4})?|[A-Z]\d[A-Z]\s?\d[A-Z]\d)["\'`]?', re.I, 'low', 'Postal / ZIP code in labeled field.'),
    ('age', 'indirect_id', 'Age', r'\bage\s*[:=]\s*["\'`]?(\d{1,3})["\'`]?', re.I, 'low', 'Age in a labeled field.'),
    ('gender', 'indirect_id', 'Gender', r'\bgender\s*[:=]\s*["\'`]?(male|female|non[\s-]?binary|m|f|nb|other)["\'`]?', re.I, 'low', 'Gender in a labeled field.'),
    ('marital_status', 'indirect_id', 'Marital Status', r'\bmarital[_\s-]?status\s*[:=]\s*["\'`]?(single|married|divorced|widowed|separated)["\'`]?', re.I, 'low', 'Marital status.'),
    ('religion', 'sensitive', 'Religion', r'\breligion\s*[:=]\s*["\'`]?([A-Za-z]{3,32})["\'`]?', re.I, 'high', 'Religion.'),
    ('sexual_orientation', 'sensitive', 'Sexual Orientation', r'\b(sexual[_\s-]?orientation|orientation)\s*[:=]\s*["\'`]?(straight|heterosexual|gay|lesbian|bisexual|bi|pansexual|asexual|queer|lgbtq\+?)["\'`]?', re.I, 'high', 'Sexual orientation.'),
    ('ethnicity', 'sensitive', 'Ethnicity / Race', r'\b(ethnicity|race|nationality)\s*[:=]\s*["\'`]?([A-Za-z\s]{2,32})["\'`]?', re.I, 'high', 'Ethnicity / race / nationality.'),
    ('political', 'sensitive', 'Political Affiliation', r'\b(political[_\s-]?party|political[_\s-]?affiliation|union[_\s-]?membership)\s*[:=]\s*["\'`]?([^"\'`\n]{2,64})["\'`]?', re.I, 'high', 'Political / union affiliation.'),
    ('biometric', 'sensitive', 'Biometric Identifier', r'\b(fingerprint|face[_\s-]?id|faceid|retina[_\s-]?scan|iris[_\s-]?scan|voiceprint|biometric[_\s-]?(?:hash|template))\b', re.I, 'high', 'Biometric identifier.'),
    ('diagnosis', 'health', 'Medical Diagnosis', r'\b(diagnosis|diagnosed\s+with|medical[_\s-]?condition|illness|disease)\s*[:=]?\s*["\'`]?([A-Za-z\s]{3,64})["\'`]?', re.I, 'high', 'Medical diagnosis / condition.'),
    ('medication', 'health', 'Medication / Prescription', r'\b(medication|prescription|dosage|Rx)\s*[:=]\s*["\'`]?([A-Za-z0-9\s\-]{3,64})["\'`]?', re.I, 'high', 'Medication / prescription.'),
    ('medical_record', 'health', 'Medical Record Number', r'\b(MRN|medical[_\s-]?record[_\s-]?number|patient[_\s-]?id)\s*[:#=]?\s*["\'`]?([A-Z0-9]{4,15})["\'`]?', re.I, 'high', 'Medical record / patient identifier.'),
    ('health_keyword', 'health', 'Health Keyword', r'\b(HIV|AIDS|cancer|diabetes|hypertension|depression|bipolar|schizophrenia|pregnancy|pregnant|HBV|HCV|tuberculosis|chemotherapy|insulin)\b', re.I, 'high', 'Health-related keyword in free text.'),
    ('ipv4_public', 'online_id', 'IPv4 Address', r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b', 0, 'medium', 'IPv4 address.'),
    ('ipv6', 'online_id', 'IPv6 Address', r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b', 0, 'medium', 'IPv6 address.'),
    ('mac_address', 'online_id', 'MAC Address', r'\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', 0, 'medium', 'MAC address.'),
    ('uuid', 'online_id', 'UUID / Device ID', r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b', 0, 'low', 'UUID / device identifier.'),
    ('imei', 'online_id', 'IMEI', r'\bIMEI\s*[:#=]?\s*(\d{15})\b', re.I, 'high', 'IMEI.'),
    ('advertising_id', 'online_id', 'Advertising ID', r'\b(gaid|idfa|advertising[_\s-]?id|android[_\s-]?id)\s*[:=]\s*["\'`]?([A-Za-z0-9\-]{8,})["\'`]?', re.I, 'medium', 'Mobile advertising identifier.'),
    ('email_address', 'communication', 'Email Address', r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', 0, 'low', 'Email address.'),
    ('phone_number', 'communication', 'Phone Number', r'\b(?:\+?1[-.\s]?)?\(?([2-9]\d{2})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b', 0, 'medium', 'Phone number.'),
    ('phone_international', 'communication', 'International Phone', r'\+(?:[0-9]\s?){7,14}[0-9]', 0, 'medium', 'International phone number.'),
    ('im_handle', 'communication', 'Messaging Handle', r'\b(whatsapp|telegram|signal|discord|wechat|skype)\s*[:=]\s*["\'`]?(@?[A-Za-z0-9_\-.+]{3,32})["\'`]?', re.I, 'low', 'Messaging app handle.'),
    ('geo_coords', 'behavioral', 'Geo Coordinates', r'\b-?([1-8]?\d(?:\.\d+)|90(?:\.0+)?),\s*-?((?:1[0-7]\d|[1-9]?\d)(?:\.\d+)|180(?:\.0+)?)\b', 0, 'medium', 'Latitude/longitude pair.'),
    ('location_field', 'behavioral', 'Location Field', r'\b(location|gps|coords|geo)\s*[:=]\s*["\'`]?([^"\'`\n]{3,80})["\'`]?', re.I, 'low', 'Location / GPS field.'),
    ('search_query', 'behavioral', 'Search Query', r'\b(search[_\s-]?query|query|q)\s*[:=]\s*["\'`]([^"\'`\n]{2,120})["\'`]', re.I, 'low', 'Captured search query.'),
    ('browsing_history', 'behavioral', 'Browsing History', r'\b(browsing[_\s-]?history|visited[_\s-]?urls?|page[_\s-]?views?)\b', re.I, 'low', 'Browsing-history reference.'),
    ('user_agent', 'behavioral', 'User-Agent String', r'\bMozilla/5\.0\s*\([^)]{5,200}\)[^"\'`\n]{0,200}', 0, 'low', 'Captured User-Agent string.'),
    ('purchase_history', 'behavioral', 'Purchase History', r'\b(purchase[_\s-]?history|orders?|cart[_\s-]?items?)\s*[:=]', re.I, 'low', 'Purchase / order history field.'),
    ('private_ip', 'internal_info', 'Private IP Address', r'\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b', 0, 'medium', 'Private / internal IP address.'),
    ('internal_hostname', 'internal_info', 'Internal Hostname', r'\b[a-z0-9\-]+\.(?:internal|local|corp|lan|intranet)\b', re.I, 'medium', 'Internal hostname.'),
    ('file_path', 'internal_info', 'Absolute File Path', r'\b(?:/(?:home|Users|var|etc|opt|root)/[^\s"\'`<>\n]{2,120}|[A-Z]:\\Users\\[^\s"\'`<>\n]{2,120})', 0, 'low', 'Absolute file path / user directory.'),
    ('stack_trace', 'internal_info', 'Stack Trace', r'\bat\s+[A-Za-z_$][\w$.]*\s*\([^)]*:\d+:\d+\)', 0, 'low', 'JavaScript / Java stack-trace frame.'),
    ('port_open', 'internal_info', 'Exposed Port', r'\blocalhost:(?:3306|5432|27017|6379|9200|11211|8080|8000)\b', 0, 'medium', 'Reference to an exposed internal service port.'),
    ('cors_wildcard', 'misconfig', 'CORS Wildcard', r'\bAccess-Control-Allow-Origin\s*:\s*\*|cors\s*\(\s*\{\s*origin\s*:\s*["\'`]\*["\'`]', re.I, 'high', "CORS configured with '*'."),
    ('public_s3', 'misconfig', 'Open S3 Bucket URL', r'\bhttps?://(?:[a-z0-9-]+\.s3|s3[.-][a-z0-9-]+)\.amazonaws\.com/[^\s"\'`<>]*', re.I, 'high', 'S3 bucket URL.'),
    ('exposed_git', 'misconfig', 'Exposed .git Folder', r'/\.git(?:/|\b)', 0, 'high', 'Reference to a .git folder served over HTTP.'),
    ('admin_panel', 'misconfig', 'Admin Panel Path', r'/(?:admin|wp-admin|phpmyadmin|manager/html|administrator)(?:/|\?|$)', 0, 'medium', 'Admin panel path.'),
    ('default_credentials', 'misconfig', 'Default Credentials', r'\b(admin|root|user|guest)\s*[:=]\s*["\'`](admin|root|password|1234|changeme|default)["\'`]', re.I, 'critical', 'Default / unchanged credentials.'),
    ('ssl_disabled', 'misconfig', 'SSL Verification Disabled', r'\b(rejectUnauthorized\s*:\s*false|verify\s*=\s*False|--insecure|CURLOPT_SSL_VERIFYPEER\s*,\s*0)\b', 0, 'high', 'TLS / SSL verification disabled.'),
    ('auth_disabled', 'misconfig', 'Auth Disabled', r'\b(auth|authentication|require[_\s-]?auth)\s*[:=]\s*(false|False|FALSE|0|"false"|\'false\')', 0, 'high', 'Authentication disabled in config.'),
    ('env_production_debug', 'misconfig', 'Production Debug Mode', r'\b(ENV|NODE_ENV|APP_ENV)\s*[:=]\s*["\'`]?production["\'`]?[\s\S]{0,120}\bdebug\s*[:=]\s*true', re.I, 'high', 'Debug mode enabled in production.'),
]

RULES = [
    DetectionRule(rule_id, category, rule_type, re.compile(pattern, flags), severity, message)
    for rule_id, category, rule_type, pattern, flags, severity, message in RULE_DATA
]

CATEGORY_TIP = {
    'auth_secrets': 'Rotate the credential now and move it to a secrets manager.',
    'api_keys': 'Revoke the key at the vendor and load the new one from environment variables.',
    'crypto_keys': 'Treat as compromised; regenerate and distribute via a KMS.',
    'source_secrets': 'Scrub from git history and rotate the exposed value.',
    'financial': 'Tokenize or truncate; never persist full PAN or CVV.',
    'direct_id': 'Redact or tokenize. Apply PII retention limits.',
    'indirect_id': 'Generalize values to reduce re-identification risk.',
    'sensitive': 'Encrypt, restrict access, and keep an access log.',
    'health': 'Apply minimum-necessary access and audit trails.',
    'online_id': 'Hash with a rotating salt and expire aggressively.',
    'communication': 'Hash or tokenize; avoid plaintext logs.',
    'behavioral': 'Aggregate or anonymize before analytics.',
    'internal_info': 'Strip internal topology from public logs and commits.',
    'misconfig': 'Fix the configuration immediately and scan CI for regressions.',
}


def _mask_sensitive(value: str, severity: str) -> str:
    if severity in {'critical', 'high'} and len(value) > 8:
        return f'{value[:4]}****{value[-2:]}'
    return value


def _risk_level(issues: list[dict[str, Any]]) -> str:
    severities = {issue['severity'] for issue in issues}
    if not issues:
        return 'none'
    if 'critical' in severities or 'high' in severities or len(issues) >= 5:
        return 'high'
    if 'medium' in severities or len(issues) >= 2:
        return 'medium'
    return 'low'


def _score(issues: list[dict[str, Any]]) -> float:
    if not issues:
        return 0.0
    weighted = sum(SEVERITY_WEIGHT[issue['severity']] for issue in issues)
    return round(min(1.0, weighted / 3), 2)


def _summary(issues: list[dict[str, Any]]) -> str:
    if not issues:
        return 'No obvious secrets, PII, or risky configuration detected.'
    categories = []
    seen = set()
    for issue in issues:
        if issue['category'] not in seen:
            categories.append(issue['category'])
            seen.add(issue['category'])
    tips = ' '.join(CATEGORY_TIP[category] for category in categories if category in CATEGORY_TIP)
    return f'Detected {len(issues)} issue(s) across {len(categories)} category/categories. {tips}'.strip()


def _detect_issues(content: str) -> list[dict[str, Any]]:
    issues = []
    for rule in RULES:
        for match in rule.pattern.finditer(content):
            issues.append({
                'id': rule.id,
                'category': rule.category,
                'type': rule.type,
                'severity': rule.severity,
                'message': rule.message,
                'match': _mask_sensitive(match.group(0), rule.severity),
                'index': match.start(),
                'line': content.count('\n', 0, match.start()) + 1,
            })
    return issues


def analyze(file_path: str | Path) -> dict[str, Any]:
    """Analyze a file path and return a JSON-like score and summary."""
    path = Path(file_path)
    logger.debug('analysing file %s...', path)
    try:
        content = path.read_text(encoding='utf-8', errors='replace')
    except OSError as e:
        logger.warning('Unable to read %s: %s', path, e)
        return {'score': 0.0, 'summary': f'Unable to read file: {e}', 'error': str(e)}

    issues = _detect_issues(content)
    risk = _risk_level(issues)
    return {
        'score': _score(issues),
        'summary': _summary(issues),
        'risk': risk,
        'issues': issues,
    }


class AIAnalysisWorker(BaseWorker):

    def analyse(self, task: Task, report: Report, manual_trigger: bool=False) -> None:
        result = analyze(task.file.path)
        if result.get('error'):
            report.status = Status.ERROR
            report.add_details('error', result['error'])
            return

        risk = result['risk']
        if risk == 'none':
            report.status = Status.CLEAN
        elif risk == 'low':
            report.status = Status.WARN
        elif risk == 'medium':
            report.status = Status.WARN
        else:
            report.status = Status.ALERT

        report.add_details('score', {'value': result['score']})
        report.add_details('summary', result['summary'])
        if result['issues']:
            report.add_details('issues', {'items': result['issues']})
