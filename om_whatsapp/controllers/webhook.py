import hashlib
import hmac
import json
import logging

from odoo import SUPERUSER_ID, fields, http
from odoo.http import request

from odoo.addons.om_whatsapp.models.om_whatsapp_account import WEBHOOK_PATH

_logger = logging.getLogger(__name__)


class OmWhatsappWebhook(http.Controller):
    """ The webhook of the Meta app: Meta checks it with the verify token,
    then posts the messages, statuses and template updates of the business
    accounts, signed with the App Secret (or per-route secret in managed mode). """

    @http.route(WEBHOOK_PATH, type='http', auth='public', methods=['GET'], csrf=False)
    def verify(self, **params):
        accounts = request.env['om.whatsapp.account'].sudo().search([
            ('provider', '=', 'meta'),
            ('meta_managed', '=', False),
        ])
        token = params.get('hub.verify_token')
        if params.get('hub.mode') == 'subscribe' and token and any(
            t and hmac.compare_digest(t, token) for t in accounts.mapped('meta_verify_token')
        ):
            return request.make_response(params.get('hub.challenge', ''), headers=[('Content-Type', 'text/plain')])
        return request.make_response('Forbidden', status=403)

    @http.route(WEBHOOK_PATH, type='http', auth='public', methods=['POST'], csrf=False)
    def receive(self):
        body = request.httprequest.get_data()
        payload = self._parse_payload(body)
        if payload is None:
            return request.make_response('Bad Request', status=400)
        env = request.env(user=SUPERUSER_ID)
        Account = env['om.whatsapp.account'].with_context(active_test=False)
        signature = request.httprequest.headers.get('X-Hub-Signature-256', '')
        header_phone_id = (request.httprequest.headers.get('X-Shamel-WhatsApp-Phone-Number-Id') or '').strip()
        for entry, change in self._iter_changes(payload):
            error_response = self._handle_change(env, Account, entry, change, header_phone_id, body, signature)
            if error_response is not None:
                return error_response
        return request.make_response('OK')

    @staticmethod
    def _parse_payload(body):
        try:
            payload = json.loads(body)
        except ValueError:
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _iter_changes(payload):
        for entry in payload.get('entry') or []:
            if not isinstance(entry, dict):
                continue
            for change in entry.get('changes') or []:
                if isinstance(change, dict):
                    yield entry, change

    def _handle_change(self, env, Account, entry, change, header_phone_id, body, signature):
        value = change.get('value') or {}
        phone_number_id = (value.get('metadata') or {}).get('phone_number_id')
        entry_waba_id = str(entry.get('id') or '')
        account, error_response = self._resolve_account(
            Account, entry_waba_id, phone_number_id, header_phone_id, body, signature,
        )
        if error_response is not None or not account:
            return error_response
        try:
            with env.cr.savepoint():
                account._meta_process_webhook(change.get('field'), value)
        except Exception:
            # an answer other than 200 makes Meta send it again and again;
            # managed accounts are behind shamel-bff's durable retry worker
            _logger.exception("WhatsApp webhook of %s not processed", account.name)
            if account.meta_managed:
                return request.make_response('Internal Server Error', status=500)
        return None

    def _resolve_account(self, Account, entry_waba_id, phone_number_id, header_phone_id, body, signature):
        if phone_number_id:
            return self._resolve_phone_account(Account, entry_waba_id, phone_number_id, body, signature)
        return self._resolve_waba_account(Account, entry_waba_id, header_phone_id, body, signature)

    def _resolve_phone_account(self, Account, entry_waba_id, phone_number_id, body, signature):
        account = Account.search([('provider', '=', 'meta'), ('meta_phone_number_id', '=', phone_number_id)], limit=1)
        if not account:
            return None, None
        if entry_waba_id and account.meta_waba_id and account.meta_waba_id != entry_waba_id:
            _logger.warning("WhatsApp webhook WABA mismatch for %s: ignored", account.name)
            return (None, request.make_response('Forbidden', status=403)) if account.meta_managed else (None, None)
        if not self._signed_by(account, body, signature):
            _logger.warning("WhatsApp webhook not signed by the app of %s: ignored", account.name)
            return None, request.make_response('Forbidden', status=403)
        return account, None

    def _resolve_waba_account(self, Account, entry_waba_id, header_phone_id, body, signature):
        if header_phone_id:
            account, response = self._resolve_header_waba_account(Account, entry_waba_id, header_phone_id, body, signature)
            if account or response is not None:
                return account, response
        if not entry_waba_id:
            return None, None
        candidates = Account.search([('provider', '=', 'meta'), ('meta_waba_id', '=', entry_waba_id)])
        if not candidates:
            return None, None
        account = next((acc for acc in candidates if self._signed_by(acc, body, signature)), None)
        if not account:
            _logger.warning("WhatsApp webhook not signed by the app of %s: ignored", candidates[0].name)
            return None, request.make_response('Forbidden', status=403)
        return account, None

    def _resolve_header_waba_account(self, Account, entry_waba_id, header_phone_id, body, signature):
        account = Account.search([
            ('provider', '=', 'meta'),
            ('meta_phone_number_id', '=', header_phone_id),
            ('meta_waba_id', '=', entry_waba_id),
        ], limit=1)
        if account:
            if not self._signed_by(account, body, signature):
                _logger.warning("WhatsApp webhook not signed by the app of %s: ignored", account.name)
                return None, request.make_response('Forbidden', status=403)
            return account, None
        mismatch = Account.search([
            ('provider', '=', 'meta'),
            ('meta_phone_number_id', '=', header_phone_id),
            ('meta_managed', '=', True),
        ], limit=1)
        if mismatch:
            _logger.warning("WhatsApp webhook WABA mismatch for %s: ignored", mismatch.name)
            return None, request.make_response('Forbidden', status=403)
        return None, None

    @staticmethod
    def _matches_secret(secret, body, signature):
        if not secret or not signature:
            return False
        expected = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    @classmethod
    def _signed_by(cls, account, body, signature):
        if not account.meta_managed:
            return cls._matches_secret(account.meta_app_secret, body, signature)
        if cls._matches_secret(account.meta_webhook_secret, body, signature):
            return True
        prev_valid = (
            account.meta_webhook_secret_previous
            and account.meta_webhook_secret_previous_until
            and account.meta_webhook_secret_previous_until > fields.Datetime.now()
        )
        return bool(prev_valid and cls._matches_secret(account.meta_webhook_secret_previous, body, signature))
