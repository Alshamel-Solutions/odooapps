import hashlib
import hmac
import json
from datetime import timedelta
from unittest.mock import patch

from odoo import Command, fields
from odoo.exceptions import AccessError, UserError
from odoo.tests import HttpCase, TransactionCase, new_test_user, tagged

from odoo.addons.om_whatsapp.models.om_whatsapp_account import MANAGED_LOCKED_FIELDS
from odoo.addons.om_whatsapp.tools import MetaApiError

from .fake_meta import APP_ID, APP_SECRET, PERMANENT_TOKEN, PHONE_ID, WABA_ID, fake_meta

ROUTER_URL = 'https://api.alshamels.net/webhooks/whatsapp'
MANAGED_SECRET = 'route-secret-initial-0123456789abcdef'
ROTATED_SECRET = 'route-secret-rotated-fedcba9876543210'
SECOND_PHONE_ID = '5550002222'
SECOND_SECRET = 'route-secret-second-number-abcdef1234'


def _sign(secret, body):
    return 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@tagged('post_install', '-at_install')
class TestManagedRouterModel(TransactionCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.startClassPatcher(patch.object(
            type(cls.env['om.whatsapp.account']), '_meta_database_reachable', return_value=True,
        ))
        cls.env['ir.config_parameter'].sudo().set_param('web.base.url', 'https://client.alshamels.net')
        cls.erp_manager = new_test_user(
            cls.env, 'shamel_erp_manager',
            groups='base.group_user,base.group_erp_manager,om_whatsapp_base.group_om_whatsapp_manager',
        )
        cls.wa_manager = new_test_user(
            cls.env, 'shamel_wa_manager',
            groups='base.group_user,base.group_partner_manager,om_whatsapp_base.group_om_whatsapp_manager',
        )
        cls.wa_user = new_test_user(
            cls.env, 'shamel_wa_user',
            groups='base.group_user,om_whatsapp_base.group_om_whatsapp_user',
        )

    def _provision_vals(self, **overrides):
        vals = {
            'phone_number_id': PHONE_ID,
            'waba_id': WABA_ID,
            'waba_name': 'Acme WABA',
            'app_id': APP_ID,
            'access_token': PERMANENT_TOKEN,
            'webhook_secret': MANAGED_SECRET,
            'router_url': ROUTER_URL,
            'skip_meta_check': True,
        }
        vals.update(overrides)
        return vals

    def test_provisioning_auth_guard_and_validation(self):
        Account = self.env['om.whatsapp.account']
        for user in (self.wa_user, self.wa_manager):
            with self.assertRaises(AccessError):
                Account.with_user(user).action_shamel_provision_managed(self._provision_vals())
            with self.assertRaises(AccessError):
                Account.with_user(user).action_shamel_rotate_managed_secret(PHONE_ID, ROTATED_SECRET)
            with self.assertRaises(AccessError):
                Account.with_user(user).action_shamel_unprovision_managed(PHONE_ID)

        with self.assertRaises(UserError):
            Account.with_user(self.erp_manager).action_shamel_provision_managed('not-a-dict')
        with self.assertRaises(UserError):
            Account.with_user(self.erp_manager).action_shamel_provision_managed({'phone_number_id': PHONE_ID})

    def test_provision_online_idempotency_and_no_secret_leak(self):
        Account = self.env['om.whatsapp.account'].with_user(self.erp_manager)
        with fake_meta() as meta:
            meta.templates.append({
                'id': 'tpl-managed-1', 'name': 'order_ready', 'language': 'en_US',
                'status': 'APPROVED', 'category': 'UTILITY',
                'components': [{'type': 'BODY', 'text': 'Order {{1}} is ready.'}],
            })
            result = Account.action_shamel_provision_managed(self._provision_vals(skip_meta_check=False))

        self.assertEqual(result['name'], 'Odoo Mates')
        self.assertEqual(result['meta_state'], 'connected')
        self.assertEqual(result['phone'], '+1 555-000-1111')
        self.assertEqual(result['verified_name'], 'Odoo Mates')
        self.assertEqual(result['templates_synced'], 1)
        result_blob = json.dumps(result)
        self.assertNotIn(PERMANENT_TOKEN, result_blob)
        self.assertNotIn(MANAGED_SECRET, result_blob)
        self.assertNotIn(('GET', 'debug_token'), meta.calls)
        self.assertNotIn(('GET', f'{APP_ID}/subscriptions'), meta.calls)

        account = self.env['om.whatsapp.account'].sudo().browse(result['account_id'])
        self.assertTrue(account.meta_managed)
        self.assertFalse(account.meta_app_secret)
        self.assertEqual(account.meta_webhook_secret, MANAGED_SECRET)
        self.assertEqual(account.meta_router_url, ROUTER_URL)

        # Idempotent update preserves customized name unless explicitly overridden
        account.with_user(self.wa_manager).write({'name': 'Support Desk'})
        second = Account.action_shamel_provision_managed(self._provision_vals(webhook_secret=ROTATED_SECRET))
        self.assertEqual(second['account_id'], account.id)
        self.assertEqual(account.name, 'Support Desk')
        self.assertEqual(account.meta_webhook_secret, ROTATED_SECRET)

        third = Account.action_shamel_provision_managed(self._provision_vals(name='Sales Line'))
        self.assertEqual(third['account_id'], account.id)
        self.assertEqual(account.name, 'Sales Line')

    def test_write_create_and_unlink_guardrails(self):
        Account = self.env['om.whatsapp.account']
        # Non-system managers cannot mark new or existing accounts as managed
        with self.assertRaises(AccessError):
            Account.with_user(self.wa_manager).create({'name': 'Spoof', 'provider': 'meta', 'meta_managed': True})
        standalone = Account.with_user(self.wa_manager).create({'name': 'Own', 'provider': 'meta'})
        with self.assertRaises(AccessError):
            standalone.with_user(self.wa_manager).write({'meta_managed': True})

        res = Account.with_user(self.erp_manager).action_shamel_provision_managed(self._provision_vals(name='Managed'))
        account = Account.browse(res['account_id'])

        # Every locked field is blocked for WhatsApp manager (even with spoofed context) and non-su ERP manager
        sample_values = {
            'provider': 'link',
            'active': False,
            'meta_managed': False,
            'meta_app_id': '999',
            'meta_app_secret': 'injected',
            'meta_access_token': 'injected',
            'meta_waba_id': '999',
            'meta_waba_name': 'Other',
            'meta_phone_number_id': '999',
            'meta_webhook_secret': 'injected',
            'meta_webhook_secret_previous': 'injected',
            'meta_webhook_secret_previous_until': fields.Datetime.now(),
            'meta_router_url': 'https://evil.example',
            'meta_verify_token': 'injected',
            'meta_pin': '123456',
        }
        self.assertEqual(set(sample_values), set(MANAGED_LOCKED_FIELDS))
        for field_name, val in sample_values.items():
            with self.assertRaises(AccessError):
                account.with_user(self.wa_manager).write({field_name: val})
            with self.assertRaises(AccessError):
                account.with_user(self.wa_manager).with_context(shamel_whatsapp_provision=True).write({field_name: val})

        with self.assertRaises(AccessError):
            account.with_user(self.erp_manager).write({'meta_webhook_secret': 'ui-edit'})
        with self.assertRaises(AccessError):
            account.with_user(self.wa_manager).action_archive()
        with self.assertRaises(AccessError):
            account.with_user(self.wa_manager).unlink()
        with self.assertRaises(AccessError):
            account.with_user(self.erp_manager).unlink()

        # Operational fields remain editable by WhatsApp managers
        account.with_user(self.wa_manager).write({
            'name': 'Customer Care',
            'user_ids': [Command.set((self.wa_manager | self.wa_user).ids)],
            'receive_unknown': False,
            'reply_days': 14,
        })
        self.assertEqual(account.name, 'Customer Care')
        self.assertFalse(account.receive_unknown)
        self.assertEqual(account.reply_days, 14)
        self.assertIn(self.wa_user, account.user_ids)

    def test_blocked_and_allowed_actions_on_managed_account(self):
        Account = self.env['om.whatsapp.account']
        res = Account.with_user(self.erp_manager).action_shamel_provision_managed(self._provision_vals(name='Managed'))
        account = Account.browse(res['account_id'])

        for method in ('action_meta_setup', 'action_meta_permanent_token', 'action_meta_set_webhook', 'action_meta_disconnect'):
            with self.assertRaisesRegex(UserError, 'Alshamel'):
                getattr(account.with_user(self.wa_manager), method)()

        # Direct wizard bypass is also blocked
        with fake_meta():
            wizard = self.env['om.whatsapp.meta.setup'].with_user(self.wa_manager).create({
                'account_id': account.id, 'app_id': APP_ID, 'app_secret': APP_SECRET, 'access_token': PERMANENT_TOKEN,
            })
            with self.assertRaisesRegex(UserError, 'Alshamel'):
                wizard.action_check_app_id()
            with self.assertRaisesRegex(UserError, 'Alshamel'):
                wizard.action_connect()
            with self.assertRaisesRegex(UserError, 'Alshamel'):
                wizard.action_save_permanent()

            # Send Test Message and Sync Templates still work without app_secret
            test_action = account.with_user(self.wa_manager).action_meta_test_message()
            test_wizard = self.env['om.whatsapp.meta.setup'].with_user(self.wa_manager).with_context(
                **test_action['context']
            ).create({'test_number': '+966500000001'})
            test_wizard.action_send_test()
            account.with_user(self.wa_manager).action_meta_sync_templates()

        # _meta_explain on 190 points to Alshamel support, not Make it Permanent
        explained = account._meta_explain(MetaApiError('Token expired', 190))
        self.assertIn('Alshamel support', explained)
        self.assertNotIn('Make it Permanent', explained)

    def test_meta_check_managed_never_uses_app_secret(self):
        Account = self.env['om.whatsapp.account']
        res = Account.with_user(self.erp_manager).action_shamel_provision_managed(self._provision_vals(name='Managed'))
        account = Account.browse(res['account_id'])
        self.assertFalse(account.sudo().meta_app_secret)

        with fake_meta() as meta:
            meta.numbers[0]['quality_rating'] = 'YELLOW'
            problems = account.with_user(self.wa_manager)._meta_check()
        self.assertEqual(problems, [])
        self.assertEqual(account.meta_state, 'connected')
        self.assertEqual(account.meta_quality_rating, 'YELLOW')
        self.assertNotIn(('GET', 'debug_token'), meta.calls)
        self.assertNotIn(('GET', f'{APP_ID}/subscriptions'), meta.calls)

        # Invalid token (190) -> Alshamel support error message
        account.sudo().write({'meta_access_token': 'revoked-token'})
        with fake_meta():
            problems = account._meta_check()
        self.assertEqual(account.meta_state, 'error')
        self.assertIn('Alshamel support', problems[0])

        # Missing signing secret -> error
        account.sudo().write({'meta_access_token': PERMANENT_TOKEN, 'meta_webhook_secret': False})
        with fake_meta():
            problems = account._meta_check()
        self.assertEqual(account.meta_state, 'error')
        self.assertIn('Webhook signing secret is missing', problems[0])

        # Unreachable DB -> managed database message (no Set Webhook instruction)
        account.sudo().write({'meta_webhook_secret': MANAGED_SECRET})
        with fake_meta(), patch.object(type(account), '_meta_database_reachable', return_value=False):
            problems = account._meta_check()
        self.assertEqual(account.meta_state, 'error')
        self.assertIn('Alshamel support', problems[0])
        self.assertNotIn('Set Webhook', problems[0])

    def test_rotate_and_unprovision_preserve_history(self):
        Account = self.env['om.whatsapp.account'].with_user(self.erp_manager)
        res = Account.action_shamel_provision_managed(self._provision_vals(name='Managed'))
        account = self.env['om.whatsapp.account'].sudo().browse(res['account_id'])

        rot = Account.action_shamel_rotate_managed_secret(PHONE_ID, ROTATED_SECRET, grace_seconds=600)
        self.assertEqual(rot['account_id'], account.id)
        self.assertTrue(rot['rotated'])
        self.assertTrue(rot['grace_until'].endswith('Z'))
        self.assertNotIn(ROTATED_SECRET, json.dumps(rot))
        self.assertNotIn(MANAGED_SECRET, json.dumps(rot))
        self.assertEqual(account.meta_webhook_secret, ROTATED_SECRET)
        self.assertEqual(account.meta_webhook_secret_previous, MANAGED_SECRET)
        self.assertGreater(account.meta_webhook_secret_previous_until, fields.Datetime.now())

        # Record a Discuss conversation + message before unprovisioning
        msg = account._om_whatsapp_receive('+966501234567', 'Keep this history', whatsapp_id='wamid.keep.1')
        channel = self.env['discuss.channel'].sudo().search([('om_whatsapp_account_id', '=', account.id)])
        self.assertTrue(msg)
        self.assertEqual(len(channel), 1)

        unprov = Account.action_shamel_unprovision_managed(PHONE_ID)
        self.assertEqual(unprov, {'account_id': account.id, 'unprovisioned': True})
        self.assertFalse(account.active)
        self.assertEqual(account.meta_state, 'draft')
        self.assertFalse(account.meta_access_token)
        self.assertFalse(account.meta_webhook_secret)
        self.assertFalse(account.meta_webhook_secret_previous)
        self.assertFalse(account.meta_webhook_secret_previous_until)
        self.assertFalse(account.meta_phone_number_id)
        # History preserved
        self.assertTrue(channel.exists())
        self.assertTrue(msg.exists())
        # Idempotent second call returns clean unprovisioned=False
        self.assertEqual(Account.action_shamel_unprovision_managed(PHONE_ID), {'account_id': 0, 'unprovisioned': False})

    def test_form_view_loads_with_managed_elements(self):
        view = self.env['om.whatsapp.account'].get_view(view_type='form')
        self.assertIn('meta_managed', view['arch'])
        self.assertIn('managed by Alshamel', view['arch'])
        self.assertNotIn('meta_webhook_secret', view['arch'])


@tagged('post_install', '-at_install')
class TestManagedRouterWebhook(HttpCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.user = new_test_user(
            cls.env, 'shamel_wh_user', groups='base.group_user,om_whatsapp_base.group_om_whatsapp_user',
        )
        cls.alice = cls.env['res.partner'].create({'name': 'Alice Managed', 'phone': '+966501112233'})
        cls.managed = cls.env['om.whatsapp.account'].sudo().with_context(shamel_whatsapp_provision=True).create({
            'name': 'Managed Primary',
            'provider': 'meta',
            'user_ids': [Command.set(cls.user.ids)],
            'meta_managed': True,
            'meta_app_id': APP_ID,
            'meta_app_secret': False,
            'meta_access_token': PERMANENT_TOKEN,
            'meta_waba_id': WABA_ID,
            'meta_phone_number_id': PHONE_ID,
            'meta_webhook_secret': MANAGED_SECRET,
            'meta_router_url': ROUTER_URL,
            'meta_state': 'connected',
        })
        cls.standalone = cls.env['om.whatsapp.account'].create({
            'name': 'Standalone Meta',
            'provider': 'meta',
            'user_ids': [Command.set(cls.user.ids)],
            'meta_managed': False,
            'meta_app_id': APP_ID,
            'meta_app_secret': APP_SECRET,
            'meta_access_token': PERMANENT_TOKEN,
            'meta_waba_id': '8888888888',
            'meta_phone_number_id': '8888880001',
            'meta_state': 'connected',
        })

    def _post_raw(self, payload, secret, headers=None):
        body = json.dumps(payload).encode()
        req_headers = {'Content-Type': 'application/json', 'X-Hub-Signature-256': _sign(secret, body)}
        if headers:
            req_headers.update(headers)
        return self.url_open('/om_whatsapp/webhook', data=body, headers=req_headers)

    def _message_payload(self, wamid, text='Hello', waba_id=WABA_ID, phone_number_id=PHONE_ID):
        return {
            'object': 'whatsapp_business_account',
            'entry': [{
                'id': waba_id,
                'changes': [{
                    'field': 'messages',
                    'value': {
                        'messaging_product': 'whatsapp',
                        'metadata': {'phone_number_id': phone_number_id},
                        'contacts': [{'wa_id': '966501112233', 'profile': {'name': 'Alice'}}],
                        'messages': [{'from': '966501112233', 'id': wamid, 'timestamp': '1760000000',
                                      'type': 'text', 'text': {'body': text}}],
                    },
                }],
            }],
        }

    def test_get_verify_ignores_managed_keeps_standalone(self):
        managed_tok = self.managed.meta_verify_token
        resp_managed = self.url_open(
            f'/om_whatsapp/webhook?hub.mode=subscribe&hub.verify_token={managed_tok}&hub.challenge=99'
        )
        self.assertEqual(resp_managed.status_code, 403)

        standalone_tok = self.standalone.meta_verify_token
        resp_standalone = self.url_open(
            f'/om_whatsapp/webhook?hub.mode=subscribe&hub.verify_token={standalone_tok}&hub.challenge=99'
        )
        self.assertEqual((resp_standalone.status_code, resp_standalone.text), (200, '99'))

    def test_managed_hmac_and_no_app_secret_fallback(self):
        # Valid per-route secret -> 200 and creates message
        ok = self._post_raw(self._message_payload('wamid.mgr.1', 'Hi managed'), MANAGED_SECRET)
        self.assertEqual(ok.status_code, 200)
        msg = self.env['mail.message'].search([('om_whatsapp_id', '=', 'wamid.mgr.1')])
        self.assertEqual(msg._om_whatsapp_text(), 'Hi managed')

        # Wrong secret -> 403
        with self.assertLogs('odoo.addons.om_whatsapp.controllers.webhook', 'WARNING'):
            bad = self._post_raw(self._message_payload('wamid.mgr.bad', 'Forged'), 'wrong-secret')
        self.assertEqual(bad.status_code, 403)
        self.assertFalse(self.env['mail.message'].search([('om_whatsapp_id', '=', 'wamid.mgr.bad')]))

        # Even if meta_app_secret were somehow set, managed mode NEVER falls back to it
        self.managed.sudo().write({'meta_app_secret': APP_SECRET})
        try:
            with self.assertLogs('odoo.addons.om_whatsapp.controllers.webhook', 'WARNING'):
                fallback = self._post_raw(self._message_payload('wamid.mgr.appsec', 'Nope'), APP_SECRET)
            self.assertEqual(fallback.status_code, 403)
        finally:
            self.managed.sudo().write({'meta_app_secret': False})

        # Empty webhook_secret -> fail closed 403
        self.managed.sudo().write({'meta_webhook_secret': False})
        try:
            with self.assertLogs('odoo.addons.om_whatsapp.controllers.webhook', 'WARNING'):
                empty = self._post_raw(self._message_payload('wamid.mgr.empty', 'Empty'), '')
            self.assertEqual(empty.status_code, 403)
        finally:
            self.managed.sudo().write({'meta_webhook_secret': MANAGED_SECRET})

        # WABA mismatch on managed account -> 403
        with self.assertLogs('odoo.addons.om_whatsapp.controllers.webhook', 'WARNING'):
            mismatch = self._post_raw(
                self._message_payload('wamid.mgr.waba', 'Wrong WABA', waba_id='7777777777'),
                MANAGED_SECRET,
            )
        self.assertEqual(mismatch.status_code, 403)
        self.assertFalse(self.env['mail.message'].search([('om_whatsapp_id', '=', 'wamid.mgr.waba')]))

    def test_rotation_grace_window(self):
        self.env['om.whatsapp.account'].action_shamel_rotate_managed_secret(PHONE_ID, ROTATED_SECRET, grace_seconds=900)
        # During grace window, both old and new secrets succeed
        self.assertEqual(
            self._post_raw(self._message_payload('wamid.rot.old', 'Old ok'), MANAGED_SECRET).status_code, 200,
        )
        self.assertEqual(
            self._post_raw(self._message_payload('wamid.rot.new', 'New ok'), ROTATED_SECRET).status_code, 200,
        )
        # After grace expires, old secret is rejected (403) while new secret succeeds (200)
        self.managed.sudo().write({'meta_webhook_secret_previous_until': fields.Datetime.now() - timedelta(seconds=10)})
        with self.assertLogs('odoo.addons.om_whatsapp.controllers.webhook', 'WARNING'):
            expired = self._post_raw(self._message_payload('wamid.rot.exp', 'Expired'), MANAGED_SECRET)
        self.assertEqual(expired.status_code, 403)
        self.assertEqual(
            self._post_raw(self._message_payload('wamid.rot.after', 'Still ok'), ROTATED_SECRET).status_code, 200,
        )

    def test_waba_event_routing_with_and_without_header(self):
        second = self.env['om.whatsapp.account'].sudo().with_context(shamel_whatsapp_provision=True).create({
            'name': 'Managed Secondary',
            'provider': 'meta',
            'user_ids': [Command.set(self.user.ids)],
            'meta_managed': True,
            'meta_app_id': APP_ID,
            'meta_access_token': PERMANENT_TOKEN,
            'meta_waba_id': WABA_ID,
            'meta_phone_number_id': SECOND_PHONE_ID,
            'meta_webhook_secret': SECOND_SECRET,
            'meta_state': 'connected',
        })
        template = self.env['om.whatsapp.template'].with_context(om_whatsapp_meta_sync=True).create({
            'name': 'Invoice Notice',
            'model_id': self.env['ir.model']._get_id('res.partner'),
            'account_id': second.id,
            'body': 'Invoice ready',
            'meta_template_id': 'tpl-waba-1',
            'meta_waba_id': WABA_ID,
            'meta_status': 'PENDING',
        })
        waba_payload = {
            'object': 'whatsapp_business_account',
            'entry': [{
                'id': WABA_ID,
                'changes': [{
                    'field': 'message_template_status_update',
                    'value': {
                        'event': 'APPROVED',
                        'message_template_id': 'tpl-waba-1',
                        'message_template_name': 'invoice_notice',
                        'message_template_language': 'en_US',
                        'reason': 'NONE',
                    },
                }],
            }],
        }
        # Header deterministically picks second account
        resp_hdr = self._post_raw(
            waba_payload, SECOND_SECRET, headers={'X-Shamel-WhatsApp-Phone-Number-Id': SECOND_PHONE_ID},
        )
        self.assertEqual(resp_hdr.status_code, 200)
        template.invalidate_recordset()
        self.assertEqual(template.meta_status, 'APPROVED')

        # Header with mismatched WABA -> 403
        bad_waba_payload = {**waba_payload, 'entry': [{**waba_payload['entry'][0], 'id': '9999999999'}]}
        with self.assertLogs('odoo.addons.om_whatsapp.controllers.webhook', 'WARNING'):
            resp_mis = self._post_raw(
                bad_waba_payload, SECOND_SECRET, headers={'X-Shamel-WhatsApp-Phone-Number-Id': SECOND_PHONE_ID},
            )
        self.assertEqual(resp_mis.status_code, 403)

        # Without header on 2-number WABA DB, falls back to matching candidate by signature
        waba_payload['entry'][0]['changes'][0]['value']['event'] = 'PAUSED'
        resp_no_hdr = self._post_raw(waba_payload, SECOND_SECRET)
        self.assertEqual(resp_no_hdr.status_code, 200)
        template.invalidate_recordset()
        self.assertEqual(template.meta_status, 'PAUSED')

        # Forged WABA event without header -> 403
        with self.assertLogs('odoo.addons.om_whatsapp.controllers.webhook', 'WARNING'):
            resp_forged = self._post_raw(waba_payload, 'forged-secret')
        self.assertEqual(resp_forged.status_code, 403)

    def test_exception_returns_500_for_managed_and_200_for_standalone(self):
        AccountModel = type(self.env['om.whatsapp.account'])
        with patch.object(AccountModel, '_meta_process_webhook', side_effect=RuntimeError('transient boom')):
            with self.assertLogs('odoo.addons.om_whatsapp.controllers.webhook', 'ERROR'):
                resp_managed = self._post_raw(self._message_payload('wamid.err.mgr', 'Boom'), MANAGED_SECRET)
            self.assertEqual(resp_managed.status_code, 500)

            with self.assertLogs('odoo.addons.om_whatsapp.controllers.webhook', 'ERROR'):
                resp_standalone = self._post_raw(
                    self._message_payload('wamid.err.std', 'Boom', waba_id='8888888888', phone_number_id='8888880001'),
                    APP_SECRET,
                )
            self.assertEqual(resp_standalone.status_code, 200)

        # Standalone normal delivery still works end-to-end
        ok_std = self._post_raw(
            self._message_payload('wamid.std.ok', 'Standalone works', waba_id='8888888888', phone_number_id='8888880001'),
            APP_SECRET,
        )
        self.assertEqual(ok_std.status_code, 200)
        self.assertEqual(
            self.env['mail.message'].search([('om_whatsapp_id', '=', 'wamid.std.ok')])._om_whatsapp_text(),
            'Standalone works',
        )
