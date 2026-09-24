from odoo import Command
from odoo.addons.account.tests.common import AccountTestInvoicingCommon
from odoo.exceptions import AccessError
from odoo.tests import tagged


@tagged("post_install", "-at_install")
class TestReportQuery(AccountTestInvoicingCommon):
    def test_query_contract_applies_dates_company_and_record_access(self):
        other = self.setup_other_company()
        moves = self.env['account.move']
        for data in (self.company_data, other):
            moves |= self.env['account.move'].with_company(data['company']).create({
                'date': '2026-01-01',
                'journal_id': data['default_journal_misc'].id,
                'line_ids': [Command.create({
                    'account_id': data['default_account_expense'].id, 'debit': 123.45,
                }), Command.create({
                    'account_id': data['default_account_revenue'].id, 'credit': 123.45,
                })],
            })
        moves.action_post()
        lines = self.env['account.move.line'].with_context(
            allowed_company_ids=self.env.company.ids, state='posted',
            date_from='2026-01-01', date_to='2026-01-01', strict_range=True,
        )
        domain = [('id', 'in', moves.line_ids.ids)]

        def query_ids(records):
            tables, where, params = records._query_get(tuple(domain))
            self.assertIsInstance(tables, str)
            self.assertIsInstance(where, str)
            self.env.cr.execute('SELECT account_move_line.id FROM ' + tables + ' WHERE ' + where, params)
            return {row[0] for row in self.env.cr.fetchall()}

        expected = moves.filtered(lambda m: m.company_id == self.env.company).line_ids
        self.assertEqual(query_ids(lines), set(expected.ids))
        self.assertEqual(query_ids(lines.with_context(date_to='2025-12-31')), set())
        hidden = expected[0]
        self.env['ir.rule'].sudo().create({
            'name': 'Query regression rule',
            'model_id': self.env['ir.model']._get_id('account.move.line'),
            'domain_force': repr([('id', '!=', hidden.id)]),
        })
        self.assertEqual(query_ids(lines), set((expected - hidden).ids))
        with self.assertRaises(AccessError):
            lines.with_user(self.env.ref('base.public_user'))._query_get(domain)
