from odoo import Command
from odoo.addons.account.tests.common import AccountTestInvoicingCommon
from odoo.tests import tagged


@tagged("post_install", "-at_install")
class TestBudgetQuery(AccountTestInvoicingCommon):
    def test_native_aggregates_keep_budget_signs_and_date_bounds(self):
        account = self.company_data['default_account_revenue']
        self.env['account.move'].create({
            'date': '2026-01-10',
            'journal_id': self.company_data['default_journal_misc'].id,
            'line_ids': [Command.create({'account_id': account.id, 'credit': 75.25}),
                         Command.create({'account_id': self.company_data['default_account_expense'].id, 'debit': 75.25})],
        })
        position = self.env['account.budget.post'].create({
            'name': 'Revenue', 'account_ids': [Command.set(account.ids)],
        })
        line = self.env['crossovered.budget.lines'].new({
            'general_budget_id': position.id,
            'date_from': '2026-01-01', 'date_to': '2026-01-31',
        })
        line._compute_practical_amount()
        self.assertAlmostEqual(line.practical_amount, 75.25)
        plan = self.env.ref('analytic.analytic_plan_projects')
        analytic = self.env['account.analytic.account'].create({'name': 'Budget', 'plan_id': plan.id})
        self.env['account.analytic.line'].create([
            {'name': 'Current', 'account_id': analytic.id, 'general_account_id': account.id,
             'date': '2026-01-10', 'amount': -50.25},
            {'name': 'Excluded', 'account_id': analytic.id, 'general_account_id': account.id,
             'date': '2026-02-01', 'amount': -999},
        ])
        line.analytic_account_id = analytic
        line._compute_practical_amount()
        self.assertAlmostEqual(line.practical_amount, -50.25)
