def migrate(cr, version):
    if not version:
        return

    # Legacy 19.0.1.0.0 (legacy_bank_statement_import) registered a dashboard
    # kanban inheritance calling action_import_bank_statement and a wizard
    # view/action targeting account.bank.statement.import. Upstream 1.1.2 uses
    # different XMLIDs, so remove the legacy records before om_account_reconcile
    # validates account.account_journal_dashboard_kanban_view during -u.
    cr.execute("""
        DELETE FROM ir_act_window
         WHERE id IN (
             SELECT res_id
               FROM ir_model_data
              WHERE module = 'om_account_bank_statement_import'
                AND name = 'action_om_account_bank_statement_import'
                AND model = 'ir.actions.act_window'
         )
    """)
    cr.execute("""
        DELETE FROM ir_ui_view
         WHERE id IN (
             SELECT res_id
               FROM ir_model_data
              WHERE module = 'om_account_bank_statement_import'
                AND name IN (
                    'journal_dashboard_view_inherit',
                    'om_account_bank_statement_import_view'
                )
                AND model = 'ir.ui.view'
         )
    """)
    cr.execute("""
        DELETE FROM ir_model_data
         WHERE module = 'om_account_bank_statement_import'
           AND name IN (
               'action_om_account_bank_statement_import',
               'journal_dashboard_view_inherit',
               'om_account_bank_statement_import_view'
           )
    """)
