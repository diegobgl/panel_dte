{
    'name': 'Panel DTE',
    'version': '1.0',
    'category': 'Accounting',
    'summary': 'Manage Chilean DTEs in a custom panel',
    'description': 'Allows receiving, viewing, and responding to Chilean DTEs.',
    'author': 'Diego Gajardo',
    'depends': ['mail', 'account', 'l10n_cl_edi'],
    'data': [
        'wizards/dte_reclamo_wizard.xml',
        'views/invoice_mail_view.xml',
        'views/invoice_mail_report.xml',
        'views/config_setting.xml',
        'report/invoice_mail_report_templates.xml',
        'security/ir.model.access.csv',

    ],
    'installable': True,
    'auto_install': False,
}
