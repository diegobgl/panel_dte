{
    'name': 'Panel DTE',
    'version': '1.0',
    'category': 'Accounting',
    'summary': 'Manage Chilean DTEs in a custom panel',
    'description': 'Allows receiving, viewing, and responding to Chilean DTEs.',
    'author': 'Diego Gajardo',
    'depends': ['mail', 'account', 'l10n_cl_edi'],
    'data': [
        'views/invoice_mail_view.xml',
        'views/invoice_mail_extended_view.xml',
    ],
    'installable': True,
    'auto_install': False,
}
