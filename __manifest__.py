
{
    'name': 'Chilean Electronic Invoice Importer',
    'version': '1.0',
    'category': 'Accounting',
    'summary': 'Module to import and manage Chilean electronic invoices from XML',
    'description': 'This module allows importing and managing Chilean electronic invoices.',
    'author': 'Your Name',
    'depends': ['mail', 'account'],
    'data': [
        'views/invoice_mail_view.xml',
    ],
    'installable': True,
    'auto_install': False,
}
