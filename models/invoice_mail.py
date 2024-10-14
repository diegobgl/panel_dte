
from odoo import models, fields, api

class InvoiceMail(models.Model):
    _name = 'invoice.mail'
    _description = 'Imported Electronic Invoices'

    name = fields.Char(string='Document Name')
    company_rut = fields.Char(string='Company RUT')
    company_name = fields.Char(string='Company Name')
    total_amount = fields.Float(string='Total Amount')
    status = fields.Selection([
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected')
    ], default='pending', string='Status')
    xml_file = fields.Binary(string='XML File', attachment=True)
    pdf_preview = fields.Binary(string='PDF Preview', attachment=True)

    def action_accept(self):
        self.status = 'accepted'

    def action_reject(self):
        self.status = 'rejected'

    @api.model
    def create_from_email(self, email_message, xml_attachment):
        xml_content = xml_attachment.decode('utf-8')
        invoice_data = {
            'name': 'Factura 37',
            'company_rut': '77494541-5',
            'company_name': 'DB TERRA CHILE HOLDCO SPA',
            'total_amount': 1190.00,
            'xml_file': xml_attachment,
            'pdf_preview': self.generate_pdf_preview(xml_content),
        }
        return self.create(invoice_data)

    def generate_pdf_preview(self, xml_content):
        return b''  # Placeholder for actual PDF preview generation
