from odoo import models, fields, api
from odoo.tools import email_split
from odoo.exceptions import UserError
import base64

class InvoiceMail(models.Model):
    _name = 'invoice.mail'
    _inherit = ['mail.thread']
    _description = 'Imported Electronic Invoices'

    name = fields.Char(string='Document Name', required=True)
    company_rut = fields.Char(string='Company RUT')
    company_name = fields.Char(string='Company Name')
    total_amount = fields.Float(string='Total Amount')
    status = fields.Selection([
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected')
    ], default='pending', string='Status', tracking=True)
    xml_file = fields.Binary(string='XML File', attachment=True)
    xml_filename = fields.Char(string='XML File Name')
    pdf_preview = fields.Binary(string='PDF Preview', attachment=True)
    email_from = fields.Char(string='Email From')
    email_subject = fields.Char(string='Email Subject')
    date_received = fields.Datetime(string='Date Received', default=fields.Datetime.now)  # Nuevo campo de fecha

    @api.model
    def message_new(self, msg_dict, custom_values=None):
        """Create a new invoice record from an incoming email."""
        custom_values = custom_values or {}
        # Extract email content
        subject = msg_dict.get('subject', '')
        from_email = email_split(msg_dict.get('from', ''))[0]
        attachments = msg_dict.get('attachments', [])

        # Process attachments
        xml_file = None
        xml_filename = None
        for attachment in attachments:
            if attachment[0].endswith('.xml'):
                xml_file = base64.b64encode(attachment[1])
                xml_filename = attachment[0]

        # Create the record with the extracted data
        custom_values.update({
            'name': subject or 'Imported Invoice',
            'company_name': from_email,
            'email_subject': subject,
            'email_from': from_email,
            'xml_file': xml_file,
            'xml_filename': xml_filename,
            'date_received': fields.Datetime.now(),  # Establecer la fecha de recepción
        })

        return super().message_new(msg_dict, custom_values)
    

    @api.depends('xml_file')
    def _compute_attachments_count(self):
        for record in self:
            record.attachments_count = 1 if record.xml_file else 0

    def action_accept(self):
        self.status = 'accepted'

    def action_reject(self):
        self.status = 'rejected'
