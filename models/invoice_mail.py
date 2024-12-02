from odoo import models, fields, api
from odoo.exceptions import UserError
from odoo.tools import email_split

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
    pdf_preview = fields.Binary(string='PDF Preview', attachment=True)
    email_from = fields.Char(string='Email From')
    email_subject = fields.Char(string='Email Subject')
    attachments_count = fields.Integer(string="Attachments", compute="_compute_attachments_count")
    
    @api.depends('xml_file')
    def _compute_attachments_count(self):
        for record in self:
            record.attachments_count = 1 if record.xml_file else 0

    def action_accept(self):
        self.status = 'accepted'

    def action_reject(self):
        self.status = 'rejected'

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
        for attachment in attachments:
            if attachment[0].endswith('.xml'):  # Look for XML files
                xml_file = attachment[1]

        # Create the record with the extracted data
        custom_values.update({
            'name': subject or 'Imported Invoice',
            'company_name': from_email,
            'email_subject': subject,
            'email_from': from_email,
            'xml_file': xml_file,
        })

        return super().message_new(msg_dict, custom_values)

    def generate_pdf_preview(self, xml_content):
        # Placeholder: Implement actual logic to generate PDF from XML content
        return b''
