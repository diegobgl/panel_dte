from odoo import models, fields, api
from odoo.tools import email_split
from odoo.exceptions import UserError
import base64
import xml.etree.ElementTree as ET


class InvoiceMail(models.Model):
    _name = 'invoice.mail'
    _inherit = ['mail.thread']
    _description = 'Imported Electronic Invoices'

    name = fields.Char(string='Document Name', required=True)
    company_rut = fields.Char(string='RUT Emisor')
    company_name = fields.Char(string='Razón Social Emisor')
    company_address = fields.Char(string='Dirección Emisor')
    partner_rut = fields.Char(string='RUT Receptor')
    partner_name = fields.Char(string='Razón Social Receptor')
    partner_address = fields.Char(string='Dirección Receptor')
    date_emission = fields.Date(string='Fecha de Emisión')
    date_due = fields.Date(string='Fecha de Vencimiento')
    amount_net = fields.Float(string='Monto Neto')
    amount_tax = fields.Float(string='Monto IVA')
    amount_total = fields.Float(string='Monto Total')
    xml_file = fields.Binary(string='Archivo XML', attachment=True)
    pdf_preview = fields.Binary(string='Previsualización PDF', attachment=True)
    line_ids = fields.One2many('invoice.mail.line', 'invoice_id', string='Detalle de Productos')


    @api.model
    def generate_pdf_preview(self):
        """Generate a PDF preview of the document."""
        template_id = self.env.ref('your_module_name.barcode_stamp_footer')
        if not template_id:
            raise UserError("Template for PDF generation not found.")

        # Render the QWeb report
        report_service = self.env['ir.actions.report']
        pdf_content, content_type = report_service._render_qweb_pdf(
            template_id.xml_id, {'o': self}
        )

        # Store the PDF in binary field
        self.pdf_preview = base64.b64encode(pdf_content)
        return True


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

    @api.model
    def fetch_emails(self):
        """Fetch emails from the configured server and process them."""
        # Obtener servidores de correo configurados
        mail_servers = self.env['fetchmail.server'].search([('state', '=', 'connected')])
        if not mail_servers:
            raise UserError("No mail servers are connected. Please check the configuration.")

        for server in mail_servers:
            # Procesar correos para el servidor actual
            server.fetch_mail()
        return True

    @api.model
    def parse_xml(self, xml_content):
        """Parse XML content and extract DTE data."""
        root = ET.fromstring(xml_content)
        ns = {'sii': 'http://www.sii.cl/SiiDte'}

        documento = root.find('.//sii:Documento', ns)
        if not documento:
            raise UserError("No se encontró un documento válido en el XML.")

        encabezado = documento.find('.//sii:Encabezado', ns)

        # Encabezado
        tipo_dte = encabezado.find('.//sii:IdDoc/sii:TipoDTE', ns).text
        folio = encabezado.find('.//sii:IdDoc/sii:Folio', ns).text
        fecha_emision = encabezado.find('.//sii:IdDoc/sii:FchEmis', ns).text
        monto_total = encabezado.find('.//sii:Totales/sii:MntTotal', ns).text

        # Emisor y Receptor
        rut_emisor = encabezado.find('.//sii:Emisor/sii:RUTEmisor', ns).text
        razon_social_emisor = encabezado.find('.//sii:Emisor/sii:RznSoc', ns).text
        rut_receptor = encabezado.find('.//sii:Receptor/sii:RUTRecep', ns).text
        razon_social_receptor = encabezado.find('.//sii:Receptor/sii:RznSocRecep', ns).text

        # Crear Factura
        invoice = self.create({
            'name': f'DTE {tipo_dte}-{folio}',
            'company_rut': rut_emisor,
            'company_name': razon_social_emisor,
            'partner_rut': rut_receptor,
            'partner_name': razon_social_receptor,
            'date_emission': fecha_emision,
            'amount_total': float(monto_total),
        })

        # Detalles
        detalles = documento.findall('.//sii:Detalle', ns)
        for detalle in detalles:
            nombre_item = detalle.find('.//sii:NmbItem', ns).text
            cantidad_item = detalle.find('.//sii:QtyItem', ns).text
            precio_item = detalle.find('.//sii:PrcItem', ns).text

            self.env['invoice.mail.line'].create({
                'invoice_id': invoice.id,
                'product_name': nombre_item,
                'quantity': float(cantidad_item),
                'price_unit': float(precio_item),
            })

        return invoice

class InvoiceMailLine(models.Model):
    _name = 'invoice.mail.line'
    _description = 'Invoice Mail Line'

    invoice_id = fields.Many2one('invoice.mail', string='Factura', ondelete='cascade')
    product_name = fields.Char(string='Producto/Servicio')
    product_code = fields.Char(string='Código')
    quantity = fields.Float(string='Cantidad')
    price_unit = fields.Float(string='Precio Unitario')
    subtotal = fields.Float(string='Subtotal', compute='_compute_subtotal', store=True)

    @api.depends('quantity', 'price_unit')
    def _compute_subtotal(self):
        for line in self:
            line.subtotal = line.quantity * line.price_unit
