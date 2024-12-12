from odoo import models, fields, api
from odoo.tools import email_split
from odoo.exceptions import UserError
import base64
import xml.etree.ElementTree as ET



class InvoiceMail(models.Model):
    _name = 'invoice.mail'
    _inherit = ['mail.thread', 'mail.activity.mixin']
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
    state = fields.Selection([
            ('draft', 'Borrador'),
            ('pending', 'Pendiente'),
            ('accepted', 'Aceptado'),
            ('rejected', 'Rechazado'),
        ], default='draft', string='Estado', tracking=True)
    l10n_cl_reference_ids = fields.One2many(
        'invoice.mail.reference', 'invoice_mail_id', string="References")
    currency_id = fields.Many2one(
        comodel_name="res.currency",
        string="Currency",
        default=lambda self: self.env.company.currency_id,  # Define la moneda predeterminada
        required=True,
    )



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
        """Procesar correo y crear registro con datos extraídos del XML."""
        custom_values = custom_values or {}
        subject = msg_dict.get('subject', 'Imported Invoice')
        attachments = msg_dict.get('attachments', [])

        # Variables para almacenar los archivos
        xml_file = None
        pdf_file = None

        # Procesar archivos adjuntos
        for attachment in attachments:
            filename = attachment[0]
            file_content = attachment[1]

            if filename.endswith('.xml'):
                xml_file = file_content
            elif filename.endswith('.pdf'):
                pdf_file = file_content

        if not xml_file:
            raise UserError("No se encontró un archivo XML válido en el correo.")

        # Procesar datos del XML antes de crear el registro
        parsed_data = self.parse_xml(xml_file)

        # Actualizar valores personalizados con datos extraídos del XML y correo
        custom_values.update({
            'name': subject,
            'xml_file': base64.b64encode(xml_file),
            'pdf_preview': base64.b64encode(pdf_file) if pdf_file else False,
            **parsed_data,  # Incluir los datos extraídos del XML
        })

        # Crear el registro con los valores completos
        return super().message_new(msg_dict, custom_values)

    

    @api.depends('xml_file')
    def _compute_attachments_count(self):
        for record in self:
            record.attachments_count = 1 if record.xml_file else 0

    def action_set_pending(self):
        """Cambiar el estado a Pendiente."""
        self.state = 'pending'

    def action_accept(self):
        """Cambiar el estado a Aceptado."""
        if self.state != 'pending':
            raise UserError("Solo se pueden aceptar DTEs en estado pendiente.")
        self.state = 'accepted'

    def action_reject(self):
        """Cambiar el estado a Rechazado."""
        if self.state != 'pending':
            raise UserError("Solo se pueden rechazar DTEs en estado pendiente.")
        self.state = 'rejected'


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

    def parse_xml(self, xml_content):
        """Parse XML content and extract DTE data."""
        ns = {'sii': 'http://www.sii.cl/SiiDte'}
        try:
            root = ET.fromstring(xml_content)
            documento = root.find('.//sii:Documento', ns)
            if not documento:
                raise UserError("No se encontró un documento válido en el XML.")

            encabezado = documento.find('.//sii:Encabezado', ns)

            # Extraer datos del encabezado
            tipo_dte = encabezado.find('.//sii:IdDoc/sii:TipoDTE', ns).text
            folio = encabezado.find('.//sii:IdDoc/sii:Folio', ns).text
            fecha_emision = encabezado.find('.//sii:IdDoc/sii:FchEmis', ns).text
            monto_total = encabezado.find('.//sii:Totales/sii:MntTotal', ns).text
            monto_neto = encabezado.find('.//sii:Totales/sii:MntNeto', ns).text
            iva = encabezado.find('.//sii:Totales/sii:IVA', ns).text
            rut_emisor = encabezado.find('.//sii:Emisor/sii:RUTEmisor', ns).text
            razon_social_emisor = encabezado.find('.//sii:Emisor/sii:RznSoc', ns).text
            rut_receptor = encabezado.find('.//sii:Receptor/sii:RUTRecep', ns).text
            razon_social_receptor = encabezado.find('.//sii:Receptor/sii:RznSocRecep', ns).text

            # Crear el registro de la factura
            invoice = self.create({
                'name': f'DTE {tipo_dte}-{folio}',
                'company_rut': rut_emisor,
                'company_name': razon_social_emisor,
                'partner_rut': rut_receptor,
                'partner_name': razon_social_receptor,
                'date_emission': fecha_emision,
                'amount_total': float(monto_total),
                'amount_net': float(monto_neto),
                'amount_tax': float(iva),
            })

            # Extraer los detalles de productos/servicios
            detalles = documento.findall('.//sii:Detalle', ns)
            if not detalles:
                raise UserError("No se encontraron detalles de productos en el XML.")

            for detalle in detalles:
                nombre_item = detalle.find('.//sii:NmbItem', ns)
                cantidad_item = detalle.find('.//sii:QtyItem', ns)
                precio_item = detalle.find('.//sii:PrcItem', ns)

                # Crear las líneas de productos solo si todos los datos están presentes
                if nombre_item is not None and cantidad_item is not None and precio_item is not None:
                    self.env['invoice.mail.line'].create({
                        'invoice_id': invoice.id,
                        'product_name': nombre_item.text,
                        'quantity': float(cantidad_item.text),
                        'price_unit': float(precio_item.text),
                    })

            return invoice
        except ET.ParseError as e:
            raise UserError(f"Error al analizar el XML: {e}")
        except Exception as e:
            raise UserError(f"Error procesando el XML: {e}")


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


class InvoiceMailReport(models.AbstractModel):
    _name = 'report.panel_dte.invoice_mail_report'
    _description = 'Invoice Mail Report'

    def _get_report_values(self, docids, data=None):
        docs = self.env['invoice.mail'].browse(docids)
        return {
            'doc_ids': docids,
            'doc_model': 'invoice.mail',
            'docs': docs,
        }

class InvoiceMailReference(models.Model):
    _name = 'invoice.mail.reference'
    _description = 'Invoice Mail References'

    invoice_mail_id = fields.Many2one('invoice.mail', string="Invoice")
    origin_doc_number = fields.Char(string="Origin Reference")
    l10n_cl_reference_doc_type_id = fields.Many2one('l10n_cl.document.type', string="Reference Doc Type")
    reference_doc_code = fields.Char(string="Reference Doc Code")
    reason = fields.Char(string="Reason")
    date = fields.Date(string="Date")
