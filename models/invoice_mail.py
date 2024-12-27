import base64
import logging
import time
from OpenSSL import crypto
from zeep import Client, Settings
from zeep.transports import Transport
from requests import Session
from odoo import models, fields, api, _
from odoo.exceptions import UserError


_logger = logging.getLogger(__name__)
class InvoiceMail(models.Model):
    _name = 'invoice.mail'
    _inherit = ['mail.thread', 'mail.activity.mixin', 'l10n_cl.edi.util']
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
    l10n_cl_reference_ids = fields.One2many(
        'invoice.mail.reference', 'invoice_mail_id', string="References")
    currency_id = fields.Many2one(
        comodel_name="res.currency",
        string="Currency",
        default=lambda self: self.env.company.currency_id,
        required=True,
    )
    folio_number = fields.Char(string='Folio Number')
    document_type = fields.Many2one('l10n_latam.document.type', string='Document Type')
    l10n_cl_sii_track_id = fields.Char(string='SII Track ID')
    l10n_cl_dte_status = fields.Selection([
        ('not_sent', 'Not Sent'),
        ('ask_for_status', 'Ask for Status'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
    ], string='SII Status', default='not_sent')




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
        """Procesar correo y extraer datos del XML y PDF adjuntos en un único registro."""
        custom_values = custom_values or {}
        subject = msg_dict.get('subject', 'Imported Invoice')
        from_email = email_split(msg_dict.get('from', ''))[0]
        body = msg_dict.get('body', '')
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

        # Procesar el XML y extraer datos relevantes
        try:
            ns = {'sii': 'http://www.sii.cl/SiiDte'}
            root = ET.fromstring(xml_file)
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

            # Extraer datos del emisor y receptor
            rut_emisor = encabezado.find('.//sii:Emisor/sii:RUTEmisor', ns).text
            razon_social_emisor = encabezado.find('.//sii:Emisor/sii:RznSoc', ns).text
            rut_receptor = encabezado.find('.//sii:Receptor/sii:RUTRecep', ns).text
            razon_social_receptor = encabezado.find('.//sii:Receptor/sii:RznSocRecep', ns).text

            # Preparar valores para crear el registro
            custom_values.update({
                'name': f'DTE {tipo_dte}-{folio}',
                'company_rut': rut_emisor,
                'company_name': razon_social_emisor,
                'partner_rut': rut_receptor,
                'partner_name': razon_social_receptor,
                'date_emission': fecha_emision,
                'amount_total': float(monto_total),
                'amount_net': float(monto_neto),
                'amount_tax': float(iva),
                'folio_number': folio,
                'document_type': tipo_dte,
                'xml_file': base64.b64encode(xml_file),
                'pdf_preview': base64.b64encode(pdf_file) if pdf_file else False,
            })
        except ET.ParseError as e:
            raise UserError(f"Error al analizar el XML: {e}")
        except Exception as e:
            raise UserError(f"Error procesando el XML: {e}")

        # Crear el registro
        record = super().message_new(msg_dict, custom_values)

        # Procesar detalles de productos/servicios del XML
        try:
            detalles = documento.findall('.//sii:Detalle', ns)
            for detalle in detalles:
                nombre_item = detalle.find('.//sii:NmbItem', ns).text
                cantidad_item = detalle.find('.//sii:QtyItem', ns).text
                precio_item = detalle.find('.//sii:PrcItem', ns).text
                descripcion_item = detalle.find('.//sii:DscItem', ns)
                descripcion_texto = descripcion_item.text if descripcion_item is not None else ''

                self.env['invoice.mail.line'].create({
                    'invoice_id': record.id,
                    'product_name': nombre_item,
                    'quantity': float(cantidad_item),
                    'price_unit': float(precio_item),
                    'description': descripcion_texto,  # Asigna la descripción
                })
        except Exception as e:
            raise UserError(f"Error al procesar los detalles del XML: {e}")

        # Registrar el contenido del correo en el chatter
        record.message_post(
            body=body or "Sin contenido en el cuerpo del correo.",
            subject=subject,
            message_type='comment',
            subtype_xmlid='mail.mt_note',
        )

        return record
    

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



    def _get_active_certificate(self):
        """
        Obtiene el certificado activo desde el modelo l10n_cl.certificate.
        """
        certificate = self.env['l10n_cl.certificate'].search([], limit=1)
        if not certificate:
            raise UserError(_("No se encontró un certificado digital activo en el sistema."))
        if not certificate.signature_key_file or not certificate.signature_pass_phrase:
            raise UserError(_("El certificado configurado no tiene una clave o archivo válido."))
        return certificate



    def _get_dte_claim(self):
        """
        Consulta el estado de un DTE en el SII utilizando el token generado con el certificado almacenado.
        """
        try:
            _logger.info(f"Solicitando estado al SII para folio {self.folio_number}.")

            # Paso 1: Obtener la semilla
            seed = self._get_seed()

            # Paso 2: Firmar la semilla con el certificado activo
            signed_seed = self._get_signed_seed(seed)

            # Paso 3: Obtener el token
            token = self._request_token(signed_seed)
            if not token:
                raise UserError("No se pudo generar un token válido para la consulta al SII.")

            # Paso 4: Configurar cliente SOAP para consultar el estado del DTE
            url = "https://palena.sii.cl/DTEWS/QueryEstDte.jws?WSDL"
            session = requests.Session()
            transport = Transport(session=session)
            settings = Settings(strict=False, xml_huge_tree=True)
            client = Client(url, transport=transport, settings=settings)

            # Paso 5: Preparar los parámetros de la consulta
            rut_emisor, dv_emisor = self.company_rut.split('-')
            rut_receptor, dv_receptor = self.partner_rut.split('-')
            params = {
                "RutConsultante": rut_emisor,
                "DvConsultante": dv_emisor,
                "RutCompania": rut_emisor,
                "DvCompania": dv_emisor,
                "RutReceptor": rut_receptor,
                "DvReceptor": dv_receptor,
                "TipoDte": self.document_type.code,
                "FolioDte": self.folio_number,
                "FechaEmisionDte": self.date_emission.strftime('%Y-%m-%d'),
                "MontoDte": int(self.amount_total),
                "Token": token,
            }

            # Paso 6: Realizar la consulta al SII
            _logger.info(f"Enviando solicitud al SII con los parámetros: {params}")
            response = client.service.getEstDte(**params)

            # Paso 7: Procesar la respuesta del SII
            if response and hasattr(response, 'EstadoDTE'):
                estado_dte = response.EstadoDTE
                glosa_estado = response.GlosaEstado
                _logger.info(f"Estado del DTE obtenido: {estado_dte}, Glosa: {glosa_estado}")

                # Actualizar el estado en el modelo
                self.l10n_cl_dte_status = estado_dte
                self.message_post(
                    body=f"Estado del DTE consultado: {estado_dte} - {glosa_estado}",
                    subject="Consulta de Estado DTE",
                    message_type='notification'
                )
                return estado_dte, glosa_estado
            else:
                _logger.error(f"Respuesta inválida del SII: {response}")
                raise UserError(_("No se pudo obtener el estado del DTE desde el SII."))

        except Exception as e:
            _logger.error(f"Error al consultar el estado del DTE en el SII: {e}")
            raise UserError(_("Error al consultar el estado del DTE en el SII: %s") % e)


    

    def check_sii_status(self):
        """
        Flujo completo para consultar el estado del DTE en el SII:
        1. Obtener la semilla.
        2. Firmar la semilla con el certificado activo.
        3. Solicitar el token usando la semilla firmada.
        4. Consultar el estado del DTE en el SII utilizando el token.
        """
        try:
            _logger.info(f"Solicitando estado al SII para folio {self.folio_number}.")

            # Paso 1: Obtener la semilla
            seed = self._get_seed()

            # Paso 2: Firmar la semilla
            signed_seed = self._get_signed_seed(seed)

            # Paso 3: Obtener el token
            token = self._request_token(signed_seed)
            if not token:
                raise UserError("No se pudo generar un token válido para la consulta al SII.")

            # Paso 4: Consultar el estado del DTE en el SII
            url = "https://palena.sii.cl/DTEWS/QueryEstDte.jws?WSDL"

            # Configurar cliente Zeep para la consulta
            session = Session()
            transport = Transport(session=session, timeout=10)
            settings = Settings(strict=False, xml_huge_tree=True)
            client = Client(url, settings=settings, transport=transport)

            # Crear parámetros para la consulta
            rut_emisor, dv_emisor = self.company_rut.split('-')
            rut_receptor, dv_receptor = self.partner_rut.split('-')
            params = {
                "RutConsultante": rut_emisor,
                "DvConsultante": dv_emisor,
                "RutCompania": rut_emisor,
                "DvCompania": dv_emisor,
                "RutReceptor": rut_receptor,
                "DvReceptor": dv_receptor,
                "TipoDte": self.document_type.code,
                "FolioDte": self.folio_number,
                "FechaEmisionDte": self.date_emission.strftime('%Y-%m-%d'),
                "MontoDte": int(self.amount_total),
                "Token": token,
            }

            # Realizar la consulta
            _logger.info(f"Enviando solicitud de consulta al SII con parámetros: {params}")
            response = client.service.getEstDte(**params)

            # Procesar la respuesta
            if response and hasattr(response, 'EstadoDTE'):
                estado_dte = response.EstadoDTE
                glosa_estado = response.GlosaEstado
                _logger.info(f"Estado del DTE obtenido: {estado_dte}, Glosa: {glosa_estado}")

                # Actualizar el estado en el modelo
                self.l10n_cl_dte_status = estado_dte
                self.message_post(
                    body=f"Estado del DTE consultado: {estado_dte} - {glosa_estado}",
                    subject="Consulta de Estado DTE",
                    message_type='notification'
                )
            else:
                _logger.error(f"Respuesta inválida del SII: {response}")
                raise UserError(_("No se pudo obtener el estado del DTE desde el SII."))

        except Exception as e:
            _logger.error(f"Error al consultar el estado del DTE en el SII: {e}")
            raise UserError(_("Error al consultar el estado del DTE en el SII: %s") % e)


    def _get_seed(self):
        """
        Solicita la semilla al servicio del SII.
        Utiliza reintentos en caso de errores temporales.
        """
        url = "https://palena.sii.cl/DTEWS/CrSeed.jws?WSDL"
        max_retries = 5
        retry_delay = 5  # Tiempo de espera entre reintentos (en segundos)

        for attempt in range(max_retries):
            try:
                # Configurar cliente Zeep
                session = Session()
                transport = Transport(session=session, timeout=10)
                settings = Settings(strict=False, xml_huge_tree=True)
                client = Client(url, settings=settings, transport=transport)

                # Realizar la solicitud al servicio
                _logger.info(f"Realizando solicitud de semilla al SII. Intento {attempt + 1} de {max_retries}.")
                response = client.service.getSeed()

                if response:
                    # Validar y retornar la semilla
                    _logger.info(f"Semilla obtenida correctamente: {response}")
                    return response
                else:
                    raise UserError(_("No se pudo obtener la semilla del SII."))

            except Exception as e:
                _logger.error(f"Error al obtener la semilla en el intento {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)  # Esperar antes de reintentar
                else:
                    raise UserError(_("No se pudo obtener la semilla después de varios intentos: %s") % e)


    def _get_signed_seed(self, seed):
        """
        Firma la semilla utilizando el certificado almacenado en Odoo.
        """
        certificate = self._get_active_certificate()

        try:
            # Obtener clave privada y certificado desde el modelo l10n_cl.certificate
            p12 = crypto.load_pkcs12(
                base64.b64decode(certificate.signature_key_file),
                certificate.signature_pass_phrase.encode('utf-8')
            )
            private_key = p12.get_privatekey()
            cert = p12.get_certificate()

            # Crear la firma digital de la semilla
            signed_info = crypto.sign(private_key, seed.encode('utf-8'), 'sha1')

            # Construir el XML firmado
            signed_xml = f"""
            <getToken>
                <item>
                    <Semilla>{seed}</Semilla>
                </item>
                <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <SignedInfo>
                        <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                        <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                        <Reference URI="\">
                            <Transforms>
                                <Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                            </Transforms>
                            <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                            <DigestValue></DigestValue>
                        </Reference>
                    </SignedInfo>
                    <SignatureValue>{base64.b64encode(signed_info).decode('utf-8')}</SignatureValue>
                    <KeyInfo>
                        <X509Data>
                            <X509Certificate>{base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)).decode('utf-8')}</X509Certificate>
                        </X509Data>
                    </KeyInfo>
                </Signature>
            </getToken>
            """
            _logger.info(f"Semilla firmada correctamente.")
            return signed_xml

        except Exception as e:
            _logger.error(f"Error al firmar la semilla: {e}")
            raise UserError(_("Error al firmar la semilla: %s") % e)


    def _request_token(self, signed_seed):
        """
        Envía la semilla firmada al servicio del SII para obtener el token.
        """
        url = "https://palena.sii.cl/DTEWS/GetTokenFromSeed.jws?WSDL"
        try:
            # Configurar cliente Zeep
            session = Session()
            transport = Transport(session=session, timeout=10)
            settings = Settings(strict=False, xml_huge_tree=True)
            client = Client(url, settings=settings, transport=transport)

            # Enviar la semilla firmada
            response = client.service.getToken(signed_seed)

            if response:
                _logger.info(f"Token obtenido correctamente: {response}")
                return response
            else:
                raise UserError(_("No se pudo obtener el token del SII."))
        except Exception as e:
            _logger.error(f"Error al solicitar el token: {e}")
            raise UserError(_("Error al solicitar el token: %s") % e)

    def get_token(self):
        """
        Flujo completo: obtener semilla, firmarla y solicitar el token.
        """
        try:
            # Paso 1: Obtener la semilla
            seed = self._get_seed()

            # Paso 2: Firmar la semilla
            signed_seed = self._get_signed_seed(seed)

            # Paso 3: Solicitar el token al SII
            token = self._request_token(signed_seed)
            return token
        except Exception as e:
            _logger.error(f"Error en el proceso de obtención del token: {e}")
            raise UserError(_("Error en el proceso de obtención del token: %s") % e)



class InvoiceMailLine(models.Model):
    _name = 'invoice.mail.line'
    _description = 'Invoice Mail Line'

    invoice_id = fields.Many2one('invoice.mail', string='Factura', ondelete='cascade')
    product_name = fields.Char(string='Producto/Servicio')
    product_code = fields.Char(string='Código')
    quantity = fields.Float(string='Cantidad')
    price_unit = fields.Float(string='Precio Unitario')
    subtotal = fields.Float(string='Subtotal', compute='_compute_subtotal', store=True)
    description = fields.Text(string='Descripción')  


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
