import requests
import urllib3
import base64
import logging
import html
import hashlib
import xml.etree.ElementTree as ET
from lxml import etree
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from odoo import models, fields, api
from odoo.tools.translate import _
from odoo.exceptions import UserError
from odoo.tools import email_split


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
    response_raw = fields.Text(string="Respuesta XML Cruda")
    folio_number = fields.Char(string='Folio Number')
    document_type = fields.Many2one('l10n_latam.document.type', string='Document Type')
    l10n_cl_sii_track_id = fields.Char(string='SII Track ID')
    l10n_cl_dte_status = fields.Selection([
        ('not_sent', 'Not Sent'),
        ('ask_for_status', 'Ask for Status'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
    ], string='SII Status', default='not_sent')
    xml_signed_file = fields.Binary(string='XML File (Signed/Requests)', attachment=True)
    line_ids = fields.One2many(
        'invoice.mail.line',
        'invoice_id',
        string='Detalle de Productos'
    )
    l10n_cl_reference_ids = fields.One2many(
        'invoice.mail.reference', 
        'invoice_mail_id', 
        string="References"
    )
    response_raw = fields.Text(string="Respuesta XML Cruda")





    @api.model
    def generate_pdf_preview(self):
        """Generate a PDF preview of the document."""
        template_id = self.env.ref('your_module_name.barcode_stamp_footer')  # Reemplaza 'your_module_name' por el nombre de tu módulo
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
        record.sudo().message_post(
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


    # -------------------------------------------------------------------------
    # OBTENER SEMILLA, FIRMAR, PEDIR TOKEN
    # -------------------------------------------------------------------------


    # def _get_seed(self):
    #     """
    #     Obtiene y procesa una semilla desde el servicio CrSeed.jws.
    #     """
    #     seed_url = "https://palena.sii.cl/DTEWS/CrSeed.jws"
    #     soap_request = """
    #     <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    #         <soapenv:Header/>
    #         <soapenv:Body>
    #             <getSeed/>
    #         </soapenv:Body>
    #     </soapenv:Envelope>
    #     """
    #     # Enviar solicitud SOAP
    #     response_data = self._send_soap_request(seed_url, soap_request, 'urn:getSeed')

    #     # Parsear la respuesta SOAP
    #     response_root = etree.fromstring(response_data.encode('utf-8'))
    #     ns = {'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/'}

    #     # Extraer el nodo getSeedReturn
    #     get_seed_return = response_root.find('.//soapenv:Body//getSeedResponse//getSeedReturn', namespaces=ns)
    #     if get_seed_return is None or not get_seed_return.text:
    #         raise UserError("No se encontró el nodo 'getSeedReturn' en la respuesta SOAP.")

    #     # Desescapar contenido
    #     unescaped_content = html.unescape(get_seed_return.text)
    #     decoded_response = etree.fromstring(unescaped_content.encode('utf-8'))

    #     # Buscar RESP_BODY con namespace
    #     sii_ns = {'SII': 'http://www.sii.cl/XMLSchema'}
    #     resp_body_node = decoded_response.find('.//SII:RESP_BODY', namespaces=sii_ns)
    #     if resp_body_node is None:
    #         raise UserError("No se encontró el nodo 'RESP_BODY' con prefijo SII.")

    #     # Dentro de RESP_BODY, buscar SEMILLA (sin namespace)
    #     seed_node = resp_body_node.find('SEMILLA')
    #     if seed_node is None or not seed_node.text:
    #         raise UserError("No se encontró el nodo 'SEMILLA' en el XML procesado.")

    #     return seed_node.text

    # def _sign_seed(self, seed):
    #     """
    #     Firma la semilla utilizando el certificado configurado y devuelve el XML firmado
    #     en el formato que exige el SII (sin prefijo ds:, sin cabeceras PEM, y sin <?xml ...>).
    #     """
    #     try:
    #         # 1) Obtener y validar el certificado activo
    #         certificate = self._get_active_certificate()
    #         if not certificate.signature_key_file or not certificate.signature_pass_phrase:
    #             raise UserError("El certificado configurado no es válido o falta la contraseña.")

    #         # 2) Cargar el PKCS12
    #         pfx_data = base64.b64decode(certificate.signature_key_file)
    #         p12 = crypto.load_pkcs12(pfx_data, certificate.signature_pass_phrase.encode('utf-8'))

    #         # 3) Extraer clave privada
    #         private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
    #         private_key = load_pem_private_key(private_key_pem, password=None, backend=default_backend())

    #         # 4) Extraer certificado en PEM, quitar BEGIN/END y saltos de línea para dejar solo Base64
    #         public_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())
    #         public_cert_pem_str = public_cert_pem.decode('utf-8')
    #         public_cert_pem_str = public_cert_pem_str.replace("-----BEGIN CERTIFICATE-----", "")
    #         public_cert_pem_str = public_cert_pem_str.replace("-----END CERTIFICATE-----", "")
    #         public_cert_pem_str = public_cert_pem_str.replace("\n", "").strip()
    #         x509_cert_b64 = public_cert_pem_str  # Esto es solo el contenido base64 del certificado

    #         # -------------------- Construir el XML <getToken> --------------------
    #         # <getToken>
    #         get_token = etree.Element("getToken")

    #         # <item><Semilla>...</Semilla></item>
    #         item = etree.SubElement(get_token, "item")
    #         etree.SubElement(item, "Semilla").text = seed

    #         # <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    #         signature_node = etree.Element("Signature", nsmap={None: "http://www.w3.org/2000/09/xmldsig#"})

    #         # <SignedInfo>
    #         signed_info = etree.SubElement(signature_node, "SignedInfo")
    #         etree.SubElement(
    #             signed_info,
    #             "CanonicalizationMethod",
    #             Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    #         )
    #         etree.SubElement(
    #             signed_info,
    #             "SignatureMethod",
    #             Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    #         )
    #         reference = etree.SubElement(signed_info, "Reference", URI="")
    #         transforms = etree.SubElement(reference, "Transforms")
    #         etree.SubElement(
    #             transforms,
    #             "Transform",
    #             Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    #         )
    #         etree.SubElement(
    #             reference,
    #             "DigestMethod",
    #             Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"
    #         )

    #         # Calcular <DigestValue> de la semilla
    #         digest = hashlib.sha1(seed.encode('utf-8')).digest()
    #         digest_value = base64.b64encode(digest).decode('utf-8')
    #         etree.SubElement(reference, "DigestValue").text = digest_value

    #         # Firmar <SignedInfo>
    #         signed_info_c14n = etree.tostring(
    #             signed_info,
    #             method="c14n",
    #             exclusive=True,
    #             with_comments=False
    #         )
    #         signature = private_key.sign(
    #             signed_info_c14n,
    #             padding.PKCS1v15(),
    #             hashes.SHA1()
    #         )
    #         signature_value = base64.b64encode(signature).decode('utf-8')

    #         # <SignatureValue> con la firma resultante
    #         etree.SubElement(signature_node, "SignatureValue").text = signature_value

    #         # <KeyInfo><KeyValue><RSAKeyValue><Modulus> + <Exponent>
    #         key_info = etree.SubElement(signature_node, "KeyInfo")
    #         key_value = etree.SubElement(key_info, "KeyValue")
    #         rsa_key_value = etree.SubElement(key_value, "RSAKeyValue")

    #         # Modulus
    #         modulus = base64.b64encode(
    #             private_key.private_numbers().public_numbers.n.to_bytes(
    #                 (private_key.private_numbers().public_numbers.n.bit_length() + 7) // 8,
    #                 byteorder="big"
    #             )
    #         ).decode('utf-8')
    #         etree.SubElement(rsa_key_value, "Modulus").text = modulus

    #         # Exponent
    #         exponent = base64.b64encode(
    #             private_key.private_numbers().public_numbers.e.to_bytes(
    #                 (private_key.private_numbers().public_numbers.e.bit_length() + 7) // 8,
    #                 byteorder="big"
    #             )
    #         ).decode('utf-8')
    #         etree.SubElement(rsa_key_value, "Exponent").text = exponent

    #         # <X509Data><X509Certificate>
    #         x509_data = etree.SubElement(key_info, "X509Data")
    #         etree.SubElement(x509_data, "X509Certificate").text = x509_cert_b64

    #         # Insertar el nodo <Signature> en <getToken>
    #         get_token.append(signature_node)

    #         # Convertir a string, sin <?xml ?> (xml_declaration=False)
    #         signed_xml = etree.tostring(
    #             get_token,
    #             pretty_print=True,
    #             encoding="UTF-8",
    #             xml_declaration=False
    #         ).decode('utf-8')

    #         _logger.info("Semilla firmada correctamente (sin prefijo ds:, sin cabeceras PEM).")
    #         return signed_xml

    #     except Exception as e:
    #         _logger.error(f"Error al firmar la semilla: {e}")
    #         raise UserError(f"Error al firmar la semilla: {e}")

    def _get_token_from_internal_api(self):
        """
        Obtiene el token desde la API interna.
        """
        ICP = self.env['ir.config_parameter'].sudo()

        # Obtener la configuración desde Ajustes
        api_login_url = ICP.get_param('my_module.api_login_url') or ''
        api_sii_token_url = ICP.get_param('my_module.api_sii_token_url') or ''
        email_api = ICP.get_param('my_module.api_user') or ''
        pass_api = ICP.get_param('my_module.api_pass') or ''

        # Validar que tengamos todo para la conexión
        if not api_login_url or not api_sii_token_url or not email_api or not pass_api:
            raise UserError(_("Falta configuración de la API interna. Revisa Ajustes."))

        # Realizar la solicitud de login
        payload_login = {
            'email': email_api,
            'password': pass_api,
        }
        try:
            # Enviar los datos como `form-data`
            _logger.info(f"Enviando solicitud de login a {api_login_url} con usuario {email_api}.")
            resp_login = requests.post(api_login_url, data=payload_login, timeout=30)
        except requests.exceptions.RequestException as e:
            raise UserError(_("Error de conexión al hacer login en la API interna: %s") % str(e))

        if resp_login.status_code != 200:
            raise UserError(_("Error en login. Respuesta HTTP: %s\nDetalle: %s") %
                            (resp_login.status_code, resp_login.text))

        data_login = resp_login.json()
        login_token = data_login.get('token')
        if not login_token:
            raise UserError(_("No se obtuvo 'token' de la API interna en la etapa de login."))

        # Registrar en los logs para debug
        _logger.info(f"Token de login obtenido: {login_token}")

        # Solicitar el token SII usando el token de login
        headers = {
            'Authorization': f"Bearer {login_token}"
        }
        try:
            _logger.info(f"Solicitando token SII a {api_sii_token_url}.")
            resp_sii = requests.post(api_sii_token_url, headers=headers, timeout=30)
        except requests.exceptions.RequestException as e:
            raise UserError(_("Error de conexión al pedir token SII: %s") % str(e))

        if resp_sii.status_code != 200:
            raise UserError(_("Error al pedir token SII. Respuesta HTTP: %s\nDetalle: %s") %
                            (resp_sii.status_code, resp_sii.text))

        data_sii = resp_sii.json()
        sii_token = data_sii.get('success', {}).get('descripcionRespuesta', {}).get('token')

        if not sii_token:
            raise UserError(_("No se obtuvo 'token' de la API interna (ruta success.descripcionRespuesta.token)."))

        _logger.info(f"Token SII obtenido: {sii_token}")

        return sii_token

    def _split_vat(self, vat_string):
        """
        Recibe un RUT completo '12345678-9' (con o sin puntos) y retorna (rut, dv).
        """
        rut_clean = vat_string.replace('.', '').replace('-', '')
        return rut_clean[:-1], rut_clean[-1]

    def _get_token(self, signed_seed):
        """
        Intercambio de semilla firmada por Token con el SII.
        """
        token_url = "https://palena.sii.cl/DTEWS/GetTokenFromSeed.jws"
        soap_request = f"""
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <getToken xmlns="http://www.sii.cl/XMLSchema">
                    <pszXml><![CDATA[{signed_seed}]]></pszXml>
                </getToken>
            </soapenv:Body>
        </soapenv:Envelope>
        """

        response_data = self._send_soap_request(token_url, soap_request, 'urn:getToken')
        # Guardar la respuesta cruda
        self.response_raw = response_data  

        # La respuesta real viene dentro de <getTokenReturn>...</getTokenReturn>
        response_root = etree.fromstring(response_data.encode('utf-8'))
        sii_ns = {'SII': 'http://www.sii.cl/XMLSchema'}
        # Se espera <SII:RESP_BODY><TOKEN>...</TOKEN></SII:RESP_BODY>
        token_node = response_root.find('.//SII:RESP_BODY/TOKEN', namespaces=sii_ns)

        # Si no hay <TOKEN>, es que el SII devolvió error (p.e. ESTADO=10, GLOSA=Error Interno)
        if token_node is None or not token_node.text:
            # Publica también la respuesta (estado 10) en el chatter para debug
            self.post_xml_to_chatter(response_data, description="Respuesta SII: Error, no se encontró TOKEN")
            raise UserError("No se encontró el nodo 'TOKEN' en la respuesta. Posible error interno del SII.")

        return token_node.text

    # -------------------------------------------------------------------------
    # ENVÍO DE SOLICITUDES SOAP
    # -------------------------------------------------------------------------


    @api.model
    def _send_soap_request(self, url, soap_body, soap_action_header=''):
        _logger.info(f"Enviando solicitud SOAP a {url}.")
        # --> Si quieres ver en el log la request completa:
        _logger.info(f"SOAP Request Body:\n{soap_body}")

        self.post_xml_to_chatter(soap_body, description=f"SOAP Request to {url}")
        self._store_soap_documents("soap_request", soap_body)

        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': soap_action_header,
        }
        try:
            response = requests.post(url, data=soap_body.encode('utf-8'), headers=headers, timeout=30)
            if response.status_code != 200:
                _logger.error(f"Error HTTP {response.status_code}: {response.text}")
                raise UserError(f"Error SOAP. Código HTTP: {response.status_code}")

            # --> Si quieres ver en el log la response completa:
            _logger.info(f"SOAP Response Body:\n{response.text}")

            self.post_xml_to_chatter(response.text, description=f"SOAP Response from {url}")
            self._store_soap_documents("soap_response", response.text)

            return response.text

        except requests.exceptions.RequestException as e:
            _logger.error(f"Error al enviar solicitud SOAP: {e}")
            raise UserError(f"Error al enviar solicitud SOAP: {e}")


    # -------------------------------------------------------------------------
    # AYUDANTES PARA CERTIFICADOS Y LOG
    # -------------------------------------------------------------------------

    def _get_active_certificate(self):
        """
        Busca un certificado activo y válido configurado.
        """
        certificate = self.env['l10n_cl.certificate'].sudo().search([], limit=1)
        if not certificate:
            raise UserError("No se encontró ningún certificado configurado.")
        if not certificate._is_valid_certificate():
            raise UserError("El certificado configurado está expirado o no es válido.")
        return certificate

    def post_xml_to_chatter(self, xml_content, description="XML generado"):
        """
        Registra el contenido en el Chatter (como texto con <pre>).
        """
        escaped_xml = html.escape(xml_content or "")
        self.message_post(
            body=f"<b>{description}</b><br/><pre style='white-space: pre-wrap;'>{escaped_xml}</pre>",
            subject=description,
            message_type='comment',
            subtype_xmlid='mail.mt_note',
        )


    def _store_soap_documents(self, tag_name, content):
        """
        Guarda 'content' en el campo xml_signed_file como un adjunto base64.
        """
        try:
            txt = f"--- {tag_name.upper()} ---\n{content}"
            content_binary = base64.b64encode(txt.encode('utf-8'))
            self.xml_signed_file = content_binary
            self.message_post(
                body=f"{tag_name} guardado en xml_signed_file",
                subject="Registro SOAP",
                message_type='comment',
                subtype_xmlid='mail.mt_note',
            )
        except Exception as e:
            _logger.error(f"Error al guardar {tag_name}: {e}")
            raise UserError(f"Error al guardar {tag_name}: {e}")


    # get dte claim funcional ok
    def _get_dte_claim(self, emitter_vat, document_type_code, document_number, date_emission, amount_total):
        """
        Consultar estado del DTE en SII (documento que hemos recibido).
        - emitter_vat: RUT completo del Emisor (ej. '12345678-9')
        - document_type_code: Ej. '33'
        - document_number: Folio del DTE
        - date_emission: Fecha datetime/date en Odoo
        - amount_total: Monto total del DTE
        """
        try:
            # 1) Preparar RUT consultante y receptor (tu misma empresa, pues recibes el DTE).
            if not self.env.company.vat:
                raise UserError("No está configurado el RUT de la compañía en Odoo.")
            rut_consultante, dv_consultante = self._split_vat(self.env.company.vat)
            rut_receptor, dv_receptor = rut_consultante, dv_consultante  # Mismo RUT si documento es recibido

            # 2) Preparar RUT compañía emisora (desde 'emitter_vat').
            if not emitter_vat:
                raise UserError("No se proporcionó el RUT del Emisor para la consulta.")
            rut_compania, dv_compania = self._split_vat(emitter_vat)

            # 3) Obtener token de la API interna (o del método que uses para firmar semilla).
            _logger.info("Obteniendo token para la consulta del DTE...")
            token = self._get_token_from_internal_api()
            if not token:
                raise UserError("No se pudo obtener un token válido para la consulta al SII.")

            # 4) Construir la solicitud SOAP
            url = "https://palena.sii.cl/DTEWS/QueryEstDte.jws"
            soap_request = f"""
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dte="http://DefaultNamespace">
                <soapenv:Header/>
                <soapenv:Body>
                    <dte:getEstDte>
                        <RutConsultante>{rut_consultante}</RutConsultante>
                        <DvConsultante>{dv_consultante}</DvConsultante>
                        <RutCompania>{rut_compania}</RutCompania>
                        <DvCompania>{dv_compania}</DvCompania>
                        <RutReceptor>{rut_receptor}</RutReceptor>
                        <DvReceptor>{dv_receptor}</DvReceptor>
                        <TipoDte>{document_type_code}</TipoDte>
                        <FolioDte>{document_number}</FolioDte>
                        <FechaEmisionDte>{date_emission.strftime('%d-%m-%Y')}</FechaEmisionDte>
                        <MontoDte>{int(amount_total)}</MontoDte>
                        <Token>{token}</Token>
                    </dte:getEstDte>
                </soapenv:Body>
            </soapenv:Envelope>
            """
            _logger.info(f"Enviando solicitud SOAP a {url}:\n{soap_request}")

            # 5) Envío con urllib3
            http = urllib3.PoolManager()
            headers = {
                'Content-Type': 'text/xml; charset=utf-8',
                'SOAPAction': ''
            }
            response = http.request('POST', url, body=soap_request.encode('utf-8'), headers=headers)
            if response.status != 200:
                raise UserError(f"Error HTTP {response.status} en consulta al SII: {response.data}")

            # 6) Parsear respuesta SOAP
            #    OJO: La respuesta viene con un XML anidado dentro de <getEstDteReturn>
            #    Debes extraer ese segundo XML real donde sale <ESTADO>, <ERR_CODE>, etc.
            root_soap = etree.fromstring(response.data, etree.XMLParser(recover=True))
            
            # Buscar el tag <getEstDteReturn> que contiene el segundo XML en texto escapado
            ns_soap = {'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/', 'ns1': 'http://DefaultNamespace'}
            getEstDteReturn = root_soap.find('.//ns1:getEstDteReturn', namespaces=ns_soap)
            if getEstDteReturn is None or not getEstDteReturn.text:
                raise UserError("No se encontró <getEstDteReturn> con la respuesta del SII.")

            # Des-escape para obtener XML interno
            second_xml_unescaped = html.unescape(getEstDteReturn.text)
            # Parseamos el segundo XML, quitando la cabecera <?xml ...> si diera conflicto
            parser = etree.XMLParser(remove_encoding_decl=True, recover=True)
            second_root = etree.fromstring(second_xml_unescaped.encode('utf-8'), parser=parser)

            # 7) Extraer datos: <ESTADO>, <ERR_CODE>, <GLOSA_ERR>, etc.
            sii_ns = {'SII': 'http://www.sii.cl/XMLSchema'}
            estado_node = second_root.find('.//SII:RESP_HDR/SII:ESTADO', namespaces=sii_ns)
            err_code_node = second_root.find('.//SII:RESP_HDR/SII:ERR_CODE', namespaces=sii_ns)
            glosa_err_node = second_root.find('.//SII:RESP_HDR/SII:GLOSA_ERR', namespaces=sii_ns)

            estado = estado_node.text if estado_node is not None else ''
            err_code = err_code_node.text if err_code_node is not None else ''
            glosa_err = glosa_err_node.text if glosa_err_node is not None else ''

            _logger.info(f"Respuesta SII => ESTADO: {estado}, ERR_CODE: {err_code}, GLOSA_ERR: {glosa_err}")

            # 8) Manejo de la lógica de resultado
            if err_code:
                # Ejemplo: -1861 => "Error Interno"
                raise UserError(f"Consulta SII con error. ERR_CODE: {err_code}, GLOSA_ERR: {glosa_err}")

            return estado  # Retorna el código de estado SII (e.g. '0', '1', etc.)

        except Exception as e:
            _logger.error(f"Error consultando el estado del DTE: {e}")
            raise UserError(f"Error al consultar el estado del DTE en el SII: {e}")
    


    # def _get_private_key_modulus(self, private_key):
    #     """
    #     Obtiene el módulo de la clave privada en formato Base64.
    #     """
    #     numbers = private_key.private_numbers()
    #     return base64.b64encode(numbers.public_numbers.n.to_bytes((numbers.public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8')

    # -------------------------------------------------------------------------
    # FUNCIONES PRINCIPALES PARA CONSULTAR ESTADO AL SII
    # -------------------------------------------------------------------------
    def check_sii_status(self):
        """
        Consulta el estado del DTE en el SII y registra los XML generados en el Chatter,
        tomando a rut_compania desde company_rut (emisor) y rut_consultante/receptor
        desde la empresa principal en Odoo.
        """
        self.ensure_one()
        try:
            _logger.info(
                f"Consultando el estado del DTE en el SII para la factura {self.name}, "
                f"TipoDoc: {self.document_type.code}, Folio: {self.folio_number}"
            )

            # 1) Validar que tengas la info necesaria
            if not self.env.company.vat:
                raise UserError("No se ha definido el RUT de tu compañía principal (env.company.vat).")

            if not self.company_rut:
                raise UserError("No existe RUT Emisor en el campo company_rut.")

            if not self.date_emission:
                raise UserError("La factura no tiene Fecha de Emisión (date_emission).")

            # 2) Preparar datos para la consulta
            #    - Emisor = company_rut (desde el XML)
            #    - Consultante/Receptor = tu compañía (env.company.vat)
            rut_consultante, dv_consultante = self._split_vat(self.env.company.vat)
            rut_compania, dv_compania = self._split_vat(self.company_rut)
            # En un DTE recibido, Receptor es tu propio RUT
            rut_receptor, dv_receptor = rut_consultante, dv_consultante

            # 3) Obtener token SII desde tu API interna
            token = self._get_token_from_internal_api()
            _logger.info(f"Token obtenido correctamente (vía API interna): {token}")

            # 4) Armar solicitud SOAP
            soap_request = f"""
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dte="http://DefaultNamespace">
                <soapenv:Header/>
                <soapenv:Body>
                    <dte:getEstDte>
                        <RutConsultante>{rut_consultante}</RutConsultante>
                        <DvConsultante>{dv_consultante}</DvConsultante>
                        <RutCompania>{rut_compania}</RutCompania>
                        <DvCompania>{dv_compania}</DvCompania>
                        <RutReceptor>{rut_receptor}</RutReceptor>
                        <DvReceptor>{dv_receptor}</DvReceptor>
                        <TipoDte>{self.document_type.code}</TipoDte>
                        <FolioDte>{self.folio_number}</FolioDte>
                        <FechaEmisionDte>{self.date_emission.strftime('%d-%m-%Y')}</FechaEmisionDte>
                        <MontoDte>{int(self.amount_total)}</MontoDte>
                        <Token>{token}</Token>
                    </dte:getEstDte>
                </soapenv:Body>
            </soapenv:Envelope>
            """

            #self.post_xml_to_chatter(soap_request, description="Solicitud SOAP Consulta Estado DTE")
            status_url = "https://palena.sii.cl/DTEWS/QueryEstDte.jws"

            # 5) Enviar la solicitud
            response_data = self._send_soap_request(status_url, soap_request, '')

            # Guardar la respuesta en el Chatter
            #self.post_xml_to_chatter(response_data, description="Respuesta SOAP Consulta Estado DTE")
            _logger.info(f"Respuesta de estado DTE: {response_data}")

            # 6) Parsear la respuesta para extraer <ESTADO> y <GLOSA>
            response_root = etree.fromstring(response_data.encode('utf-8'), etree.XMLParser(recover=True))
            namespaces = {'SII': 'http://www.sii.cl/XMLSchema', 'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/'}
            estado_element = response_root.find('.//SII:RESP_HDR/SII:ESTADO', namespaces=namespaces)
            estado = estado_element.text if estado_element is not None else 'unknown'
            glosa_element = response_root.find('.//SII:RESP_HDR/SII:GLOSA', namespaces=namespaces)
            glosa = glosa_element.text if glosa_element is not None else ''

            _logger.info(f"SII respondió ESTADO={estado}, GLOSA={glosa}")

            # 7) Actualizar el estado en Odoo
            if estado == '00':
                self.l10n_cl_dte_status = 'accepted'
            elif estado in ['01','02','03','04','05','06','07','08','09','10','11','12','-3']:
                self.l10n_cl_dte_status = 'rejected'
            else:
                self.l10n_cl_dte_status = 'ask_for_status'

            self.message_post(
                body=f"Estado del DTE consultado: {estado} - {glosa}",
                subject="Consulta de Estado DTE",
                message_type='comment',
                subtype_xmlid='mail.mt_note',
            )

        except Exception as e:
            _logger.error(f"Error consultando el estado del DTE: {e}")
            raise UserError(f"Error consultando el estado del DTE en el SII: {e}")



    #def validate xml funcional ok
    def _validate_sii_response(self, response_data):
        try:
            root = etree.fromstring(response_data)
            estado = root.find('.//ESTADO')
            if estado is None or estado.text != "00":
                raise UserError(f"Error en la respuesta del SII: {estado.text if estado is not None else 'Desconocido'}")
            return root
        except Exception as e:
            raise UserError(f"Respuesta del SII no válida: {e}")



    def _get_digest_value(self, data):
        """
        Calcula el DigestValue (SHA-1 en formato Base64) para el XML firmado.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')  # Asegurar que los datos estén en bytes

        # Calcular el hash SHA-1
        digest = hashlib.sha1(data).digest()

        # Convertir el resultado del hash a Base64
        return base64.b64encode(digest).decode('utf-8')

    def _get_signature_value(self, private_key, signed_info):
        """
        Firma el bloque SignedInfo usando la clave privada proporcionada.
        :param private_key: Clave privada en formato OpenSSL.
        :param signed_info: Bloque SignedInfo que se firmará.
        :return: La firma en Base64.
        """
        try:
            signature = crypto.sign(private_key, signed_info.encode('utf-8'), 'sha1')
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            raise UserError(f"Error al generar el SignatureValue: {str(e)}")



    def save_signed_xml(self, xml_signed):
        """
        Guarda el XML firmado en el campo `xml_signed_file`.
        """
        try:
            self.xml_signed_file = base64.b64encode(xml_signed.encode('utf-8'))
            _logger.info("El XML firmado ha sido almacenado correctamente en el campo `xml_signed_file`.")
        except Exception as e:
            _logger.error(f"Error al guardar el XML firmado: {e}")
            raise UserError(f"Error al guardar el XML firmado: {e}")



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

class APIConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    # Campos para tu configuración
    api_login_url = fields.Char(
        string="API Login URL",
        help="URL para la ruta de login de tu API interna.")
    api_user = fields.Char(
        string="Usuario para API",
        help="Usuario (o email) para autenticarse en la API interna.")
    api_pass = fields.Char(
        string="Contraseña para API",
        help="Contraseña para la API interna.",
        password=True)  # Esto enmascara la visualización
    api_sii_token_url = fields.Char(
        string="API SII Token URL",
        help="URL para el endpoint /api/facturacion/obtenerTokenSII de la API interna."
    )

    # Aquí, las "keys" que usaremos en ir.config_parameter
    @api.model
    def get_values(self):
        res = super(APIConfigSettings, self).get_values()
        ICP = self.env['ir.config_parameter'].sudo()
        res.update(
            api_login_url=ICP.get_param('my_module.api_login_url', default=''),
            api_sii_token_url=ICP.get_param('my_module.api_sii_token_url', default=''),
            api_user=ICP.get_param('my_module.api_user', default=''),
            api_pass=ICP.get_param('my_module.api_pass', default=''),
        )
        return res

    def set_values(self):
        super(APIConfigSettings, self).set_values()
        ICP = self.env['ir.config_parameter'].sudo()
        ICP.set_param('my_module.api_login_url', self.api_login_url or '')
        ICP.set_param('my_module.api_sii_token_url', self.api_sii_token_url or '')
        ICP.set_param('my_module.api_user', self.api_user or '')
        ICP.set_param('my_module.api_pass', self.api_pass or '')

