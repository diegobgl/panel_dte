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


    def _get_seed(self):
        """
        Obtiene y procesa una semilla desde el servicio CrSeed.jws.
        """
        seed_url = "https://palena.sii.cl/DTEWS/CrSeed.jws"
        soap_request = """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <getSeed/>
            </soapenv:Body>
        </soapenv:Envelope>
        """
        # Enviar solicitud SOAP
        response_data = self._send_soap_request(seed_url, soap_request, 'urn:getSeed')

        # Parsear la respuesta SOAP
        response_root = etree.fromstring(response_data.encode('utf-8'))
        ns = {'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/'}

        # Extraer el nodo getSeedReturn
        get_seed_return = response_root.find('.//soapenv:Body//getSeedResponse//getSeedReturn', namespaces=ns)
        if get_seed_return is None or not get_seed_return.text:
            raise UserError("No se encontró el nodo 'getSeedReturn' en la respuesta SOAP.")

        # Desescapar contenido
        unescaped_content = html.unescape(get_seed_return.text)
        decoded_response = etree.fromstring(unescaped_content.encode('utf-8'))

        # Buscar RESP_BODY con namespace
        sii_ns = {'SII': 'http://www.sii.cl/XMLSchema'}
        resp_body_node = decoded_response.find('.//SII:RESP_BODY', namespaces=sii_ns)
        if resp_body_node is None:
            raise UserError("No se encontró el nodo 'RESP_BODY' con prefijo SII.")

        # Dentro de RESP_BODY, buscar SEMILLA (sin namespace)
        seed_node = resp_body_node.find('SEMILLA')
        if seed_node is None or not seed_node.text:
            raise UserError("No se encontró el nodo 'SEMILLA' en el XML procesado.")

        return seed_node.text

    def _sign_seed(self, seed):
        """
        Firma la semilla utilizando el certificado configurado y devuelve el XML firmado.
        """
        # Obtener certificado
        certificate = self._get_active_certificate()
        if not certificate.signature_key_file or not certificate.signature_pass_phrase:
            raise UserError("El certificado configurado no es válido o falta la contraseña.")

        # Decodificar PKCS12
        pfx_data = base64.b64decode(certificate.signature_key_file)
        p12 = crypto.load_pkcs12(pfx_data, certificate.signature_pass_phrase.encode('utf-8'))

        # Extraer claves
        private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
        private_key = load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        public_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())
        x509_cert_b64 = base64.b64encode(public_cert).decode('utf-8')

        # Crear SignedInfo
        nsmap = {"ds": "http://www.w3.org/2000/09/xmldsig#"}
        signed_info = etree.Element("{http://www.w3.org/2000/09/xmldsig#}SignedInfo", nsmap=nsmap)
        etree.SubElement(
            signed_info,
            "{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod",
            Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        )
        etree.SubElement(
            signed_info,
            "{http://www.w3.org/2000/09/xmldsig#}SignatureMethod",
            Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        )
        reference = etree.SubElement(
            signed_info,
            "{http://www.w3.org/2000/09/xmldsig#}Reference",
            URI=""
        )
        transforms = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}Transforms")
        etree.SubElement(
            transforms,
            "{http://www.w3.org/2000/09/xmldsig#}Transform",
            Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"
        )
        etree.SubElement(
            reference,
            "{http://www.w3.org/2000/09/xmldsig#}DigestMethod",
            Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"
        )

        # DigestValue
        digest = hashlib.sha1(seed.encode('utf-8')).digest()
        digest_value = base64.b64encode(digest).decode('utf-8')
        etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}DigestValue").text = digest_value

        # Firmar
        signed_info_c14n = etree.tostring(signed_info, method="c14n", exclusive=True, with_comments=False)
        signature = private_key.sign(
            signed_info_c14n,
            padding.PKCS1v15(),
            hashes.SHA1()
        )
        signature_value = base64.b64encode(signature).decode('utf-8')

        # KeyInfo
        key_info = etree.Element("{http://www.w3.org/2000/09/xmldsig#}KeyInfo", nsmap=nsmap)
        key_value = etree.SubElement(key_info, "{http://www.w3.org/2000/09/xmldsig#}KeyValue")
        rsa_key_value = etree.SubElement(key_value, "{http://www.w3.org/2000/09/xmldsig#}RSAKeyValue")

        # Modulus
        modulus = base64.b64encode(
            private_key.private_numbers().public_numbers.n.to_bytes(
                (private_key.private_numbers().public_numbers.n.bit_length() + 7) // 8,
                byteorder="big"
            )
        ).decode('utf-8')
        # Exponent
        exponent = base64.b64encode(
            private_key.private_numbers().public_numbers.e.to_bytes(
                (private_key.private_numbers().public_numbers.e.bit_length() + 7) // 8,
                byteorder="big"
            )
        ).decode('utf-8')

        etree.SubElement(rsa_key_value, "{http://www.w3.org/2000/09/xmldsig#}Modulus").text = modulus
        etree.SubElement(rsa_key_value, "{http://www.w3.org/2000/09/xmldsig#}Exponent").text = exponent

        x509_data = etree.SubElement(key_info, "{http://www.w3.org/2000/09/xmldsig#}X509Data")
        etree.SubElement(x509_data, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate").text = x509_cert_b64

        # Construir Signature
        signature_node = etree.Element("{http://www.w3.org/2000/09/xmldsig#}Signature", nsmap=nsmap)
        signature_node.append(signed_info)
        etree.SubElement(signature_node, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue").text = signature_value
        signature_node.append(key_info)

        # Envolver en getToken -> item -> Semilla
        get_token = etree.Element("getToken")
        item = etree.SubElement(get_token, "item")
        etree.SubElement(item, "Semilla").text = seed
        get_token.append(signature_node)

        # XML final firmado
        signed_xml = etree.tostring(
            get_token, pretty_print=True, xml_declaration=True, encoding="UTF-8"
        ).decode('utf-8')

        # También puedes guardarlo en self.xml_signed_file si gustas:
        # self._store_soap_documents("Signed Seed", signed_xml)

        _logger.info("Semilla firmada correctamente.")
        return signed_xml


    

        #get token funcional 
   
   
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


    def _send_soap_request(self, url, soap_body, soap_action_header=''):
        """
        Envía una solicitud SOAP al SII y registra request/response.
        """
        _logger.info(f"Enviando solicitud SOAP a {url}.")
        _logger.debug(f"SOAP Body:\n{soap_body}")

        # Publicar en Chatter la request si quieres:
        # self.post_xml_to_chatter(soap_body, description=f"SOAP Request to {url}")

        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': soap_action_header
        }
        try:
            response = requests.post(url, data=soap_body.encode('utf-8'), headers=headers, timeout=30)
            if response.status_code != 200:
                _logger.error(f"Error HTTP {response.status_code}: {response.text}")
                raise UserError(f"Error SOAP. Código HTTP: {response.status_code}")

            # Publicar en Chatter la response si quieres:
            # self.post_xml_to_chatter(response.text, description=f"SOAP Response from {url}")

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
        Registra cualquier contenido (SOAP, XML, etc.) en el Chatter.
        """
        escaped_xml = html.escape(xml_content)
        self.message_post(
            body=f"<b>{description}</b><br/><pre style='white-space: pre-wrap;'>{escaped_xml}</pre>",
            subject=description,
            message_type='comment',
            subtype_xmlid='mail.mt_note',
        )

    def _store_soap_documents(self, tag_name, content):
        """
        Guarda el contenido en el campo `xml_signed_file` como adjunto base64,
        por si lo quieres descargar luego.
        """
        try:
            txt = f"--- {tag_name} ---\n{content}"
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
    def _get_dte_claim(self, company_vat, digital_signature, document_type_code, document_number, date_emission, amount_total):
        """Consultar estado del DTE en SII usando urllib3."""
        try:
            # URL del servicio SOAP
            url = "https://palena.sii.cl/DTEWS/QueryEstDte.jws"

            # Generar un nuevo token antes de la consulta
            _logger.info("Generando token para la consulta del DTE.")
            token = self.env['l10n_cl.edi.util']._get_token('SII', digital_signature)
            if not token:
                raise UserError("No se pudo generar un token válido para la consulta al SII.")

            # Separar RUT y dígito verificador
            rut_emisor = str(company_vat[:-2])
            dv_emisor = str(company_vat[-1])
            rut_receptor = str(self.partner_rut[:-2])
            dv_receptor = str(self.partner_rut[-1])
            rut_consultante = str(company_vat[:-2])
            dv_consultante = str(company_vat[-1])

            # Crear el cuerpo del XML para la solicitud SOAP
            soap_request = f"""
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dte="http://DefaultNamespace">
            <soapenv:Header/>
            <soapenv:Body>
                <dte:getEstDte>
                    <RutConsultante>{rut_consultante}</RutConsultante>
                    <DvConsultante>{dv_consultante}</DvConsultante>
                    <RutCompania>{rut_emisor}</RutCompania>
                    <DvCompania>{dv_emisor}</DvCompania>
                    <RutReceptor>{rut_receptor}</RutReceptor>
                    <DvReceptor>{dv_receptor}</DvReceptor>
                    <TipoDte>{document_type_code}</TipoDte>
                    <FolioDte>{document_number}</FolioDte>
                    <FechaEmisionDte>{date_emission.strftime('%Y-%m-%d')}</FechaEmisionDte>
                    <MontoDte>{int(amount_total)}</MontoDte>
                    <Token>{token}</Token>
                </dte:getEstDte>
            </soapenv:Body>
            </soapenv:Envelope>
            """

            _logger.info(f"Enviando solicitud al SII con los siguientes parámetros:\n{soap_request}")

            # Configurar urllib3
            http = urllib3.PoolManager()
            headers = {
                'Content-Type': 'text/xml; charset=utf-8',
                'SOAPAction': ''
            }

            # Enviar la solicitud
            response = http.request(
                'POST',
                url,
                body=soap_request.encode('utf-8'),
                headers=headers
            )

            # Validar el código de respuesta HTTP
            if response.status != 200:
                _logger.error(f"Error HTTP al consultar el estado del DTE: {response.status}")
                raise UserError(f"Error HTTP al consultar el estado del DTE: {response.status}")

            # Parsear la respuesta SOAP
            response_xml = etree.fromstring(response.data)
            _logger.info(f"Respuesta completa del SII: {etree.tostring(response_xml, pretty_print=True).decode()}")

            # Extraer el estado del DTE desde la respuesta
            ns = {'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
                'sii': 'http://www.sii.cl/XMLSchema'}
            estado = response_xml.xpath('//sii:ESTADO', namespaces=ns)
            glosa = response_xml.xpath('//sii:GLOSA', namespaces=ns)

            if estado and estado[0].text == '001':
                _logger.error(f"Error del SII: {glosa[0].text if glosa else 'TOKEN NO EXISTE'}")
                raise UserError(f"Error del SII: {glosa[0].text if glosa else 'TOKEN NO EXISTE'}")

            return estado[0].text if estado else None

        except Exception as e:
            _logger.error(f"Error general al consultar el estado del DTE: {e}")
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
        Consulta el estado del DTE en el SII y registra los XML generados en el Chatter.
        """
        self.ensure_one()
        try:
            # Logueamos en el servidor
            _logger.info(
                f"Consultando estado DTE en SII para el RUT: {self.company_rut}, "
                f"TipoDoc: {self.document_type.code}, Folio: {self.folio_number}"
            )

            # 1) Obtener la semilla
            seed = self._get_seed()
            self.post_xml_to_chatter(seed, description="Semilla Obtenida (Texto plano)")
            _logger.info(f"Semilla obtenida: {seed}")

            # 2) Firmar la semilla
            signed_seed = self._sign_seed(seed)
            self.post_xml_to_chatter(signed_seed, description="Semilla Firmada (XML)")

            # 3) Obtener el token
            token = self._get_token(signed_seed)
            _logger.info(f"Token obtenido correctamente: {token}")

            # 4) Construir la solicitud SOAP para consultar estado del DTE
            soap_request = f"""
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dte="http://DefaultNamespace">
                <soapenv:Header/>
                <soapenv:Body>
                    <dte:getEstDte>
                        <RutConsultante>{self.company_rut[:-2]}</RutConsultante>
                        <DvConsultante>{self.company_rut[-1]}</DvConsultante>
                        <RutCompania>{self.company_rut[:-2]}</RutCompania>
                        <DvCompania>{self.company_rut[-1]}</DvCompania>
                        <RutReceptor>{self.partner_rut[:-2]}</RutReceptor>
                        <DvReceptor>{self.partner_rut[-1]}</DvReceptor>
                        <TipoDte>{self.document_type.code}</TipoDte>
                        <FolioDte>{self.folio_number}</FolioDte>
                        <FechaEmisionDte>{self.date_emission.strftime('%Y-%m-%d')}</FechaEmisionDte>
                        <MontoDte>{int(self.amount_total)}</MontoDte>
                        <Token>{token}</Token>
                    </dte:getEstDte>
                </soapenv:Body>
            </soapenv:Envelope>
            """
            self.post_xml_to_chatter(soap_request, description="Solicitud SOAP Consulta Estado DTE")

            # 5) Enviar la solicitud
            status_url = "https://palena.sii.cl/DTEWS/QueryEstDte.jws"
            response_data = self._send_soap_request(status_url, soap_request, '')

            # Guardar la respuesta en el Chatter
            self.post_xml_to_chatter(response_data, description="Respuesta SOAP Consulta Estado DTE")
            _logger.info(f"Respuesta de estado DTE: {response_data}")

            # 6) Parsear la respuesta
            response_root = etree.fromstring(response_data)
            namespaces = {
                'SII': 'http://www.sii.cl/XMLSchema',
                'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/'
            }
            estado_element = response_root.find('.//SII:RESP_HDR/SII:ESTADO', namespaces=namespaces)
            estado = estado_element.text if estado_element is not None else 'unknown'

            glosa_element = response_root.find('.//SII:RESP_HDR/SII:GLOSA', namespaces=namespaces)
            glosa = glosa_element.text if glosa_element is not None else ''

            # 7) Actualizar estado en este registro
            if estado == '00':
                self.l10n_cl_dte_status = 'accepted'
            elif estado in ['01','02','03','04','05','06','07','08','09','10','11','12','-3']:
                self.l10n_cl_dte_status = 'rejected'
            else:
                self.l10n_cl_dte_status = 'ask_for_status'

            # Mensaje final en chatter
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
