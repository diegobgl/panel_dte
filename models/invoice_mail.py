import requests
import urllib3
from odoo import models, fields, api
from odoo.tools import email_split
from odoo.exceptions import UserError
import base64
import xml.etree.ElementTree as ET
import signxml
from lxml import etree
from signxml import XMLSigner, XMLVerifier
import logging
import html
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization

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
    xml_signed_file = fields.Binary(string="Archivo XML Firmado", attachment=True)





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

    def _get_active_certificate(self):
        """Busca el certificado activo y válido. Lanza un error si no lo encuentra."""
        certificate = self.env['l10n_cl.certificate'].sudo().search([], limit=1)
        if not certificate:
            raise UserError("No se encontró ningún certificado configurado en el sistema.")
        if not certificate._is_valid_certificate():
            raise UserError("El certificado configurado está expirado o no es válido.")
        return certificate
    


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
    
    

        #get token funcional 
   
   
    def _get_token(self, signed_seed):
            """
            Solicita el token al SII utilizando la semilla firmada.
            """
            token_url = "https://palena.sii.cl/DTEWS/GetTokenFromSeed.jws"  # Reemplazar con URL correcta

            try:
                _logger.info("Solicitando el token al SII.")

                soap_request = f"""
                <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                    <soapenv:Header/>
                    <soapenv:Body>
                        <getToken xmlns="https://palena.sii.cl/DTEWS/GetTokenFromSeed.jws">
                            <pszXml><![CDATA[{signed_seed}]]></pszXml>
                        </getToken>
                    </soapenv:Body>
                </soapenv:Envelope>
                """
                self.save_signed_xml(signed_seed)
                self.post_xml_to_chatter(soap_request, description="Solicitud de Token al SII")

                response_data = self._send_soap_request(token_url, soap_request, 'urn:getToken')

                response_xml = etree.fromstring(response_data.encode('utf-8')) # Codifica la respuesta a bytes
                ns = {'ns1': 'https://palena.sii.cl/DTEWS/GetTokenFromSeed.jws'}
                get_token_return = response_xml.find('.//ns1:getTokenReturn', namespaces=ns)

                if get_token_return is None or not get_token_return.text:
                    raise UserError("No se encontró el nodo getTokenReturn o su contenido está vacío en la respuesta del SII.")

                decoded_token_xml = html.unescape(get_token_return.text)
                token_root = etree.fromstring(decoded_token_xml.encode('utf-8')) # Codifica la respuesta a bytes

                token = token_root.find('.//TOKEN')
                if token is None or not token.text:
                    raise UserError("No se pudo encontrar el token en la respuesta decodificada del SII.")

                _logger.info(f"Token obtenido correctamente: {token.text}")
                return token.text

            except Exception as e:
                _logger.error(f"Error al obtener el token desde el SII: {e}")
                raise UserError(f"Error al obtener el token desde el SII: {e}")

    def _send_soap_request(self, url, soap_body, soap_action_header):
        """
        Envía una solicitud SOAP al SII.

        :param url: URL del servicio web del SII.
        :param soap_body: Cuerpo de la solicitud SOAP en formato XML.
        :param soap_action_header: Valor para el header SOAPAction.
        :return: Respuesta del SII como string.
        """
        http = urllib3.PoolManager()
        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': soap_action_header
        }

        try:
            response = http.request('POST', url, body=soap_body.encode('utf-8'), headers=headers)

            if response.status != 200:
                _logger.error(f"Error HTTP {response.status} al enviar solicitud a {url}")
                raise UserError(f"Error HTTP {response.status} al enviar solicitud a {url}")

            response_data = response.data.decode('utf-8')
            _logger.info(f"Respuesta de {url}:\n{response_data}")
            self.post_xml_to_chatter(response_data, description=f"Respuesta del SII para {soap_action_header}")

            return response_data

        except Exception as e:
            _logger.error(f"Error al enviar solicitud SOAP a {url}: {e}")
            raise UserError(f"Error al enviar solicitud SOAP a {url}: {e}")



    def _get_seed(self):
            """Solicita la semilla desde el SII y registra la salida en el chatter."""
            seed_url = "https://palena.sii.cl/DTEWS/CrSeed.jws"

            try:
                _logger.info("Solicitando la semilla al SII.")
                self.sudo().message_post(
                    body="Iniciando solicitud de semilla al SII.",
                    subject="Solicitud de Semilla",
                    message_type='notification',
                )

                soap_request = """
                <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                    <soapenv:Header/>
                    <soapenv:Body>
                        <getSeed/>
                    </soapenv:Body>
                </soapenv:Envelope>
                """
                response_data = self._send_soap_request(seed_url, soap_request, 'urn:getSeed')

                root = etree.fromstring(response_data.encode('utf-8')) # Codifica la respuesta a bytes
                ns = {'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/'}
                get_seed_return = root.find('.//soapenv:Body/getSeedResponse/getSeedReturn', namespaces=ns)

                if get_seed_return is None:
                    raise Exception("No se pudo encontrar el nodo getSeedReturn en la respuesta del SII.")

                decoded_response = html.unescape(get_seed_return.text)
                seed_root = etree.fromstring(decoded_response.encode('utf-8')) # Codifica la respuesta a bytes

                estado = seed_root.find('.//ESTADO').text
                if estado != "00":
                    glosa = seed_root.find('.//GLOSA').text or "Sin detalles."
                    raise Exception(f"Error al generar la semilla: {glosa}")

                semilla = seed_root.find('.//SEMILLA').text
                if not semilla:
                    raise Exception("No se pudo encontrar la semilla en la respuesta del SII.")

                self.sudo().message_post(
                    body=f"Semilla obtenida correctamente: {semilla}",
                    subject="Semilla Obtenida",
                    message_type='notification',
                )

                return semilla

            except Exception as e:
                _logger.error(f"Error al obtener la semilla desde el SII: {e}")
                self.sudo().message_post(
                    body=f"Error al obtener la semilla desde el SII: {e}",
                    subject="Error al Obtener Semilla",
                    message_type='notification',
                )
                raise UserError(f"Error al obtener la semilla desde el SII: {e}")

    def _sign_seed(self, seed):
        """
        Firma la semilla utilizando el certificado configurado y la librería signxml.
        """
        try:
            certificate = self._get_active_certificate()

            # Crear XML base con la semilla
            root = etree.Element("getToken")
            item = etree.SubElement(root, "item")
            etree.SubElement(item, "Semilla").text = seed

            # Usar signxml para firmar
            signer = XMLSigner(
                method=signxml.methods.Enveloped,
                signature_algorithm="rsa-sha1",
                digest_algorithm='sha1',
                c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            )
            signed_root = signer.sign(
                root,
                key=base64.b64decode(certificate.signature_key_file),
                cert=base64.b64decode(certificate.signature_cert_file),
                passphrase=certificate.signature_pass_phrase.encode()
            )

            signed_seed = etree.tostring(signed_root, encoding="UTF-8").decode("utf-8")

            return signed_seed

        except Exception as e:
            _logger.error(f"Error al firmar la semilla: {e}")
            raise UserError(f"Error al firmar la semilla: {e}")

    def _get_private_key_modulus(self, private_key):
        """
        Obtiene el módulo de la clave privada en formato Base64.
        """
        numbers = private_key.private_numbers()
        return base64.b64encode(numbers.public_numbers.n.to_bytes((numbers.public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8')

    def check_sii_status(self):
        """
        Consulta el estado del DTE en el SII y registra los XML generados en el Chatter.
        """
        self.ensure_one()
        try:
            _logger.info(f"Consultando el estado del DTE en el SII para el RUT: {self.company_rut}, TipoDoc: {self.document_type.code}, Folio: {self.folio_number}")

            # Solicitar la semilla
            seed = self._get_seed()
            _logger.info(f"Semilla obtenida: {seed}")

            # Firmar la semilla
            signed_seed = self._sign_seed(seed)
            _logger.info("Semilla firmada correctamente.")

            # Obtener el token
            token = self._get_token(signed_seed)
            _logger.info(f"Token obtenido correctamente: {token}")

            # Construir el cuerpo de la solicitud SOAP para consultar estado del DTE
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

            # Registrar la solicitud en el Chatter
            self.sudo().post_xml_to_chatter(soap_request, description="Solicitud de Estado del DTE al SII")

            # Enviar la solicitud
            status_url = "https://palena.sii.cl/DTEWS/QueryEstDte.jws" # URL de ejemplo, PRODUCCION es otra
            response_data = self._send_soap_request(status_url, soap_request, '')

            # Parsear la respuesta y registrar en el Chatter
            self.sudo().post_xml_to_chatter(response_data, description="Respuesta del SII para Consulta de Estado DTE")

            response_root = etree.fromstring(response_data)
            # Asegúrate de que los namespaces estén correctamente definidos
            namespaces = {'SII': 'http://www.sii.cl/XMLSchema', 'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/'}

            # Extraer el estado de la respuesta
            estado_element = response_root.find('.//SII:RESP_HDR/SII:ESTADO', namespaces=namespaces)
            estado = estado_element.text if estado_element is not None else 'unknown'

            glosa_element = response_root.find('.//SII:RESP_HDR/SII:GLOSA', namespaces=namespaces)
            glosa = glosa_element.text if glosa_element is not None else ''

            _logger.info(f"Estado del DTE recibido del SII: {estado} - {glosa}")

            # Actualizar el estado en el registro
            if estado == '00':
                self.l10n_cl_dte_status = 'accepted'
            elif estado in ['01','02','03','04','05','06','07','08','09','10','11','12','-3']:
                self.l10n_cl_dte_status = 'rejected'
            else:
                self.l10n_cl_dte_status = 'ask_for_status'

            self.sudo().message_post(
                body=f"Estado del DTE consultado: {estado} - {glosa}",
                subject="Consulta de Estado DTE",
                message_type='comment',
                subtype_xmlid='mail.mt_note',
            )

        except Exception as e:
            _logger.error(f"Error al consultar el estado del DTE: {e}")
            raise UserError(f"Error al consultar el estado del DTE en el SII: {e}")


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



        # DEF POST XML TO CHATTER FUNCIONAL OK
    def post_xml_to_chatter(self, xml_content, description="XML generado para el SII"):
        """
        Registra el contenido de un XML en el Chatter de Odoo.
        """
        try:
            # Escapar caracteres especiales para mostrar el XML en formato legible en el chatter
            escaped_xml = html.escape(xml_content)

            # Publicar el mensaje en el Chatter
            self.message_post(
                body=f"""
                    <b>{description}</b><br/>
                    <pre style="white-space: pre-wrap;">{escaped_xml}</pre>
                """,
                subject="XML Generado",
                message_type='comment',
                subtype_xmlid='mail.mt_note',
            )
            _logger.info(f"El XML ha sido registrado en el Chatter con éxito: {description}.")
        except Exception as e:
            _logger.error(f"Error al registrar el XML en el Chatter: {e}")
            raise UserError(f"Error al registrar el XML en el Chatter: {e}")

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
