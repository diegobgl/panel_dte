import requests
import urllib3
from odoo import models, fields, api
from odoo.tools import email_split
from odoo.exceptions import UserError
import base64
import xml.etree.ElementTree as ET
import logging
from lxml import etree  
import time
from OpenSSL import crypto
from zeep import Client, Settings
from zeep.transports import Transport
from requests import Session
import html
import hashlib


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
        """Devuelve el certificado activo o lanza una excepción."""
        certificate = self.env['l10n_cl.certificate'].search([], limit=1)
        if not certificate:
            raise UserError("No se encontró un certificado digital activo en el sistema.")
        return certificate

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

    def _get_token(self, signed_seed):
            """Solicita el token al SII utilizando la semilla firmada."""
            token_url = "https://palena.sii.cl/DTEWS/GetTokenFromSeed.jws"
            http = urllib3.PoolManager()

            try:
                # Calcular el DigestValue
                digest_value = self._get_digest_value(signed_seed)

                # Formato XML correcto de la solicitud
                soap_request = f"""
                <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                    <soapenv:Header/>
                    <soapenv:Body>
                        <getToken>
                            <item>
                                <Semilla>{signed_seed}</Semilla>
                                <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                                    <SignedInfo>
                                        <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                                        <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                                        <Reference URI="">
                                            <Transforms>
                                                <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                                            </Transforms>
                                            <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                                            <DigestValue>{digest_value}</DigestValue>
                                        </Reference>
                                    </SignedInfo>
                                    <SignatureValue>{self._get_signature_value()}</SignatureValue>
                                    <KeyInfo>
                                        <KeyValue>
                                            <RSAKeyValue>
                                                <Modulus>{self._get_modulus()}</Modulus>
                                                <Exponent>AQAB</Exponent>
                                            </RSAKeyValue>
                                        </KeyValue>
                                        <X509Data>
                                            <X509Certificate>{self._get_certificate()}</X509Certificate>
                                        </X509Data>
                                    </KeyInfo>
                                </Signature>
                            </item>
                        </getToken>
                    </soapenv:Body>
                </soapenv:Envelope>
                """

                headers = {'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': 'urn:GetTokenFromSeed'}
                _logger.info(f"Solicitando el token con la semilla firmada:\n{soap_request}")

                # Enviar la solicitud al SII
                response = http.request('POST', token_url, body=soap_request.encode('utf-8'), headers=headers)

                if response.status != 200:
                    raise Exception(f"Error HTTP al solicitar el token: {response.status}")

                # Procesar la respuesta
                response_data = response.data.decode('utf-8')
                _logger.info(f"Respuesta obtenida del SII (token): {response_data}")
                root = etree.fromstring(response.data)

                # Extraer el nodo <getTokenReturn>
                ns = {'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/'}
                get_token_return = root.find('.//soapenv:Body/getTokenResponse/getTokenReturn', namespaces=ns)

                if get_token_return is None:
                    raise Exception("No se pudo encontrar el nodo getTokenReturn en la respuesta del SII.")

                # Decodificar el XML interno
                decoded_response = html.unescape(get_token_return.text)
                token_root = etree.fromstring(decoded_response.encode('utf-8'))

                # Extraer estado, glosa y token
                estado = token_root.find('.//ESTADO').text
                if estado != "00":
                    glosa = token_root.find('.//GLOSA').text or "Sin detalles."
                    raise Exception(f"Error al generar el token: {glosa}")

                token = token_root.find('.//TOKEN').text
                if not token:
                    raise Exception("No se pudo encontrar el token en la respuesta del SII.")

                return token

            except Exception as e:
                _logger.error(f"Error al obtener el token desde el SII: {e}")
                raise UserError(f"Error al obtener el token desde el SII: {e}")

    def _get_seed(self):
        """Solicita la semilla desde el SII y registra la salida en el chatter."""
        seed_url = "https://palena.sii.cl/DTEWS/CrSeed.jws"
        http = urllib3.PoolManager()

        try:
            _logger.info("Solicitando la semilla al SII.")
            soap_request = """
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                <soapenv:Header/>
                <soapenv:Body>
                    <getSeed/>
                </soapenv:Body>
            </soapenv:Envelope>
            """
            headers = {'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': 'urn:getSeed'}
            response = http.request('POST', seed_url, body=soap_request.encode('utf-8'), headers=headers)

            if response.status != 200:
                raise Exception(f"Error HTTP al solicitar la semilla: {response.status}")

            # Decodificar la respuesta SOAP
            response_data = response.data.decode('utf-8')
            _logger.info(f"Respuesta obtenida del SII (semilla): {response_data}")
            root = etree.fromstring(response.data)

            # Extraer el nodo <getSeedReturn>
            ns = {'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/'}
            get_seed_return = root.find('.//soapenv:Body/getSeedResponse/getSeedReturn', namespaces=ns)

            if get_seed_return is None:
                raise Exception("No se pudo encontrar el nodo getSeedReturn en la respuesta del SII.")

            # Decodificar el XML interno
            decoded_response = html.unescape(get_seed_return.text)
            seed_root = etree.fromstring(decoded_response.encode('utf-8'))

            # Extraer estado, glosa y semilla
            estado = seed_root.find('.//ESTADO').text
            if estado != "00":
                glosa = seed_root.find('.//GLOSA').text or "Sin detalles."
                raise Exception(f"Error al generar la semilla: {glosa}")

            semilla = seed_root.find('.//SEMILLA').text
            if not semilla:
                raise Exception("No se pudo encontrar la semilla en la respuesta del SII.")

            # Registrar en el chatter
            self.message_post(
                body=f"Semilla obtenida correctamente: {semilla}",
                subject="Semilla Obtenida",
                message_type='notification',
            )

            return semilla

        except Exception as e:
            _logger.error(f"Error al obtener la semilla desde el SII: {e}")
            self.message_post(
                body=f"Error al obtener la semilla desde el SII: {e}",
                subject="Error al Obtener Semilla",
                message_type='notification',
            )
            raise UserError(f"Error al obtener la semilla desde el SII: {e}")

    def _sign_seed(self, seed):
        """Firma la semilla utilizando el certificado digital configurado en Odoo."""
        certificate = self._get_active_certificate()
        try:
            # Cargar el certificado y clave privada desde el archivo PKCS#12
            p12 = crypto.load_pkcs12(
                base64.b64decode(certificate.signature_key_file),
                certificate.signature_pass_phrase.encode('utf-8')
            )
            private_key = p12.get_privatekey()
            x509_cert = p12.get_certificate()

            # Generar DigestValue (SHA1 de la semilla)
            digest = hashlib.sha1(seed.encode('utf-8')).digest()  # Usar hashlib para calcular el hash SHA1
            digest_value = base64.b64encode(digest).decode('utf-8')

            # Generar SignedInfo XML
            signed_info = f"""
            <SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                <Reference URI="">
                    <Transforms>
                        <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    </Transforms>
                    <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                    <DigestValue>{digest_value}</DigestValue>
                </Reference>
            </SignedInfo>
            """

            # Firmar SignedInfo con la clave privada
            signed_info_canonicalized = signed_info.strip().encode('utf-8')
            signature_value = crypto.sign(private_key, signed_info_canonicalized, 'sha1')
            signature_value_b64 = base64.b64encode(signature_value).decode('utf-8')

            # Extraer Modulus y Exponent de la clave pública
            public_key = x509_cert.get_pubkey()
            rsa_key = crypto.load_publickey(crypto.FILETYPE_PEM, crypto.dump_publickey(crypto.FILETYPE_PEM, public_key))
            modulus = base64.b64encode(rsa_key.to_cryptography_key().public_numbers().n.to_bytes(256, 'big')).decode('utf-8')
            exponent = base64.b64encode(rsa_key.to_cryptography_key().public_numbers().e.to_bytes(3, 'big')).decode('utf-8')

            # Generar el XML de la semilla firmada
            signed_seed = f"""
            <getToken xmlns="http://www.w3.org/2000/09/xmldsig#">
                <item>
                    <Semilla>{seed}</Semilla>
                </item>
                <Signature>
                    {signed_info.strip()}
                    <SignatureValue>{signature_value_b64}</SignatureValue>
                    <KeyInfo>
                        <KeyValue>
                            <RSAKeyValue>
                                <Modulus>{modulus}</Modulus>
                                <Exponent>{exponent}</Exponent>
                            </RSAKeyValue>
                        </KeyValue>
                        <X509Data>
                            <X509Certificate>{base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, x509_cert)).decode('utf-8')}</X509Certificate>
                        </X509Data>
                    </KeyInfo>
                </Signature>
            </getToken>
            """

            _logger.info("Semilla firmada correctamente.")
            return signed_seed.strip()

        except Exception as e:
            _logger.error(f"Error al firmar la semilla: {e}")
            raise UserError("Error al firmar la semilla.")

    def check_sii_status(self):
        """
        Consulta el estado del DTE en el SII utilizando las funciones indicadas:
        - Solicita la semilla
        - Firma la semilla
        - Envía la semilla firmada y obtiene el token
        - Realiza la consulta del estado del DTE con el token
        """
        self.ensure_one()
        try:
            _logger.info(f"Consultando el estado del DTE en el SII para el RUT: {self.company_rut}, TipoDoc: {self.document_type}, Folio: {self.folio_number}")

            # 1. Solicitar la semilla
            seed = self._get_seed()
            _logger.info(f"Semilla obtenida: {seed}")

            # 2. Firmar la semilla
            signed_seed = self._sign_seed(seed)
            _logger.info(f"Semilla firmada correctamente.")

            # 3. Obtener el token
            token = self._get_token(signed_seed)
            _logger.info(f"Token obtenido correctamente: {token}")

            # 4. Consultar el estado del DTE usando el token
            status_url = "https://palena.sii.cl/DTEWS/QueryEstDte.jws"
            soap_body = f"""
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
                        <TipoDte>{self.document_type}</TipoDte>
                        <FolioDte>{self.folio_number}</FolioDte>
                        <FechaEmisionDte>{self.date_emission.strftime('%Y-%m-%d')}</FechaEmisionDte>
                        <MontoDte>{int(self.amount_total)}</MontoDte>
                        <Token>{token}</Token>
                    </dte:getEstDte>
                </soapenv:Body>
            </soapenv:Envelope>
            """

            # Registrar el XML generado en el chatter
            self.message_post(
                body=f"<b>Solicitud de estado del DTE:</b><br/><pre>{soap_body}</pre>",
                subject="Solicitud de Estado DTE",
                message_type='comment',
                subtype_xmlid='mail.mt_note',
            )

            # 5. Enviar la solicitud al SII
            http = urllib3.PoolManager()
            headers = {'Content-Type': 'text/xml; charset=utf-8'}
            response = http.request(
                'POST',
                status_url,
                body=soap_body.encode('utf-8'),
                headers=headers,
            )

            # Validar la respuesta HTTP
            if response.status != 200:
                _logger.error(f"Error HTTP al consultar el estado del DTE: {response.status}")
                raise UserError(f"Error HTTP al consultar el estado del DTE: {response.status}. Verifique la URL o el estado del servicio.")

            # Parsear la respuesta
            response_root = etree.fromstring(response.data)
            sii_response = response_root.find('.//SII:RESP_HDR/ESTADO', namespaces={'SII': 'http://www.sii.cl/XMLSchema'})
            sii_status = sii_response.text if sii_response is not None else 'unknown'

            # Registrar la respuesta en el chatter
            self.message_post(
                body=f"<b>Respuesta del SII:</b><br/><pre>{etree.tostring(response_root, pretty_print=True).decode()}</pre>",
                subject="Respuesta de Estado DTE",
                message_type='comment',
                subtype_xmlid='mail.mt_note',
            )

            _logger.info(f"Estado del DTE recibido del SII: {sii_status}")

            # Actualizar el estado en el registro
            self.l10n_cl_dte_status = sii_status
            self.message_post(
                body=f"Estado del DTE consultado: {sii_status}",
                subject="Consulta de Estado DTE",
                message_type='comment',
                subtype_xmlid='mail.mt_note',
            )
        except Exception as e:
            _logger.error(f"Error al consultar el estado del DTE: {e}")
            raise UserError(f"Error al consultar el estado del DTE en el SII: {e}")

    def validate_xml_response(response_data):
        try:
            root = etree.fromstring(response_data)
            return root
        except etree.XMLSyntaxError as e:
            _logger.error(f"El XML de respuesta no es válido: {e}")
            raise UserError("El XML recibido del SII no es válido. Verifique la respuesta del servicio.")

    def post_xml_to_chatter(self, xml_content, description="XML generado para el SII"):
        """
        Registra el contenido de un XML en el Chatter de Odoo.

        Args:
            xml_content (str): El contenido del XML que deseas registrar.
            description (str): Descripción que acompañará al XML en el Chatter.
        """
        try:
            # Escapar caracteres especiales para mostrar el XML en formato legible en el chatter
            escaped_xml = xml_content.replace('<', '&lt;').replace('>', '&gt;')

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
            _logger.info("El XML ha sido registrado en el Chatter con éxito.")
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
