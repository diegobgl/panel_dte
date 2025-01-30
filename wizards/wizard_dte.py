from odoo import models, fields, api
from odoo.exceptions import UserError
import requests
import logging
from lxml import etree

_logger = logging.getLogger(__name__)

class DTEReclamoWizard(models.TransientModel):
    _name = "dte.reclamo.wizard"
    _description = "Registrar Aceptación/Reclamo de DTE"

    invoice_id = fields.Many2one('invoice.mail', string="DTE Relacionado", required=True)
    
    action_type = fields.Selection([
        ('ACD', 'Aceptar Documento (ACD)'),
        ('ERM', 'Otorgar Recibo Mercadería (ERM)'),
        ('RCD', 'Reclamar Contenido Documento (RCD)'),
        ('RFP', 'Reclamar Falta Parcial Mercadería (RFP)'),
        ('RFT', 'Reclamar Falta Total Mercadería (RFT)'),
    ], string="Acción", required=True)

    comment = fields.Text(string="Comentario Adicional")

    def action_send_reclamo(self):
        """ Enviar la solicitud de reclamo al SII """
        self.ensure_one()

        # Validar que la factura tenga datos correctos
        if not self.invoice_id.env.company.vat:
            raise UserError("No se ha definido el RUT de tu empresa en Odoo.")
        if not self.invoice_id.company_rut:
            raise UserError("No existe RUT del emisor en el documento.")
        if not self.invoice_id.folio_number or not self.invoice_id.document_type.code:
            raise UserError("Folio o Tipo de Documento faltante en la factura.")

        # Extraer RUTs en formato correcto
        rut_receptor, dv_receptor = self.invoice_id._split_vat(self.invoice_id.env.company.vat)
        rut_emisor, dv_emisor = self.invoice_id._split_vat(self.invoice_id.company_rut)

        # Obtener token desde API interna
        token = self.invoice_id._get_token_from_internal_api()
        _logger.info(f"Token obtenido correctamente: {token}")

        # Construir solicitud SOAP
        soap_request = f"""
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/>
            <soapenv:Body>
                <ingresarAceptacionReclamoDoc xmlns="http://ws.registroreclamodte.diii.sdi.sii.cl">
                    <rutEmisor>{rut_emisor}</rutEmisor>
                    <dvEmisor>{dv_emisor}</dvEmisor>
                    <tipoDoc>{self.invoice_id.document_type.code}</tipoDoc>
                    <folio>{self.invoice_id.folio_number}</folio>
                    <accionDoc>{self.action_type}</accionDoc>
                </ingresarAceptacionReclamoDoc>
            </soapenv:Body>
        </soapenv:Envelope>
        """

        # Enviar solicitud al SII
        url = "https://ws1.sii.cl/WSREGISTRORECLAMODTE/registroreclamodteservice"
        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'Cookie': f'TOKEN={token}'
        }

        _logger.info(f"Enviando solicitud SOAP a {url}:\n{soap_request}")
        response = requests.post(url, data=soap_request.encode('utf-8'), headers=headers, timeout=30)

        if response.status_code != 200:
            raise UserError(f"Error HTTP {response.status_code} en la solicitud SOAP: {response.text}")

        _logger.info(f"Respuesta SOAP:\n{response.text}")
        self.invoice_id.post_xml_to_chatter(response.text, description="Respuesta SOAP Registro Reclamo")

        # Procesar la respuesta
        response_root = etree.fromstring(response.text.encode('utf-8'))
        namespaces = {'ns': 'http://ws.registroreclamodte.diii.sdi.sii.cl'}
        code_resp = response_root.find('.//ns:return/ns:codResp', namespaces=namespaces)
        desc_resp = response_root.find('.//ns:return/ns:descResp', namespaces=namespaces)

        if code_resp is not None and code_resp.text == "0":
            self.invoice_id.sii_reclamo_status = 'accepted' if self.action_type == 'ACD' else 'rejected'
            _logger.info(f"Reclamo registrado correctamente: {desc_resp.text}")
        else:
            _logger.warning(f"Error en la respuesta del SII: {desc_resp.text}")
            raise UserError(f"Error en el SII: {desc_resp.text}")
