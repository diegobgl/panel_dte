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

    #action_send_reclamo
    def action_send_reclamo(self):
        """ Enviar el reclamo al SII """
        if not self.invoice_id:
            raise UserError("Debe estar relacionado con un DTE antes de enviar el reclamo.")

        # Obtener datos del documento
        rut_emisor, dv_emisor = self.invoice_id.company_rut.split('-')
        rut_receptor, dv_receptor = self.env.company.vat.split('-')
        tipo_dte = self.invoice_id.document_type.code
        folio_dte = self.invoice_id.folio_number
        token = self.env['ir.config_parameter'].sudo().get_param('my_module.sii_token')

        # Construcción de la solicitud SOAP
        soap_request = f"""
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dte="http://DefaultNamespace">
            <soapenv:Header/>
            <soapenv:Body>
                <dte:ingresarAceptacionReclamoDoc>
                    <rutEmisor>{rut_emisor}</rutEmisor>
                    <dvEmisor>{dv_emisor}</dvEmisor>
                    <tipoDoc>{tipo_dte}</tipoDoc>
                    <folio>{folio_dte}</folio>
                    <accionDoc>{self.action_type}</accionDoc>
                    <Token>{token}</Token>
                </dte:ingresarAceptacionReclamoDoc>
            </soapenv:Body>
        </soapenv:Envelope>
        """

        # Enviar solicitud
        url = "https://ws1.sii.cl/WSREGISTRORECLAMODTE/registroreclamodteservice"
        headers = {'Content-Type': 'text/xml; charset=utf-8'}
        response = requests.post(url, data=soap_request.encode('utf-8'), headers=headers)

        if response.status_code != 200:
            raise UserError(f"Error en el servicio SII: {response.status_code} - {response.text}")

        # Guardar respuesta en el chatter
        self.invoice_id.message_post(
            body=f"<b>Respuesta SII:</b> {response.text}",
            subject="Resultado de Reclamo DTE",
            message_type='comment',
            subtype_xmlid='mail.mt_note',
        )

        return True
