# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_puertosabiertos
# Purpose:      SpiderFoot plug-in for creating new modules.
#
# Author:      Chema López Lombana
#
# Created:     09/12/2021
# Copyright:   (c) Chema López Lombana 2021
# Licence:     GPL
# -------------------------------------------------------------------------------


from spiderfoot import SpiderFootEvent, SpiderFootPlugin
import subprocess

class sfp_puertosabiertos(SpiderFootPlugin):

    meta = {
        'name': "PuertosAbiertos",
        'summary': "Devuelve los puertos abiertos de un dominio",
        'flags': [""],
        'useCases': [""],
        'categories': ["Passive DNS"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["INTERNET_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
    
        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            data = []

            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

            ########################

            dominio = eventData                                                                         # El dominio de entrada lo recibimos en eventData

            #Ejecutar 

            result = subprocess.run('ping -c 1 '+ dominio, shell=True, capture_output=True, text=True)  # realizo una línea de ping --> result

            texto = (result.stdout)

            salida = texto.split(' ')                                                                   # separo las palabras en los espacios

            if len(salida)>1:                                                                           # Si hay ping
                
                ip = salida[2][1:-1]                                                                    # quito los parentesis a la IP
                hay_puertos_abiertos = False                                                            # defino que inicialmente no hay puertos abiertos
                
                result = subprocess.run(["nmap",ip],stdout = subprocess.PIPE)                            # lanzo un nmap y guardo los puertos abiertos y cerrados
                result = result.stdout.decode('utf-8')                                                   # pongo formato utf-8
                result = result.split("\n")                                                              # separo por lineas

                for linea in result:                                                                     # recorro las líneas
                    if "open" in linea:                                                                  # si detecto el texto open
                        hay_puertos_abiertos = True
                        linea_puerto = str(salida[2]) + " --> " + str(linea)                             # Creo la línea de salida con la Ip y el puerto
                        data.append(linea_puerto)                                                        # añado la línea a la lista de puertos

                if not hay_puertos_abiertos:
                    data.append("- No hay puertos abiertos -")                                           # Si no hay puertos abiertos

            else:
                data.append("Este dominio no está publicado o no existe (no responde a ping)")           # en el caso de que no responda a ping
            
            if not data:
                self.sf.error("-Unable to perform <ACTION MODULE> on " + eventData)                      # gestión de errores
                return
            
        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return
        
        puerto_open = list()                                                                             # inicializo la lista donde guardaré los resultados

        for puerto_open in data:                                                                         # recorremos data (donde tenemos el resultado)
            evt = SpiderFootEvent('TCP_PORT_OPEN', puerto_open , self.__name__, event)                   # realizamos la respuesta del script dando el tipo de datos y la lista de resultados
            self.notifyListeners(evt)

# End of sfp_puertosabiertos class