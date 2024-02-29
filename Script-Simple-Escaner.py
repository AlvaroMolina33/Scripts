
"""

PRUEBA DE CONCEPTO
Para Diplomado en Ciberseguridad Red Team USACH 2024
Curso de Pentesting Web

Version: Script v2
Autor: Alvaro Molina

Recursos usados:

tmstmp=calendar.timegm(gmt)

https://thepacketgeek.com/scapy/sniffing-custom-actions/part-1/
https://www.geeksforgeeks.org/packet-sniffing-using-scapy/
https://code-maven.com/slides/python/scapy-list-interfaces
https://thepythoncode.com/article/building-network-scanner-using-scapy
https://medium.com/@eugeneodhiambo07/network-scanner-with-python-and-scapy-f8833efff560
https://gist.github.com/highrider0602/177fb997d5b2b1d59f648b4261c0687d
https://stackoverflow.com/questions/43012166/try-getservbyport-to-display-mongod-service-in-python3
https://pythontic.com/modules/socket/getservbyport

"""



from scapy.all import *
import calendar
import os
import struct
import time
import re
from collections import Counter
import scapy.all as scapy
from scapy.layers import http
import argparse


nombre_ruta = '/home/alvaro/Documents/script/'

##Validar ip ingresada mediante regex para opcion 1
def validar_entrada(network):
    patron = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')

    if not patron.match(network):
        print("""


                ERROR: Formato de dirección de red incorrecto. Utiliza el formato Ej: 192.168.1.1/24

            """)
        return False
    return True

#Validar ip ingresada mediante regex para opcion 2
def validar_entrada_ip_puerto(network):
    patron = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

    if not patron.match(network):
        print("""

            ERROR: Formato de dirección de red incorrecto. Utiliza el formato Ej: 192.168.1.1

            """)
        return False
    return True

#Validar interfaces existentes para opcion 3
def validar_interfaz(interfaz):
    interfaces_disponibles = scapy.get_if_list()
    if interfaz in interfaces_disponibles:
        return True
    else:
        return False

#Validar enteros para opcion 2 puertos
def validar_entero(mensaje):
    while True:
        try:
            valor = int(input(mensaje))
            return valor
        except ValueError:
            print("Error: Debe ser un numero entero")


#Validar interfaces disponibles para opcion de sniffing
def mostrar_interfaces():

    print("""
            Interfaces disponibles

            """)
    interfaces = scapy.get_if_list()

    #print(interfaces)
    for interface in interfaces:
        print("Interface : "+interface)

#Funcion para escanear los hosts disponibles en la red
def scan_network(network):

        
        #Se realiza envio de paquete ARP para solicitar mac
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        ans, unans = srp(arp_request, timeout=2, verbose=0)


        #Obtener tiempo actual
        tmstmp = calendar.timegm(time.gmtime())

        #Agregar la marca de tiempo como una nueva columna (campo) en los paquetes
        for send_packet, recv_packet in ans:
            timestamp_layer = struct.pack('>Q', tmstmp) 
            recv_packet = recv_packet / Raw(load=timestamp_layer)  
            #recv_packet.add_underlayer(Ether(timestamp_layer))  # Añadir la nueva capa al paquete

        #Apartado de formtear y enviar archivo
        #pcap_filename="SCPV2_resultado_escaneo_hosts.pcap"
        pcap_filename = f"SCPV2_resultado_escaneo_hosts_{tmstmp}.pcap"
        #custom_path = nombre_ruta
        #escritorio_path = os.path.join(os.path.expanduser("~"), "Desktop")
        #pcap_filepath = os.path.join(pcap_filename, pcap_filename)


        
        #guardar archivo en formato PCAP para whireshark
        wrpcap(pcap_filename, ans)

        # Imprimir los host encontrados
        print("Listado de hosts activos en la red:")
        for send_packet, recv_packet in ans:
            ip = recv_packet[ARP].psrc
            mac = recv_packet[Ether].src
            print("IP: {}, MAC: {}".format(ip, mac))


#Funcion para escanear puertos de un host especifico y rangos
def scan_puertos(network,rango1,rango2):

    #inicio de captando datos enviados como parametros y customizando la salida.
    puertos = range(rango1, rango2)
    #pcap_filename = f"SCPV2_resultado_escaneo_hosts_{tmstmp}.pcap"
    #pcap_filename = f"SCPV2_resultado_escaneo_puertos_{tmstmp}.pcap"
    custom_path = nombre_ruta
    puertos_dic = []
    puertos_serv = []
    pack = []


     #Obtener tiempo actual
    tmstmp = calendar.timegm(time.gmtime())


    for puerto in puertos:

        #se construye paquete a enviar
        paquete = IP(dst=network) / TCP(dport=puerto, flags="S")
        #enviar paqute y espperar respuesta
        respuesta = sr1(paquete, timeout=1, verbose=0)

        #registrar informacion recibida
        pack.append(paquete)


        if respuesta is not None:

            #si se recibe respuesta SYN/ACK
            if respuesta.haslayer(TCP) and respuesta.getlayer(TCP).flags == 0x12:
                print(f"Puerto {puerto} abierto")

                #regisrar puerto abierto
                puertos_dic.append(puerto)
               # Mostrar el servicio que corre en el puerto abierto
                try:
                    servicio = socket.getservbyport(puerto)
                    print(f"Servicio en el puerto {puerto}: {servicio}")
                    puertos_serv.append(servicio)
                except OSError:
                    print(f"No se pudo determinar el servicio para el puerto {puerto}")
            elif respuesta.haslayer(TCP) and respuesta.getlayer(TCP).flags == 0x14:
                print(f"Puerto {puerto} cerrado")
            else:
                print(f"Puerto {puerto} filtrado")
        else:
            print(f"Puerto {puerto} no obtuvo respuesta")

    #pcap_filepath = os.path.join(custom_path, pcap_filename)
    pcap_filename = f"SCPV2_resultado_escaneo_puertos_{tmstmp}.pcap"
    wrpcap(pcap_filename, pack)
    print("Puertos abiertos:")
    #print(puertos_dic)
    #print(puertos_serv)

     # Resumen de la información obtenida
    print("Resumen de los puertos abiertos y sus servicios:")
    for puerto, servicio in zip(puertos_dic, puertos_serv):
        print(f"Puerto {puerto} - Servicio: {servicio}")


#Funcion para realizar Sniffing previante validado la interfaz a utilizar
def start_sniffing(interface):



    #Obtener tiempo actual
    tmstmp = calendar.timegm(time.gmtime())
    #pcap_filename = "SCPV2_sniffing.pcap"
    pcap_filename = f"SCPV2_resultado_escaneo_sniffing_{tmstmp}.pcap"
    #se define funcion interna para procesar el sniffing
    def packet_handler(packet):

        #veririficar capa de ip
        if packet.haslayer(scapy.IP):

            #extraer la direccion y el destino de paque
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            #imprimir los paquetes obtenidos mostrando la ip de origin y destino
            print(f"Paquete desde {src_ip} para {dst_ip}")


        #verifica si el paquete tiene una capa HTTP
        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
            print(f"Requesting URL: {url}")
        
        #guardar paquetes capturados en un archivo pcap 
        wrpcap(pcap_filename, packet, append=True)


    print(f"Iniciando sniffing en la interfaz : {interface}...")
    scapy.sniff(iface=interface, prn=packet_handler, store=False,timeout = 120)


#informacion de inicio
def menu():
    print("""         
            *** Bienvenido ***

                Existen las siguentes opciones para selccionar: 

                version - V2
            """)

    print("1. Escanear red")
    print("2. Otros...")
    print("3. Salir")

    

if __name__ == "__main__":
    while True:
        menu()
        #se inicia despligue de opciones
        opcion = input("Selecciona una opción: ")

        #condicional que opcion
        if opcion == "1":
            while True:
                print("""

                        *SUBMENU 1

                    """)
                print("Submenú escaneo de red")
                print("1. escanear hosts activos")
                print("2. escanear puertos de un host")
                print("3. Sniffing a un host")

                subopcion = input("Seleccione una opción: ")

                if subopcion == "1":
                    print("""

                        *Subopcion 1

                             Ej: 192.168.1.1/24)

                    """)
                    print("Opcion 1 - escanear hosts activos")
                    network = input("Introduce la dirección de red (en formato ej: 192.168.1.1/24) a escanear: ")


                    if validar_entrada(network):
                        scan_network(network)


                elif subopcion == "2":
                    print("""


                        *Subopcion 2
                        Ejemplo a escanear : 192.168.1.1)


                    """)
                    print("Has seleccionado la Subopción 2.")
                    network = input("Introduce ip 192.168.1.1)")

                    

                    if validar_entrada_ip_puerto(network):
                        print("Ingresar numero de rango de puertos a escanear ej : 1 - 20")
                        rango1 = validar_entero("Introduce el valor 1 del rango: ")
                        rango2 = validar_entero("Introduce el valor 2 del rango: ")
                        print("Los valores introducidos son:", rango1, "y", rango2)
                        scan_puertos(network,rango1,rango2)
                    #rango_puertos = input("Introduce rangos ej 1-100")

                elif subopcion == "3":
                    print("""


                        *Subopcion 3
                        Sniffing

                       
                        Nota:

                        La informacion se guarda a medida que se imprime en pantalla,
                        se puede cancelar con ctrl+c.    
       
                        El tiempo del sniffing es de 120 seg por defecto.


                    """)


                    mostrar_interfaces()
                    print("")
                    interface = input("Introduce el nombre de la interfaz de red (Ejemplo eth0): ")
                    if validar_interfaz(interface):
                        print("La interfaz es válida.")
                        start_sniffing(interface)
                    else:
                        print("La interfaz no es válida o no existe.")

                    


                else:
                    print("Opción no válida. Inténtalo de nuevo.")

        elif opcion == "2":
            print("En construcción... ")
        elif opcion == "3":
            print("Saliendo del programa.........")
            print("...........................")
            break
        else:
            print("Opción no válida. Inténtalo de nuevo.")

