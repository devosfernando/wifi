import subprocess, json, time, os, requests, sys, socket, ipaddress
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup

# Función para enviar push de alerta
def enviar_mensaje(url_mensajes, equipos, lugar):
    headers = {'Content-Type': 'application/json'}
    if equipos['estado'] == "offline":
        data = {'message': f"{lugar} - {equipos['mac']} ({equipos['nombre']}) 📴 ha dejado de estar en línea"}
    else:
        data = {'message': f"{lugar} - {equipos['mac']} ({equipos['nombre']}) 📶 ha vuelto a estar en línea"}
    
    try:
        response = requests.post(url_mensajes, json=data, headers=headers)
        if response.status_code == 200:
            print("Mensaje enviado con éxito")
        else:
            print(f"Error al enviar mensaje: {response.status_code}, {response.text}")
    except Exception as e:
        print(f"Error al conectar con el servidor: {e}")

# Indica si la ip esta en el rango de la red
def ip_en_rango(ip_str, rango_str):
    # Convertir las cadenas en objetos de IP y red
    ip = ipaddress.ip_address(ip_str)
    rango = ipaddress.ip_network(rango_str, strict=False)
    
    # Verificar si la IP está en el rango
    return ip in rango

# Función para crear un paquete ARP
def create_arp_packet(ip_range):
    # Construye el paquete ARP
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    return broadcast / arp_request

# Función para hacer ping a una IP con reintentos
def ping(ip, max_retries=9, timeout=1):
    for _ in range(max_retries):
        # Ejecuta el comando ping con un timeout
        result = subprocess.run(['ping', '-c', '1', '-W', str(timeout), ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return True  # Si responde, retorna True
    return False  # Si no responde tras todos los intentos, retorna False

# Función para escanear la red y actualizar la lista de dispositivos
def scan_network(ip_range, equipos):
    print(f"------------> Escaneando la red ...")
    # Envía el paquete y recibe respuestas
    packet = create_arp_packet(ip_range)
    try:
        answered_list = srp(packet, timeout=2, verbose=False)[0]
    except Exception as e:
        print(f"Error al ejecutar ARP scan: {e}")
        return equipos
    answered_list = srp(packet, timeout=2, verbose=False)[0]
    print(answered_list)
    # Control de dispositivos
    mac_lookup = MacLookup()
    # Iterar sobre la lista de dispositivos respondidos
    for element in answered_list:
        print(f'------------> {element[1].hwsrc} - {element[1].psrc}')
        mac_address = element[1].hwsrc
        ip_address = element[1].psrc
        try:
            # Intenta obtener el fabricante usando la dirección MAC
            vendor = mac_lookup.lookup(mac_address)
        except Exception:
            vendor = "Unknown"
        # Verificar si la MAC ya existe en el JSON de equipos
        if mac_address not in equipos:
            # Si la MAC no está, añadirla con los datos completos
            equipos[mac_address] = {
                'ip': ip_address,
                'mac': mac_address,
                'vendor': vendor,
                'nombre': 'Desconocido',
                'estado': 'online', 
                'reintentos': 0,
                'alertar': True,
            }
        else:
            # Si la MAC ya existe, solo actualizar la IP y el estado
            if equipos[mac_address]['ip'] != ip_address:
                equipos[mac_address]['ip'] = ip_address
                equipos[mac_address]['estado'] = 'online'
                equipos[mac_address]['reintentos'] = 0  # Reiniciar el contador de reintentos si está online
    print(f"------------> Escaneando la red ...")
    return equipos 

# Función para obtener la dirección MAC de un dispositivo
def get_mac(ip):
    # Construir un paquete ARP
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request

    # Enviar el paquete ARP y capturar la respuesta
    result = srp(packet, timeout=3, verbose=0)[0]

    # Si hay una respuesta, devuelve la dirección MAC
    if result:
        return result[0][1].hwsrc
    else:
        return None

# Función para obtener todas las IPs en una subred
def get_all_ips_in_subnet(subnet):
    # Crear un objeto IPv4Network a partir del rango de subred
    network = ipaddress.ip_network(subnet)
    
    # Retornar todas las IPs en la subred (exceptuando la red y el broadcast)
    return [str(ip) for ip in network.hosts()]

# Función para escanear la red y actualizar la lista de dispositivos
def scanGlobal(equipos, ip_range):
    # Control de dispositivos
    mac_lookup = MacLookup()
    list = get_all_ips_in_subnet(ip_range)
    for ip in list:
        print(f'\r -> Revisando  {ip}              ', end='', flush=True)
        if ping(ip,1,1):
            mac = get_mac(ip)
            try:
                # Intenta obtener el fabricante usando la dirección MAC
                vendor = mac_lookup.lookup(mac)
            except Exception:
                vendor = "Unknown"
            # Si responde al ping, agregarlo o actualizarlo en la lista
            if mac in equipos:
                print(f'\r -> Revisando {ip}, ACTUALIZANDO\n')
                # Actualizar la información del dispositivo
                equipos[mac].update({
                    'ip': ip,
                    'vendor': vendor,
                    'estado': 'online',  # Actualizamos el estado a 'online'
                    'reintentos': 0,     # Reiniciamos el contador de reintentos
                })
            else:
                # Si no existe, agregar el dispositivo al diccionario
                if mac != None:
                    print(f'\r -> Revisando {ip}, NUEVO\n')
                    equipos[mac] = {
                        'ip': ip,
                        'mac': mac,
                        'vendor': vendor,
                        'nombre': 'Desconocido',
                        'estado': 'online',
                        'reintentos': 0,
                        'alertar': True,
                    }
    print(f'\r Todo Actualizado                ', end='', flush=True)
    print(f'')
    return equipos
    
# Función para inicializar el programa
def inicio():
    # Función para identificar la red en la que se encuentra el equipo
    def identificadorRed():
        # Lista de redes con sus rangos
        redes = [
            {"lugar": "6411 ", "rango": "192.168.80.0/24"},
            {"lugar": "1105 ", "rango": "192.168.0.0/24" }
        ]
        # Función para obtener la IP de la interfaz activa del equipo
        def obtener_ip_local():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # No es necesario que la conexión ocurra realmente
                s.connect(("8.8.8.8", 80))
                ip_local = s.getsockname()[0]
            except Exception as e:
                print(f"Error al obtener la IP local: {e}")
                ip_local = None
            finally:
                s.close()
            return ip_local
        # Función para determinar a qué red pertenece la IP del equipo
        def determinar_red(ip, redes):
            ip_obj = ipaddress.ip_address(ip)
            for red in redes:
                red_obj = ipaddress.ip_network(red["rango"])
                if ip_obj in red_obj:
                    return red["lugar"], red["rango"]
            return None, None
        # Obtener la IP del equipo
        ip_local = obtener_ip_local()
        if ip_local:
            lugar, rango =  determinar_red(ip_local, redes)
            if lugar:
                return lugar, rango
        return None, None
    # Obtener las variables de entorno
    lugar, ip_range = identificadorRed()
    # Mensaje de alerta
    url_mensajes = os.getenv('SCAN_WIFI_IP_MENSAJE')
    # Intentar cargar el archivo de dispositivos, crear uno vacío si no existe
    try:
        # Cargar archivo de dispositivos
        with open('dispositivos.json', 'r') as archivo:
            equipos = json.load(archivo)
    except:
        # Crear archivo de dispositivos si no existe
        with open('dispositivos.json', 'w') as archivo:
            json.dump({}, archivo)
        equipos = {}
    # En caso de algun None, se considera error en las variables de entorno
    if any(var is None for var in [lugar, ip_range, url_mensajes]):
        print("Error: Se detectó un problema con las variables de entorno. El programa se detendrá.")
        print(f'export SCAN_WIFI_IP_MENSAJE="http://192.168.192.201:6367/send_message"')
        sys.exit()  # Salida controlada del programa
    return "🛜 - " + lugar, ip_range, equipos, url_mensajes

# Función principal
def main():
    # Inicializar variables
    lugar, ip_range, equipos, url_mensajes = inicio()
    # Inicializar variables de tiempo
    time_saveDevices= 1
    time_broadcast = 6
    time_ping = 1
    # Escanear la red
    equipos = scan_network(ip_range, equipos)
    # Iniciar el ciclo de monitoreo
    print("Escaneo forzado de la red")
    equipos= scanGlobal(equipos, ip_range)
    while True:
        # 'equipos' es el diccionario que contiene las MAC como claves
        for equipo in equipos:    
            if ip_en_rango(equipos[equipo]['ip'], ip_range):
                print(f"{equipos[equipo]['mac']} - {equipos[equipo]['ip'].ljust(15)}  - {equipos[equipo]['nombre'].ljust(40)}  - {equipos[equipo]['estado'].ljust(9)} - {equipos[equipo]['reintentos']}")
                estado = ping(equipos[equipo]['ip'],1,1)
                # Verificar si el estado ha cambiado
                if estado:
                    #OnLine
                    if equipos[equipo]['reintentos'] < 9:
                        equipos[equipo]['reintentos'] += 1
                else:
                    #OffLine
                    if equipos[equipo]['reintentos'] >= 0:
                        equipos[equipo]['reintentos'] -= 1
                # Incremental para avisos
                if (equipos[equipo]['reintentos'] == 9 or equipos[equipo]['reintentos'] == 0)and equipos[equipo]['alertar']:
                    print(f"{lugar}📶 - {equipos[equipo]['mac']} ({equipos[equipo]['nombre'].ljust(40)}) Cambia estado")
                    enviar_mensaje(url_mensajes, equipos[equipo], lugar)
        print("----------------------------------------------------------------------------------------------------")
        time.sleep(9)
        # Esperar un tiempo antes de volver a escanear
        time.sleep(time_ping)
        if time_broadcast <= 0:
            equipos = scan_network(ip_range, equipos)
            time_broadcast = 6
            if time_saveDevices <= 0:
                with open('dispositivos.json', 'w') as archivo:
                    json.dump(equipos, archivo)
                time_saveDevices = 10
            else:
                time_saveDevices -= 1
        else:
            time_broadcast -= 1 
            time_saveDevices -= 1

if __name__ == "__main__":
    main()
