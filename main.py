
import subprocess, json, time, os, requests
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup

# Función para enviar push de alerta
def enviar_mensaje(message):
    url = 'http://192.168.192.201:6367/send_message'  # Cambia el URL si es necesario
    headers = {'Content-Type': 'application/json'}
    data = {'message': message}
    
    try:
        response = requests.post(url, json=data, headers=headers)
        if response.status_code == 200:
            print("Mensaje enviado con éxito")
        else:
            print(f"Error al enviar mensaje: {response.status_code}, {response.text}")
    except Exception as e:
        print(f"Error al conectar con el servidor: {e}")

# Función para crear un paquete ARP
def create_arp_packet(ip_range):
    # Construye el paquete ARP
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    return broadcast / arp_request

# Función para hacer ping a una IP con reintentos
def ping(ip, max_retries=3, timeout=1):
    for _ in range(max_retries):
        # Ejecuta el comando ping con un timeout
        result = subprocess.run(['ping', '-c', '1', '-W', str(timeout), ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return True  # Si responde, retorna True
    return False  # Si no responde tras todos los intentos, retorna False

# Función para escanear la red y actualizar la lista de dispositivos
def scan_network(ip_range, equipos):
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
        print(element[1].hwsrc, element[1].psrc)
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
    return equipos 

# Función para inicializar el programa
def inicio():
    if os.getenv('SCAN_WIFI_LUGAR') == None:
        lugar = "🛜 - "
    else:
        lugar = "🛜 - " + os.getenv('SCAN_WIFI_LUGAR')
    if os.getenv('SCAN_WIFI_RANGO') == None:
        ip_range = "192.168.0.1/24"
    else:
        ip_range = os.getenv('SCAN_WIFI_RANGO')
    try:
        # Cargar archivo de dispositivos
        with open('dispositivos.json', 'r') as archivo:
            equipos = json.load(archivo)
    except:
        # Crear archivo de dispositivos si no existe
        with open('dispositivos.json', 'w') as archivo:
            json.dump({}, archivo)
        equipos = {}
    return lugar, equipos, ip_range

# Función principal
def main():
    # Inicializar variables
    lugar, equipos, ip_range = inicio()
    print(f"------------> Escaneando la red {ip_range}...")
    # Inicializar variables de tiempo
    time_saveDevices= 1
    time_broadcast = 6
    time_ping = 1
    # Escanear la red
    scan_network(ip_range, equipos)
    # Iniciar el ciclo de monitoreo
    while True:
        print(f"Escaneando la red {ip_range}...")
        # 'equipos' es el diccionario que contiene las MAC como claves
        for equipo in equipos:

            estado = ping(equipos[equipo]['ip'])
            if estado:
                if equipos[equipo]['alertar']:
                    if equipos[equipo]['reintentos'] > 6 and equipos[equipo]['estado'] == 'offline':
                        print(f"{lugar}📶 - {equipos[equipo]['mac']} ({equipos[equipo]['ip']}) ha vuelto a estar en línea")
                        enviar_mensaje(f"{lugar}📶 - {equipos[equipo]['mac']} ({equipos[equipo]['ip']}) ha vuelto a estar en línea")
                        equipos[equipo]['estado'] = 'online'
                    else:
                        if equipos[equipo]['reintentos'] < 9:
                            equipos[equipo]['reintentos'] += 1
                else:
                    if equipos[equipo]['reintentos'] < 9:
                        equipos[equipo]['reintentos'] += 1
                    equipos[equipo]['estado'] = 'online'
            else:
                if equipos[equipo]['alertar']:
                    if equipos[equipo]['reintentos'] > 6 and equipos[equipo]['estado'] == 'online':
                        print(f"{lugar}📴 - {equipos[equipo]['mac']} ({equipos[equipo]['ip']}) ha dejado de estar en línea")
                        enviar_mensaje(f"{lugar}📴 - {equipos[equipo]['mac']} ({equipos[equipo]['ip']}) ha dejado de estar en línea")
                        equipos[equipo]['estado'] = 'offline'
                    else:
                        if equipos[equipo]['reintentos'] < 9:
                            equipos[equipo]['reintentos'] += 1
                else:
                    if equipos[equipo]['reintentos'] < 9:
                        equipos[equipo]['reintentos'] += 1
                    equipos[equipo]['estado'] = 'offline'
            print(f"{equipos[equipo]['mac']} ({equipos[equipo]['ip']}) - {equipos[equipo]['estado']} - {equipos[equipo]['reintentos']}")
        # Esperar un tiempo antes de volver a escanear
        time.sleep(time_ping)
        if time_broadcast <= 0:
            scan_network(ip_range, equipos)
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
        