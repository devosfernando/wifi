# Network Monitoring Script

Este proyecto es un script de monitoreo de red que utiliza ARP para escanear dispositivos en una red local, realiza pings a las IPs detectadas y envía alertas en caso de cambios en el estado de los dispositivos (online/offline). También incluye la capacidad de identificar fabricantes a través de la dirección MAC.

## Características

- Escaneo de red utilizando paquetes ARP.
- Detección y monitoreo de dispositivos en la red.
- Envío de notificaciones cuando un dispositivo cambia su estado (online/offline).
- Almacenamiento y actualización de un archivo JSON con los dispositivos detectados.
- Identificación de fabricantes utilizando la dirección MAC.
- Capacidad de personalización del rango de IPs a escanear y el lugar (ubicación) del escaneo mediante variables de entorno.

## Requisitos

- **Python 3.x**
- **Paquetes necesarios**: 
  - `scapy`
  - `mac_vendor_lookup`
  - `requests`

Puedes instalar las dependencias necesarias ejecutando:

```bash
pip install -r requirements.txt
```