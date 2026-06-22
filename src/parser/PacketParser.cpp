// ============================================================================
// PacketParser.cpp
// Actúa como el traductor del programa. Toma los ceros y unos crudos que 
// atrapó la tarjeta de red y los convierte en información que puede leer para un humano 
// (como direcciones IP, puertos y protocolos)
// ============================================================================

#include "PacketParser.h" 
#include <ws2tcpip.h>       // Contiene herramientas de Windows para convertir direcciones IP
#include <unordered_map>
#include <mutex>

namespace PacketParser {
    //Para asignar el "ID" a cada paquete
    static std::mutex id_mutex;
    static int global_packet_id = 1;

    // Diccionario de los puertos TCP reconocidos por el programa
    std::unordered_map<int, std::string> known_tcp_ports = {
        {20, "FTP (Data)"}, {21, "FTP (Control)"}, {22, "SSH/SFTP"}, {23, "Telnet"},
        {25, "SMTP"}, {53, "DNS"}, {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"}, 
        {179, "BGP"}, {389, "LDAP"}, {443, "HTTPS"}, {445, "SMB/CIFS"}, 
        {587, "SMTP (Secure)"}, {636, "LDAPS"}, {993, "IMAPS"}
    };

    // Diccionario que vincula los puertos UDP más comunes con el nombre de su protocolo
    std::unordered_map<int, std::string> known_udp_ports = {
        {22, "SSH/SFTP"}, {53, "DNS"}, {67, "DHCP (Server)"}, {68, "DHCP (Client)"}, 
        {69, "TFTP"}, {123, "NTP"}, {161, "SNMP"}, {389, "LDAP"}, {443, "QUIC"}, 
        {514, "Syslog"}, {636, "LDAPS"}
    };

    // Función que identifica el servicio revisando tanto el puerto de origen como el de destino
    std::string GetServiceName(int srcPort, int dstPort, const std::unordered_map<int, std::string>& dict) {
        if (dict.count(srcPort)) return dict.at(srcPort); // Verifica si el puerto de salida está en la lista
        if (dict.count(dstPort)) return dict.at(dstPort); // Verifica si el puerto de llegada está en la lista
        return ""; // Retorna un texto vacío si es un puerto desconocido
    }

    // Función que convierte los 6 bytes de la dirección MAC en un texto legible (como -> 0A:1B:2C:3D:4E:5F)
    std::string GetMacString(const unsigned char* mac) {
        // Se reservan 18 espacios en memoria: 12 para los dígitos hexadecimales, 5 para los dos puntos divisorios y 1 para '\0'
        char buffer[18];

        // El formato "%02x" convierte el byte a base-16 (hexadecimal) usando "x" 
        // 02 asegura 2 dígitos por lo menos y rellena con un cero a la izquierda si el valor es menor a 16 (ej. convierte 9 a "09")
        snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        return std::string(buffer); // Devuelve la cadena de texto construida
    }

    void ResetPacketID() {
        std::lock_guard<std::mutex> lock(id_mutex);
        global_packet_id = 1;
    }

    // Función principal que recibe la memoria cruda del paquete y la convierte a nuestra estructura limpia
    PacketData ParseRawPacket(const struct pcap_pkthdr* packetHeader, const u_char* rawBytes, int linkHeaderLength, const struct timeval& firstPacketTime) {
        PacketData data;

        data.length = packetHeader->len; // Copiamos el tamaño total que tuvo el paquete al viajar por el cable
        data.rawBytes.assign(rawBytes, rawBytes + packetHeader->caplen); // Guardamos un clon de los bytes originales para el visor hexadecimal (en UIManager)

        // ============================================================================
        // EXTRACCIÓN DE CAPA 2 (Enlace de Datos / Ethernet)
        // ============================================================================
        if (linkHeaderLength == 14) { // Si la cabecera mide 14 bytes, estamos ante una red Ethernet/Wi-Fi normal
            EthernetHeader* eth = (EthernetHeader*)rawBytes;     // Casteamos la struct Ethernet sobre la memoria
            data.macDest = GetMacString(eth->destinationMac);    // Extraemos y traducimos la MAC hacia donde va
            data.macSource = GetMacString(eth->sourceMac);      // Extraemos y traducimos la MAC desde donde viene
        } else {
            data.macDest = "N/A";   // Si es una red virtual (loopback), no hay MAC
            data.macSource = "N/A"; 
        }

        // Calculo del tiempo transcurrido desde la primer captura del paquete
        long secondsDiff = packetHeader->ts.tv_sec - firstPacketTime.tv_sec;        // Restamos los segundos del paquete actual menos los del primero
        long microsecondsDiff = packetHeader->ts.tv_usec - firstPacketTime.tv_usec; // Restamos las fracciones de segundo (microsegundos)
        
        if (microsecondsDiff < 0) { // Si la resta de fracciones da negativo
            secondsDiff = secondsDiff - 1;      // Pedimos prestado un segundo
            microsecondsDiff = microsecondsDiff + 1000000; // Lo sumamos como un millón de microsegundos
        }
        char timeBuffer[64];
        snprintf(timeBuffer, sizeof(timeBuffer), "%ld.%06ld", secondsDiff, microsecondsDiff); // Unimos segundos y fracciones con un punto
        data.time = timeBuffer; // Lo guardamos en la estructura creada 

        // ============================================================================
        // EXTRACCIÓN DE CAPA 3 (Red / IP)
        // ============================================================================
        const u_char* ipPayload = rawBytes + linkHeaderLength; // Brincamos los primeros bytes (Capa 2) para leer la Capa 3
        IpHeader* ip = (IpHeader*)ipPayload; // Casteamos hacia IPv4
        
        // ">>" desplaza los bits del tamaño de la cabecera para solo leer el tipo de version IP
        if ((ip->versionAndHeader >> 4) != 4) { 
            return data; // Si es otra versión (como IPv6) devolvemos vacío para descartarlo
        }

        {   //Una vez sean solo los paquetes deseados incremetamos el ID
            std::lock_guard<std::mutex> lock(id_mutex);
            data.id = global_packet_id++;
        }
        
        data.source = inet_ntoa(ip->sourceIp);      // Convertimos la IP binaria de origen a texto normal (ej. 192.168.1.1)
        data.destination = inet_ntoa(ip->destIp);   // Convertimos la IP binaria de destino a texto normal
        
        int headerLengthIp = (ip->versionAndHeader & 0x0f) * 4;  // Calculamos el tamaño real del encabezado IP (Multiplicando por 4 bytes)

        // ============================================================================
        // EXTRACCIÓN DE CAPA 4 (Transporte / TCP y UDP)
        // ============================================================================
        const u_char* transportPayload = ipPayload + headerLengthIp;    // Brincamos la Capa 3 para quedar al inicio de la Capa 4

        if (ip->protocol == 6) { // El 6 es el numero de protocolo para TCP
            TcpHeader* tcp = (TcpHeader*)transportPayload; // Casteamos a TCP
            
            int sport = ntohs(tcp->sourcePort);  // Volteamos los bytes del puerto origen para que la PC los lea bien
            int dport = ntohs(tcp->destPort);    // Volteamos los bytes del puerto destino

            data.srcPort = sport;
            data.dstPort = dport;
            
            // Calculamos los datos trae el paquete restando todos los encabezados
            int payloadSize = ntohs(ip->totalLength) - headerLengthIp - ((tcp->dataOffset >> 4) * 4); 
            if (payloadSize < 0) payloadSize = 0; // Prevenimos números negativos si el paquete llegó roto
            
            std::string service = GetServiceName(sport, dport, known_tcp_ports); // Buscamos si es un servicio conocido

            std::string flags = "";
            if (tcp->controlFlags & 0x02) flags += "SYN,";  // Solicitud de conexión
            if (tcp->controlFlags & 0x10) flags += "ACK,";  // Reconocimiento
            if (tcp->controlFlags & 0x01) flags += "FIN,";  // Finalizar conexión
            if (tcp->controlFlags & 0x08) flags += "PSH,";  // Push (Empujar datos)
            if (tcp->controlFlags & 0x04) flags += "RST,";  // Resetear conexión
            if (!flags.empty()) flags.pop_back(); // Quitamos la última coma que sobra en el texto

            if (payloadSize > 1) { // Si el paquete trae carga útil (datos reales, no solo control)
                if (service == "HTTPS") { 
                    data.info = "Application Data (" + std::to_string(payloadSize) + " bytes)"; // Mostramos la cantidad de datos
                } 
                else if (service != "") {
                    data.protocol = service; // Le ponemos el nombre del servicio conocido
                    data.info = service + " Data (" + std::to_string(payloadSize) + " bytes)"; // Mostramos la cantidad de datos
                } 
                else {
                    data.protocol = "TCP"; // Etiqueta estándar si el puerto es desconocido
                    data.info = std::to_string(sport) + " -> " + std::to_string(dport) + " [" + flags + "] Len=" + std::to_string(payloadSize); // Mostramos flujo y banderas
                }
            } 
            else { // Si el paquete no trae datos (tiene 0 o 1 byte) es puro control de conexión
                data.protocol = "TCP"; // Etiqueta estándar
                data.info = std::to_string(sport) + " -> " + std::to_string(dport) + " [" + flags + "] Len=" + std::to_string(payloadSize); // Mostramos el flujo y banderas
            }
        } 
        else if (ip->protocol == 17) { // 17 es el numero de protocolo para UDP
            UdpHeader* udp = (UdpHeader*)transportPayload;   // Casteamos hacia UDP
            int sport = ntohs(udp->sourcePort);     // Acomodamos bytes del puerto origen
            int dport = ntohs(udp->destPort);       // Acomodamos bytes del puerto destino

            data.srcPort = sport;
            data.dstPort = dport;
            
            std::string service = GetServiceName(sport, dport, known_udp_ports); // Buscamos si es un servicio conocido
            
            if (service == "") { 
                data.protocol = "UDP"; // Etiqueta estándar si no conocemos el puerto
                data.info = std::to_string(sport) + " -> " + std::to_string(dport) + " Len=" + std::to_string(ntohs(udp->udpLength)); // Mostramos puertos y longitud total
            } else { 
                data.protocol = service; // Etiquetamos con el nombre del servicio encontrado
                data.info = service + " Message Len=" + std::to_string(ntohs(udp->udpLength)); // Mostramos que es un mensaje de ese servicio
            }
        } 
        else if (ip->protocol == 1) { // El número 1 es el estándar para ICMP (Ping)
            data.protocol = "ICMP"; 
            data.info = "Echo Request/Reply"; // Ponemos descripción estática de que es un ping
        }
        else if (ip->protocol == 2) { // El número 2 es el estándar para IGMP (Transmisión a grupos)
            data.protocol = "IGMP"; 
            data.info = "Multicast Group Membership"; // Ponemos descripción estática de grupo de transmisión
        }

        return data; // Devolvemos el objeto tipo PacketData lleno con toda la información limpia
    }
}