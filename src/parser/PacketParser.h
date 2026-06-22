// ============================================================================
// PacketParser.h
// Contiene las plantillas o moldes que describen cómo están construidos 
// los paquetes de red (Ethernet, IP, TCP, UDP). Nos sirve como un diccionario 
// para saber qué significa cada sección de bytes.
// ============================================================================

#pragma once        // Evita que el compilador procese este archivo de cabecera más de una vez por compilación
#include <string>
#include <vector>
#include <winsock2.h>
#include <pcap/pcap.h>

// ============================================================================
// ESTRUCTURAS DE RED 
// ============================================================================

// Capa 2: Encabezado de Enlace de Datos (Ethernet)
struct EthernetHeader {
    unsigned char destinationMac[6];    // Dirección MAC hacia donde va el paquete
    unsigned char sourceMac[6];         // Dirección MAC desde donde viene el paquete
    unsigned short protocolType;        // Tipo de protocolo que viaja dentro
};

// Capa 3: Encabezado de Red (IPv4)
struct IpHeader {
    unsigned char versionAndHeader;     // Contiene la versión de IP (IPv4) y el tamaño del encabezado
    unsigned char typeOfService;        // Prioridad o calidad de servicio del paquete
    unsigned short totalLength;         // Tamaño total del paquete IP (encabezado + datos)
    unsigned short identification;      // Número único para identificar fragmentos de un paquete dividido
    unsigned short fragmentOffset;      // Indica la posición de este fragmento respecto al paquete original
    unsigned char timeToLive;           // Saltos máximos permitidos antes de destruir el paquete (TTL)
    unsigned char protocol;             // Protocolo de transporte que lleva dentro (ej. TCP=6, UDP=17)
    unsigned short checksum;            // Suma matemática para verificar que el encabezado no esté corrupto
    struct in_addr sourceIp;            // Dirección IP de origen 
    struct in_addr destIp;              // Dirección IP del destinatario
};

// Capa 4: Encabezado de TCP
struct TcpHeader {
    unsigned short sourcePort;        // Puerto de origen 
    unsigned short destPort;          // Puerto de destino 
    unsigned int sequenceNum;         // Número de secuencia para ordenar los datos que llegan fragmentados
    unsigned int acknowledgmentNum;   // Número de confirmación (ACK) de los datos recibidos
    unsigned char dataOffset;         // Tamaño del propio encabezado TCP
    unsigned char controlFlags;       // Banderas de control de conexión (SYN, ACK, FIN, PSH, RST)
    unsigned short windowSize;        // Tamaño de la ventana de recepción (control de flujo de datos)
    unsigned short checksum;          // Suma matemática para verificar que los datos TCP estén intactos
    unsigned short urgentPointer;     // Indica si hay datos urgentes que procesar de inmediato
};

// Capa 4: Encabezado de UDP
struct UdpHeader {
    unsigned short sourcePort;       // Puerto de origen
    unsigned short destPort;         // Puerto de destino 
    unsigned short udpLength;        // Tamaño total del mensaje UDP (encabezado + datos)
    unsigned short checksum;         // Suma matemática de verificación de errores
};

// Capa 4: Encabezado ICMP 
struct icmp_header {
    unsigned char  type;     // 8 para solicitud (request), 0 para respuesta (reply)
    unsigned char  code;     // Subtipo del mensaje
    unsigned short checksum; // Verificación de errores
    unsigned short id;       // Identificador del mensaje
    unsigned short seq;      // Número de secuencia
};

// Capa 3/4: Encabezado IGMP (Usado para Multicast y Streaming en red)
struct igmp_header {
    unsigned char  type;         // Tipo de mensaje (ej. Membership Query)
    unsigned char  maxRespTime;  // Tiempo máximo de respuesta
    unsigned short checksum;     // Verificación de integridad
    struct in_addr groupAddress; // Dirección IP del grupo multicast
};

// ============================================================================
// ESTRUCTURA VISUAL (Los datos que se enviaran a dibujar en ImGui)
// ============================================================================

struct PacketData {
    // Datos para la tabla principal
    int id;
    std::string time;           // Momento exacto en que se capturó el paquete
    std::string source;         // Dirección IP origen en formato de texto legible
    std::string destination;    // Dirección IP destino en formato de texto legible
    std::string protocol;       // Nombre del protocolo detectado (HTTP, TLS, TCP, ICMP, etc.)
    int length;                 // Tamaño total del paquete en bytes
    std::string info;           // Resumen de la información (puertos, banderas, longitud del payload)
    int srcPort = -1;           // Puerto de origen
    int dstPort = -1;           // Puerto de destino
    
    // Datos para el panel de Inspección Profunda 
    std::string macSource;                  // Dirección MAC origen en formato de texto legible
    std::string macDest;                    // Dirección MAC destino en formato de texto legible
    std::vector<unsigned char> rawBytes;    // Copia exacta de los ceros y unos para generar el Hex Dump
};

// namespace es como ponerle a las funciones un "Apellido"
/* Funcion llamada ParseRawPacket que va a analizar todo lo que traen los paquetes y los pone en una 
estructura PacketData, esta funcion esta envuelta con el apellido PacketParser */
namespace PacketParser {
    void ResetPacketID();
    PacketData ParseRawPacket(const struct pcap_pkthdr* packetHeader, const u_char* rawBytes, int linkHeaderLength, 
        const struct timeval& firstPacketTime);

        // - PARAMETROS - 
        // const struct pcap_pkthdr* packetHeader -> Longitud fisica del paquete
        // const u_char* rawBytes -> Dir. de memoria donde empieza el paquete
        // int linkHeaderLength -> Longitud de la capa de enlace
        // const struct timeval& firstPacketTime -> Para saber cuando entro el primer paquete
}