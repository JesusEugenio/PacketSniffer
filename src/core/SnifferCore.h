// ============================================================================
// SnifferCore.h
// Archivo de configuración que lista las herramientas para encender, apagar 
// y leer la tarjeta de red. Es como el menú de comandos disponibles que el 
// resto del programa puede usar para atrapar el tráfico.
// ============================================================================

#pragma once        // Evita que el compilador procese este archivo de cabecera más de una vez por compilación
#include <string> 
#include <vector> 
#include <mutex>  
#include "../parser/PacketParser.h" // Incluye el módulo encargado de analizar la red

// Estructura que sirve como molde para registrar un dispositivo físico o virtual de la computadora
struct NetworkInterface {
    std::string name;        // Nombre codificado que emplea el sistema operativo
    std::string description; // Nombre comprensible para mostrarle al usuario
};

// Funciones bajo el "apellido" SnifferCore que se encargan del manejo de los paquetes
namespace SnifferCore {
    
    void LoadLocalInterfaces(); // Consulta y carga las tarjetas del equipo
    std::vector<NetworkInterface> GetInterfaces(); // Nos da las tarjetas para mostrarlas a la UI
    
    void StartCapture(const std::string& interfaceName); // Inicia un nuevo proceso de lectura
    void StopCapture(); // Cierra los procesos de lectura activos
    bool IsCapturing(); // Verifica si el bucle del motor está trabajando
    
    std::mutex& GetPacketMutex(); // Provee la llave de seguridad del banco de memoria
    const std::vector<PacketData>& GetCapturedPackets(); // Provee acceso de lectura al historial
    void ClearPackets(); // Reinicia la base de datos de memoria
}