// ============================================================================
// SnifferCore.cpp
// Es el motor principal de captura. Aquí el programa se conecta físicamente 
// con la tarjeta de red para atrapar todos los datos que pasan por 
// el cable en tiempo real y guardarlos en un vector
// ============================================================================

#include "SnifferCore.h" 
#include <thread> // Permite ramificar la ejecución en hilos
#include <atomic> // Variables especializadas a prueba de choques de memoria

namespace SnifferCore {

    // Variables Globales 
    std::vector<NetworkInterface> localInterfaces; // Lista de todas las tarjetas de red encontradas en el sistema
    std::vector<PacketData> capturedPackets;       // Historial completo de paquetes capturados durante la sesión
    std::mutex packetsMutex;                       // Candado que evita que dos hilos lean/escriban la lista al mismo tiempo
    
    pcap_t* captureHandle = nullptr;               // Representa la conexión abierta con la tarjeta de red (null = desconectado)
    std::thread workerThread;                      // El hilo de fondo que captura paquetes sin congelar la interfaz gráfica
    std::atomic<bool> isCapturingFlag(false);      // Bandera compartida entre hilos: true = capturando, false = detenido
    
    int linkHeaderSize = 0;                        // Tamaño de la cabecera física (14 bytes en Ethernet, 4 en túneles VPN)
    struct timeval firstPacketTime;                // Guarda la hora exacta del primer paquete (sirve como reloj cero)
    bool isFirstPacket = true;                     // Indica si aún no se ha capturado ningún paquete en esta sesión

    // -- PcapCallback --
    // Windows llama automáticamente a esta función cada vez que llega un nuevo paquete a la tarjeta de red
    // Recibe los bytes crudos y los guarda en el historial
    void PcapCallback(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* rawBytes) {
        if (isFirstPacket) { // Si es el primer paquete de la sesión...
            firstPacketTime = pkthdr->ts;   // ...guarda su hora como punto de referencia
            isFirstPacket = false;          // Marca que ya se recibió el primer paquete
        }

        // Envía los bytes crudos al analizador (PacketParser) para que los convierta
        // en información legible: IP origen, IP destino, protocolo, etc.
        PacketData parsedData = PacketParser::ParseRawPacket(pkthdr, rawBytes, linkHeaderSize, firstPacketTime);
        
        if (parsedData.protocol == "") { // Si el Parser no pudo identificar el protocolo...
            return; // ...descarta el paquete (filtra IPv6 y protocolos no soportados)
        }
        
        // Bloquea el acceso a la lista para que la interfaz gráfica no la lea mientras se escribe
        // (el bloqueo se libera automáticamente al salir de esta función)
        std::lock_guard<std::mutex> lock(packetsMutex);
        
        capturedPackets.push_back(parsedData);  // Agrega el paquete al final del historial
    }


    // -- CaptureLoop --
    // Esta es la función que ejecuta el hilo de fondo
    // Abre la tarjeta de red y se queda en un bucle infinito esperando paquetes
    // Cada vez que llega uno, llama automáticamente a PcapCallback
    void CaptureLoop(std::string deviceName) {
        char errbuf[PCAP_ERRBUF_SIZE]; // Espacio de texto para guardar mensajes de error si algo falla
        
        // Pide permiso al sistema operativo para leer TODO el tráfico de la tarjeta
        // Modo promiscuo = captura paquetes aunque no estén dirigidos a esta computadora
        // Parámetros: nombre del dispositivo, tamaño máximo de paquete, modo promiscuo=1, timeout=1000ms
        captureHandle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);
        
        if (captureHandle == nullptr) { // Falla y aborta si la tarjeta no responde
            isCapturingFlag = false; 
            return; 
        }
        
         // Detecta qué tipo de red es para saber cuántos bytes tiene la cabecera física
        if (pcap_datalink(captureHandle) == DLT_EN10MB) { // significa que el paquete viene envuelto en una trama Ethernet II clásica
            linkHeaderSize = 14; // Las cabeceras Ethernet ocupan siempre 14 bytes
        } else { 
            linkHeaderSize = 4; // Cualquier otro tipo (ej. túnel VPN, loopback)
        }
        
        // Inicia el bucle de captura: corre indefinidamente (0 = sin límite de paquetes)
        // llama a PcapCallback por cada paquete que llegue a la tarjeta
        pcap_loop(captureHandle, 0, PcapCallback, nullptr); 

        // Cuando el bucle termina (por StopCapture), limpia y cierra la conexión con la tarjeta
        pcap_close(captureHandle); 
        captureHandle = nullptr;

        isCapturingFlag = false; // Notifica a la interfaz gráfica que la captura terminó
    }

    // -- LoadLocalInterfaces --
    // Detecta todas las tarjetas de red instaladas en la computadora y las guarda
    // en la lista localInterfaces para mostrarlas en la pantalla de selección
    void LoadLocalInterfaces() {
        pcap_if_t* allDevs;                 // Puntero a la lista de dispositivos que devuelve Npcap
        char errBuf[PCAP_ERRBUF_SIZE];      // Espacio para mensajes de error
        
        if (pcap_findalldevs(&allDevs, errBuf) != -1) { // Si Npcap logra leer los dispositivos del sistema...
            for (pcap_if_t* d = allDevs; d != NULL; d = d->next) { // Recorre la lista uno por uno

                NetworkInterface netIface;  // Crea un objeto para guardar los datos de esta tarjeta
                netIface.name = d->name;    // Guarda el nombre
                
                if (d->description != nullptr) { // Evalúa la existencia de descripciones
                    netIface.description = d->description;
                } else {
                    netIface.description = "Sin Descripcion";
                }

                localInterfaces.push_back(netIface);    // Agrega la tarjeta a la lista global
            }
            pcap_freealldevs(allDevs); // Libera la memoria que Npcap reservó para la lista
        }
    }

    // -- GetInterfaces --
    // Devuelve la lista de tarjetas de red al código que la solicite
    // (la usa RenderInterfaceSelectionScreen para mostrarlas en pantalla)
    std::vector<NetworkInterface> GetInterfaces() { 
        return localInterfaces; 
    }

    // -- StartCapture --
    // Inicia la captura de paquetes en la tarjeta de red indicada
    // Crea un hilo de fondo para que la captura no congele la interfaz gráfica
    void StartCapture(const std::string& interfaceName) {
        StopCapture(); // Previene choques con ejecuciones pasadas
        
        // Si hay un hilo de fondo anterior que terminó pero no fue limpiado
        // espera a que termine y libera sus recursos
        if (workerThread.joinable()) { 
            workerThread.join(); 
        }

        isCapturingFlag = true;     // Avisa a la interfaz gráfica que la captura comenzó
        isFirstPacket = true;       // Reinicia el cronómetro
        ClearPackets();             // Borra el historial de la sesión anterior para empezar limpio

        // Crea un hilo de fondo que ejecuta CaptureLoop de forma paralela
        // Así la interfaz gráfica sigue respondiendo mientras se capturan paquetes
        workerThread = std::thread(CaptureLoop, interfaceName); 
    }

    // -- StopCapture --
    // Detiene la captura de paquetes 
    // No destruye el historial, solo frena la entrada de nuevos paquetes
    void StopCapture() {
        if (captureHandle != nullptr && isCapturingFlag) { // Solo actúa si realmente hay una captura activa
            pcap_breakloop(captureHandle); // Aplica una señal de paro intencional para romper la captura
        }
    }

    // -- IsCapturing --
    // Devuelve true si la captura está activa, false si está detenida
    // La usa la interfaz gráfica para saber qué botones mostrar
    bool IsCapturing() { 
        return isCapturingFlag; 
    }

    // -- GetPacketMutex --
    // Entrega el candado (mutex) al código que necesite leer el historial de paquetes
    // Quien lo use debe tomarlo antes de leer y soltarlo al terminar
    std::mutex& GetPacketMutex() { 
        return packetsMutex; 
    }

    // -- GetCapturedPackets --
    // Devuelve el historial completo de paquetes capturados
    // Se devuelve por referencia (sin copiar) para que sea eficiente con listas grandes.
    // NOTA PARA EL EQUIPO: Siempre usar junto con GetPacketMutex() para evitar accesos simultáneos
    const std::vector<PacketData>& GetCapturedPackets() { 
        return capturedPackets; 
    }

    // -- ClearPackets ---
    // Borra todo el historial de paquetes capturados
    // Usa el candado para evitar borrar mientras la interfaz gráfica está leyendo
    void ClearPackets() {
        std::lock_guard<std::mutex> lock(packetsMutex);  // Bloquea el acceso externo mientras se borra
        capturedPackets.clear(); // Elimina todos los paquetes de la lista
    }

    // -- FiltrarPaquetes --
    //Filtra el historial original basándose en el tipo de filtro activo y los buffers.
    //Devuelve un nuevo vector con las coincidencias encontradas.
    std::vector<PacketData> FiltrarPaquetes(const std::vector<PacketData>& originales,int tipoFiltro,
        const char* textoFiltro,const char* filtroIP,const char* filtroOrigen,const char* filtroDestino,
        const char* filtroProtocolo, bool exactaGlobal){
        std::vector<PacketData> filtrados;
        filtrados.reserve(originales.size());

        for (const auto& pkt : originales) {
            bool pasaFiltro = false;

            switch (tipoFiltro) {
                case 1: { //IP (Cualquiera: Origen o Destino), el checkbox nos indica si quiere la exacta o solo que la contenga(esto afecta a la terminación de la IP)
                    std::string ipBuscada(textoFiltro);     //Convierte a String y renombra
                    if (ipBuscada.empty()) pasaFiltro = true;
                    else {
                        //Pasar o no seguyn si necesita de la exacta o no
                        bool origOk = exactaGlobal ? (pkt.source == ipBuscada) : (pkt.source.find(ipBuscada) != std::string::npos);
                        // !=std::string::npos  tal cual, regresa verdadero mientras el resultado sea distinto de un error especial (no position/no lo encontro)
                        bool destOk = exactaGlobal ? (pkt.destination == ipBuscada) : (pkt.destination.find(ipBuscada) != std::string::npos);
                        if (origOk || destOk) pasaFiltro = true;
                    }
                    break;
                }
                case 2: { //IP Origen siempre exacta
                    std::string ipBuscada(textoFiltro);
                    if (ipBuscada.empty() || pkt.source == ipBuscada) {
                        pasaFiltro = true;
                    }
                    break;
                }
                case 3: { //IP Destino siempre exacta
                    std::string ipBuscada(textoFiltro);
                    if (ipBuscada.empty() || pkt.destination == ipBuscada) {
                        pasaFiltro = true;
                    }
                    break;
                }
                case 4: { // Protocolo
                    std::string protoBuscado(textoFiltro);
                    if (protoBuscado.empty() || pkt.protocol.find(protoBuscado) != std::string::npos) {
                        pasaFiltro = true;
                    }
                    break;
                }
                case 5: { //Combinacion
                    std::string bIP(filtroIP), bOrig(filtroOrigen), bDest(filtroDestino), bProt(filtroProtocolo);

                    //Si no manda nada entonces esa digamos que ya es verdadero para no evaluarla
                    //Si tiene texto, entonces busca la coincidencia con .find (o de forma exacta segun el checkbox)
                    //IP global, parcial o exacta según el checkbox
                    bool convIP = bIP.empty() || (exactaGlobal ? (pkt.source == bIP || pkt.destination == bIP)
                                                               : (pkt.source.find(bIP) != std::string::npos || pkt.destination.find(bIP) != std::string::npos));

                    //origen y destino exactas por default
                    bool convOrig = bOrig.empty() || (pkt.source == bOrig);
                    bool convDest = bDest.empty() || (pkt.destination == bDest);

                    //protocolo siempre busqueda parcial
                    bool convProt = bProt.empty() || pkt.protocol.find(bProt) != std::string::npos;

                    //Solo paquetes con todas las coincidencias se muestran
                    if (convIP && convOrig && convDest && convProt) {
                        pasaFiltro = true;
                    }
                    break;
                }
                default:
                    pasaFiltro = true; //Si es 0 (ninguno), pasan todos los paquetes de una
                    break;
            }

            if (pasaFiltro) {
                filtrados.push_back(pkt);
            }
        }

        return filtrados;
    }
}