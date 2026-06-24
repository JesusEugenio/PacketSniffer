// ============================================================================
// SnifferCore.cpp
// Es el motor principal de captura. Aquí el programa se conecta físicamente 
// con la tarjeta de red para atrapar todos los datos que pasan por 
// el cable en tiempo real y guardarlos en un vector
// ============================================================================

#include "SnifferCore.h"
#include <winsock2.h>
#include <iphlpapi.h>
#include <xlsxwriter.h>
#include <unordered_map>
#include <thread> // Permite ramificar la ejecución en hilos
#include <atomic> // Variables especializadas a prueba de choques de memoria
#include <fstream>
#include <filesystem>
#include <cstring>

//borrar
#include <iostream>

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

    //para las etiquetas
    std::unordered_map<std::string, Tag> MapIpTag;  //el mapa de etiquetas
    std::mutex tagMutex;                            //evitar colisiones entre la captura y lo grafico
    const std::string archive="ip_tags.bin";        //nombre del archivo

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

    // -- GetWindowsFriendlyNames --
    // Funcion que pregunta a Windows por los nombres de cada tarjeta de red
    // El FriendlyName ayuda a que el usuario reconozca la red donde va a capturar el trafico
    std::unordered_map<std::string, std::string> GetWindowsFriendlyNames() {
        std::unordered_map<std::string, std::string> friendlyNames;
        ULONG outBufLen = 15000; // Reservamos memoria para la respuesta de Windows
        PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        
        // Ejecutamos la consulta a la API de Windows
        if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen) == NO_ERROR) {
            PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
            
            while (pCurrAddresses) {
                // El AdapterName es el UUID (ej. {1234ABCD-5678...})
                std::string adapterName = pCurrAddresses->AdapterName; 
                
                // Windows devuelve el FriendlyName en un formato de texto ancho (PWCHAR). Lo convertimos a un string normal de C++
                int size = WideCharToMultiByte(CP_UTF8, 0, pCurrAddresses->FriendlyName, -1, NULL, 0, NULL, NULL);
                std::string friendlyName(size, 0);
                WideCharToMultiByte(CP_UTF8, 0, pCurrAddresses->FriendlyName, -1, &friendlyName[0], size, NULL, NULL);
                friendlyName.resize(size - 1); // Quitamos el carácter nulo final
                
                // Guardamos en el diccionario -> ej. Clave=UUID, Valor="Wi-Fi"
                friendlyNames[adapterName] = friendlyName;
                
                pCurrAddresses = pCurrAddresses->Next;
            }
        }
        free(pAddresses); // Liberacion de memoria
        return friendlyNames;
    }

    // -- LoadLocalInterfaces --
    // Detecta todas las tarjetas de red instaladas en la computadora y las guarda
    // en la lista localInterfaces para mostrarlas en la pantalla de selección
    void LoadLocalInterfaces() {
        pcap_if_t* allDevs;                 // Puntero a la lista de dispositivos que devuelve Npcap
        char errBuf[PCAP_ERRBUF_SIZE];      // Espacio para mensajes de error
        
        // Obtenemos los FriendlyNames de las tarjetas de red 
        auto windowsFriendlyNames = GetWindowsFriendlyNames();

        if (pcap_findalldevs(&allDevs, errBuf) != -1) { // Si Npcap logra leer los dispositivos del sistema...
            for (pcap_if_t* d = allDevs; d != NULL; d = d->next) { // Recorre la lista uno por uno

                NetworkInterface netIface;  // Crea un objeto para guardar los datos de esta tarjeta
                netIface.name = d->name;    // Guarda el nombre

                // El nombre de Npcap luce asi -> \Device\NPF_{UUID}, extraemos solo el {UUID}
                std::string pcapName = d->name;
                std::string uuid = "";
                size_t pos = pcapName.find('{'); // Buscamos donde empieza la llave
                if (pos != std::string::npos) {
                    uuid = pcapName.substr(pos); // Recortamos la cadena desde la llave hasta el final
                }
                
                // Revisamos si el UUID de Npcap coincide con la lista de nombres
                if (!uuid.empty() && windowsFriendlyNames.count(uuid)) {
                    netIface.description = windowsFriendlyNames[uuid]; // Coincide, le asignamos el nombre
                } 
                else if (d->description != nullptr) { 
                    netIface.description = d->description; // Plan B: Usamos el nombre del driver 
                } 
                else {
                    netIface.description = "Sin Descripcion";
                }

                // Ignoramos los adaptadores virtuales ocultos de Windows
                // No tienen trafico activo por que se utilizan para casos muy muy especificos 
                if (netIface.description.find("WAN Miniport") == std::string::npos) {
                    localInterfaces.push_back(netIface); // Si no es WAN, lo agregamos a la lista
                }
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
        PacketParser::ResetPacketID();// reiniciamos el Id de los paquetes

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

    //Para checar si la IP coincide con la etiqueta
    bool CoincideIpOEtiqueta(const std::string& ipPaquete, const std::string& busqueda, bool usarEtiqueta, bool exacta) {
        if (busqueda.empty()) return true;

        if (usarEtiqueta) { //Si es busqueda por etiqueta
            Tag infoTag;
            if (getTag(ipPaquete, infoTag)) { //si existe la etiqueta
                return exacta ? (infoTag.name == busqueda) : (infoTag.name.find(busqueda) != std::string::npos);
            }
            return false; // Si no hay etiqueta, no pasa el filtro
        }

        //Si no se debe buscar por etiqueta entonces por IP
        return exacta ? (ipPaquete == busqueda) : (ipPaquete.find(busqueda) != std::string::npos);
    }

    // -- FiltrarPaquetes --
    //Filtra el historial original basándose en el tipo de filtro activo y los buffers.
    //Devuelve un nuevo vector con las coincidencias encontradas.
    std::vector<PacketData> FiltrarPaquetes(const std::vector<PacketData>& originales,int tipoFiltro,const char* textoFiltro,
        const char* filtroIP,const char* filtroOrigen,const char* filtroDestino,const char* filtroProtocolo, const char* filtroPuertoOrig,
        const char* filtroPuertoDest,bool ipExactaGlobal, bool etiquetaIP, bool etiquetaOrig, bool etiquetaDest, bool modoEstricto){
        std::vector<PacketData> filtrados;
        filtrados.reserve(originales.size());

        for (const auto& pkt : originales) {
            bool pasaFiltro = false;

            switch (tipoFiltro) {
                case 1: { //IP (Cualquiera: Origen o Destino), el checkbox nos indica si quiere la exacta o solo que la contenga(esto afecta a la terminación de la IP)
                    std::string bIP(textoFiltro);
                    //Si el filtro está vacío, pasa; si no, verifica si coincide por IP o por Etiqueta
                    pasaFiltro = CoincideIpOEtiqueta(pkt.source, bIP, etiquetaIP, ipExactaGlobal) ||
                                 CoincideIpOEtiqueta(pkt.destination, bIP, etiquetaIP, ipExactaGlobal);
                    break;
                }
                case 2: { //IP Origen siempre exacta
                    std::string bOrig(textoFiltro);
                    pasaFiltro = CoincideIpOEtiqueta(pkt.source, bOrig, etiquetaOrig, true); // Origen es exacta
                    break;
                }
                case 3: { //IP Destino siempre exacta
                    std::string bDest(textoFiltro);
                    pasaFiltro = CoincideIpOEtiqueta(pkt.destination, bDest, etiquetaDest, true); // Destino es exacta
                    break;
                }
                case 4: { // Protocolo
                    std::string bProt(textoFiltro);
                    pasaFiltro = bProt.empty() || pkt.protocol.find(bProt) != std::string::npos;
                    break;
                }
                case 5: { // Combinacion
                    std::string bIP(filtroIP), bOrig(filtroOrigen), bDest(filtroDestino), bProt(filtroProtocolo);

                    bool convIP   = CoincideIpOEtiqueta(pkt.source, bIP, etiquetaIP, ipExactaGlobal) ||
                                    CoincideIpOEtiqueta(pkt.destination, bIP, etiquetaIP, ipExactaGlobal);

                    bool convOrig = CoincideIpOEtiqueta(pkt.source, bOrig, etiquetaOrig, true);
                    bool convDest = CoincideIpOEtiqueta(pkt.destination, bDest, etiquetaDest, true);
                    bool convProt = bProt.empty() || pkt.protocol.find(bProt) != std::string::npos;

                    // Logica de Puertos Origen/Destino en Combinado
                    auto EsPuertoValido = [](const char* filtro, int puertoPkt) -> bool {
                        if (filtro[0] == '\0') return true; //Si está vacío, no filtra

                        // Verificamos que sea numérico para evitar errores
                        for (int i = 0; filtro[i] != '\0'; ++i) {
                            if (!isdigit(filtro[i])) return false;
                        }

                        return (puertoPkt != -1 && puertoPkt == std::atoi(filtro));
                    };

                    bool convPortOrig = EsPuertoValido(filtroPuertoOrig, pkt.srcPort);
                    bool convPortDest = EsPuertoValido(filtroPuertoDest, pkt.dstPort);

                    // Solo paquetes con todas las coincidencias se muestran
                    if (modoEstricto) {
                        // Modo AND: Todos deben cumplirse
                        pasaFiltro = convIP && convOrig && convDest && convProt && convPortOrig && convPortDest;
                    } else {
                        // Modo OR: Al menos uno debe cumplirse
                        pasaFiltro = convIP || convOrig || convDest || convProt || convPortOrig || convPortDest;
                    }
                    break;
                }
                case 6:{ // Puerto Origen
                    if (textoFiltro[0] == '\0') {
                        pasaFiltro = true; // Si está vacío, no filtra nada
                    } else {
                        // Validar que sea numérico antes de convertir
                        bool esNumerico = true;
                        for (int i = 0; textoFiltro[i] != '\0'; ++i) {
                            if (!isdigit(textoFiltro[i])) esNumerico = false;
                        }
                        pasaFiltro = esNumerico && (pkt.srcPort != -1 && pkt.srcPort == std::atoi(textoFiltro));
                    }
                    break;
                }
                case 7:{ // Puerto destino
                    if (textoFiltro[0] == '\0') {
                        pasaFiltro = true; // Si está vacío, no filtra nada
                    } else {
                        // Validar que sea numérico antes de convertir
                        bool esNumerico = true;
                        for (int i = 0; textoFiltro[i] != '\0'; ++i) {
                            if (!isdigit(textoFiltro[i])) esNumerico = false;
                        }
                        pasaFiltro = esNumerico && (pkt.dstPort != -1 && pkt.dstPort == std::atoi(textoFiltro));
                    }
                    break;
                }
                default:
                    pasaFiltro = true; //Si es 0 (ninguno), pasan todos los paquetes de una
                    break;
            }

            if (pasaFiltro) {       //Dentro de los casos pasa filtro toma valor verdadero o falso segun se cumplan las condiciones
                filtrados.push_back(pkt);       //si cumple con los estandares entonces deja pasar al paquete al nuevo vector
            }
        }

        return filtrados;       //al final regresa el nuevo vector
    }

    void LoadTags() {
        std::lock_guard<std::mutex> lock(tagMutex);     //Para no intentar agregar y cargar las etiquetas a la vez
        //ruta
        std::filesystem::path exePath = std::filesystem::current_path();
        std::filesystem::path parentPath = exePath.parent_path().parent_path(); //salir del build
        std::filesystem::path dataDir = parentPath/"data";
        std::filesystem::path filePath = dataDir / archive;
        //std::cout << "El programa intentara crear la carpeta aqui: " << filePath << std::endl;

        if (!std::filesystem::exists(filePath)) {       //verificación antes de intentar abrir
            return; //no hay archivo, salir
        }

        std::ifstream file(filePath, std::ios::binary);  //nuestro archivo
        if (!file.is_open()) return;

        MapIpTag.clear();   //limpiamos el mapa
        BinaryTag tag;

        //Lemos el archivo registro por registro
        while (file.read(reinterpret_cast<char*>(&tag), sizeof(BinaryTag))) {
            MapIpTag[tag.ip]={tag.tagName, tag.colorHex};   //almacenamos clave ip, atributos el nombre y el color
        }
        file.close();
    }

    void SaveTags() {
        std::lock_guard<std::mutex> lock(tagMutex);
        //Directorio donde esta el ejecutable
        std::filesystem::path exePath = std::filesystem::current_path();
        //Salimos hasta llegar a la raiz para crear la carpeta
        std::filesystem::path parentPath = exePath.parent_path().parent_path();

        std::filesystem::path dataDir = parentPath/"data";            // Definimos la carpeta donde se va a guardar
        std::filesystem::path filePath = dataDir / archive;      // ruta completa

        //Creamos la carpeta si no existe
        if (!std::filesystem::exists(dataDir)) {
            std::filesystem::create_directories(dataDir);
        }

        std::ofstream file(filePath, std::ios::binary | std::ios::trunc);     //truncamos para guardar nuevamente
        if (!file.is_open()) return;          //si no se abrio salimos

        for (const auto& [ip, tag] : MapIpTag) {                //recorremos el mapa de etiquetas
            BinaryTag record = {};          //nuevo registro
            //Copiamos los elementos al registro
            std::strncpy(record.ip, ip.c_str(), sizeof(record.ip) - 1);
            record.ip[sizeof(record.ip) - 1] = '\0';    //Aseguramos que termine con fin de línea

            std::strncpy(record.tagName, tag.name.c_str(), sizeof(record.tagName) - 1);
            record.tagName[sizeof(record.tagName) - 1] = '\0';

            record.colorHex = tag.colorHex;
            file.write(reinterpret_cast<const char*>(&record), sizeof(BinaryTag));  //Escribimos el registro
        }
        file.close();
    }

    void AddTag(const std::string& ip, const std::string& name, uint32_t colorHex) {
        if (ip.empty() || name.empty()) return;     //no guardar vacios
        {
            std::lock_guard<std::mutex> lock(tagMutex);
            MapIpTag[ip] = { name, colorHex }; // se añade al mapa de etiquetas
        }
        SaveTags(); //actualizamos el binario
    }

    void RemoveTag(const std::string& ip) {     //eliminamos etiqueta con la IP
        {
            std::lock_guard<std::mutex> lock(tagMutex);
            MapIpTag.erase(ip);         // Eliminamos del map
        }
        SaveTags();         //Actualizamos al binario
    }

    bool getTag(const std::string& ip, Tag& outTag) {
        std::lock_guard<std::mutex> lock(tagMutex);
        auto it = MapIpTag.find(ip);        //iterador al mapa
        if (it != MapIpTag.end()) {
            outTag = it->second;        //Si hay etiqueta entonces la coloca en la variable que le mandaron
            return true;
        }
        return false;
    }

    const std::unordered_map<std::string, Tag>& GetAllTags() {
        return MapIpTag;        //Regresa las etiquetas
    }

    bool ExportToCSV(const std::string& filename, const std::vector<PacketData>& packets) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            return false; // Error al abrir el archivo
        }

        file << "ID,Time,Source,Destination,Protocol,Length,Src Port,Dst Port,Info,MAC Source,MAC Destination\n";
        for (const auto& pkt : packets) {
            // ----- Etiquetas -----
            Tag srcTag;
            std::string sourceField = pkt.source;
            if (getTag(pkt.source, srcTag)) {
                sourceField += " (" + srcTag.name + ")";
            }

            Tag destTag;
            std::string destField = pkt.destination;
            if (getTag(pkt.destination, destTag)) {
                destField += " (" + destTag.name + ")";
            }
            //---------------------
            file << pkt.id << ","
                 << pkt.time << ","
                 << sourceField << ","
                 << destField   << ","
                 << pkt.protocol << ","
                 << pkt.length << ","
                 << pkt.srcPort << ","
                 << pkt.dstPort << ","
                 << pkt.info << ","
                 << pkt.macSource << ","
                 << pkt.macDest << "\n";
        }
        file.close();
        return true;
    }

    bool ExportToXLSX(const std::string& filename, const std::vector<PacketData>& packets) {
        lxw_workbook  *workbook  = workbook_new(filename.c_str());
        if (!workbook) return false;
        
        lxw_worksheet *worksheet = workbook_add_worksheet(workbook, "Trafico Capturado");

        lxw_format *header_format = workbook_add_format(workbook);
        format_set_bold(header_format);

        worksheet_write_string(worksheet, 0, 0, "No.", header_format);
        worksheet_write_string(worksheet, 0, 1, "Time", header_format);
        worksheet_write_string(worksheet, 0, 2, "Source", header_format);
        worksheet_write_string(worksheet, 0, 3, "Destination", header_format);
        worksheet_write_string(worksheet, 0, 4, "Protocol", header_format);
        worksheet_write_string(worksheet, 0, 5, "Length", header_format);
        worksheet_write_string(worksheet, 0, 6, "Src Port", header_format);
        worksheet_write_string(worksheet, 0, 7, "Dst Port", header_format);
        worksheet_write_string(worksheet, 0, 8, "Info", header_format);
        worksheet_write_string(worksheet, 0, 9, "MAC Source", header_format);
        worksheet_write_string(worksheet, 0, 10, "MAC Destination", header_format);

        // Ensanchamos las columnas para que la información quepa bien
        worksheet_set_column(worksheet, 1, 1, 15, NULL); // Columna de Tiempo
        worksheet_set_column(worksheet, 2, 3, 20, NULL); // IPs origen y destino
        worksheet_set_column(worksheet, 8, 8, 60, NULL); // Columna Info (muy ancha)
        worksheet_set_column(worksheet, 9, 10, 30, NULL); // Columnas MAC

        int row = 1;
        for (const auto& pkt : packets) {
            // ----- Etiquetas -----
            Tag srcTag, destTag;

            std::string sVal = pkt.source;
            if (getTag(pkt.source, srcTag)) {
                sVal += " (" + srcTag.name + ")";
            }

            std::string dVal = pkt.destination;
            if (getTag(pkt.destination, destTag)) {
                dVal += " (" + destTag.name + ")";
            }
            // ---------------------------------

            worksheet_write_number(worksheet, row, 0, pkt.id, NULL);
            worksheet_write_string(worksheet, row, 1, pkt.time.c_str(), NULL);
            worksheet_write_string(worksheet, row, 2, sVal.c_str(), NULL);
            worksheet_write_string(worksheet, row, 3, dVal.c_str(), NULL);
            worksheet_write_string(worksheet, row, 4, pkt.protocol.c_str(), NULL);
            worksheet_write_number(worksheet, row, 5, pkt.length, NULL);
            if (pkt.srcPort != -1) worksheet_write_number(worksheet, row, 6, pkt.srcPort, NULL);
            else worksheet_write_string(worksheet, row, 6, "-", NULL);

            if (pkt.dstPort != -1) worksheet_write_number(worksheet, row, 7, pkt.dstPort, NULL);
            else worksheet_write_string(worksheet, row, 7, "-", NULL);
            worksheet_write_string(worksheet, row, 8, pkt.info.c_str(), NULL);
            worksheet_write_string(worksheet, row, 9, pkt.macSource.c_str(), NULL);
            worksheet_write_string(worksheet, row, 10, pkt.macDest.c_str(), NULL);
            row++;
        }

        workbook_close(workbook);
        return true;
    }
}
