// ============================================================================
// UIManager.cpp
// Se encarga de dibujar todo lo que se ve en la pantalla:
// la tabla de paquetes, los botones, los colores y los menús desplegables 
// ============================================================================

#include "UIManager.h"
#include "imgui.h"                      // Librería para crear la interfaz gráfica (ventanas, botones, etc)
#include "imgui_impl_glfw.h"            // Conecta el mouse y teclado con la interfaz gráfica
#include "imgui_impl_opengl3.h"         // Conecta la interfaz gráfica con la tarjeta de video
#include "../core/SnifferCore.h"        // Acceso al motor que captura paquetes de red
#include "../parser/PacketParser.h"     // Herramientas para leer y analizar paquetes de red
#include "Colores.h"                    //Gama de colores
#include <string>
#include <winsock2.h> 

namespace UIManager {
    // Variables Globales de Estado
    bool isShowingCaptureScreen = false;     // Está mostrando la tabla de paquetes o el menú inicial?
    std::string currentInterfaceName = "";   // Nombre del dispositivo de red seleccionado
    int selectedPacketIndex = -1;            // Registra qué fila de la tabla le dio clic el usuario (-1 es ninguna)

    //Filtros
    static int tipoFiltroActivo = 0;        //tipo de filtro activo
    static char filtroIP[64] = "";
    static char filtroIPOrigen[64] = "";
    static char filtroIPDestino[64] = "";
    static char filtroProtocolo[64] = "";
    static char textoFiltro[64] = "";       //buffer para el filtro
    static bool ipExactaGlobal=false;

    //etiquetas
    static bool viewWindowTag = false;
    static bool editTag=false;


    // Funcion para traducir los nombres de los Protocolos
    std::string GetFullProtocolName(const std::string& shortName) {
        if (shortName == "TLS/SSL" || shortName == "HTTPS") return "Transport Layer Security";
        if (shortName == "HTTP") return "Hypertext Transfer Protocol"; 
        if (shortName == "DNS") return "Domain Name System";
        if (shortName == "QUIC") return "QUIC (Quick UDP Internet Connections)";
        if (shortName == "SSH/SFTP") return "Secure Shell Protocol";
        if (shortName == "FTP (Data)" || shortName == "FTP (Control)") return "File Transfer Protocol";
        if (shortName == "DHCP (Server)" || shortName == "DHCP (Client)") return "Dynamic Host Configuration Protocol";
        if (shortName == "BGP") return "Border Gateway Protocol";
        return shortName + " Application Data"; // Etiqueta genérica si el protocolo no es reconocido por el programa
    }

    // Mostrar datos de la capa de aplicación (Capa 7)
    void DrawApplicationLayer(const std::string& appProtocol, int payloadSize) {
        if (payloadSize <= 0) return; // Si no hay datos, no muestra nada

        // Obtiene el nombre completo del protocolo (ejemplo: HTTP -> Hypertext Transfer Protocol)
        std::string fullName = GetFullProtocolName(appProtocol); 
        
        // Crea un nodo que se puede expandir/contraer en la interfaz gráfica (como un árbol)
        if (ImGui::TreeNode(fullName.c_str())) { 
            ImGui::Text("Payload Length: %d bytes", payloadSize); // Muestra cuántos datos útiles trae el paquete
            ImGui::TreePop(); // Cierra el nodo
        }
    }

    // Mostrar información de un paquete ICMP
    void DrawICMP(const unsigned char* raw, int offset, size_t captureSize) {
        // Comprueba que hay suficientes bytes para leer un paquete ICMP válido
        if (captureSize < offset + 4) return; 
        
        // Lee la estructura de datos ICMP desde la memoria del paquete capturado
        icmp_header* icmp = (icmp_header*)(raw + offset); 

        // Abre el nodo principal en la interfaz
        if (ImGui::TreeNode("Internet Control Message Protocol")) { 
            // Determina si es una pregunta (ping) o una respuesta
            std::string pingType = "Unknown"; 
            if (icmp->type == 8) pingType = "Echo (ping) Request";      // El tipo 8 indica que nuestra máquina lanzó la pregunta
            else if (icmp->type == 0) pingType = "Echo (ping) Reply";   // El tipo 0 indica que el servidor remoto respondió

            ImGui::Text("Type: %d (%s)", icmp->type, pingType.c_str()); // Muestra qué tipo de ping es
            ImGui::Text("Code: %d", icmp->code);                        // Muestra un código de diagnóstico
            ImGui::Text("Checksum: 0x%04x", ntohs(icmp->checksum));     // Muestra el resultado del checksum ()
            
            ImGui::Text("Identifier: %d", ntohs(icmp->id));             // ID único de esta conversación
            ImGui::Text("Sequence number: %d", ntohs(icmp->seq));       // Número de intento (ping 1, ping 2, ping 3...)
            ImGui::TreePop();  // Cierra el nodo gráfico
        }
    }

    // Mostrar información de un paquete IGMP
    void DrawIGMP(const unsigned char* raw, int offset, size_t captureSize) {
        // Comprueba que hay suficientes bytes para leer un paquete IGMP válido
        if (captureSize < offset + 8) return; 
        
        igmp_header* igmp = (igmp_header*)(raw + offset); // Superpone la plantilla estructural IGMP sobre la RAM
        
        // Abre el nodo principal
        if (ImGui::TreeNode("Internet Group Management Protocol")) { 
            ImGui::Text("Type: 0x%02x", igmp->type);                              // Tipo de mensaje (en formato hexadecimal)
            ImGui::Text("Max Response Time: %d", igmp->maxRespTime);              // Tiempo máximo que puede tardar en responder
            ImGui::Text("Checksum: 0x%04x", ntohs(igmp->checksum)); 
            ImGui::Text("Multicast Address: %s", inet_ntoa(igmp->groupAddress));  // Dirección IP del grupo (formato de texto)
            ImGui::TreePop(); // Cierra el nodo gráfico
        }
    }

    // Mostrar información de un paquete UDP
    void DrawUDP(const unsigned char* raw, int offset, size_t captureSize, const std::string& appProtocol) {
        // Comprueba que hay suficientes bytes para leer un paquete UDP válido
        if (captureSize < offset + 8) return; 
        
        UdpHeader* udp = (UdpHeader*)(raw + offset);    // Superpone el molde UDP sobre los bytes correspondientes
        int udpLen = ntohs(udp->udpLength);             // Lee la longitud total del paquete
        
        // Construye un título que muestra los puertos de origen y destino
        std::string title = "User Datagram Protocol, Src Port: " + std::to_string(ntohs(udp->sourcePort)) + ", Dst Port: " + std::to_string(ntohs(udp->destPort));
         
        // Abre el nodo UDP con el título personalizado
        if (ImGui::TreeNode(title.c_str())) { 
            ImGui::Text("Source Port: %d", ntohs(udp->sourcePort));         // Puerto origen (de dónde viene)
            ImGui::Text("Destination Port: %d", ntohs(udp->destPort));      // Puerto destino (a dónde va)
            ImGui::Text("Length: %d", udpLen);                              // Longitud total en bytes
            ImGui::Text("Checksum: 0x%04x", ntohs(udp->checksum)); 
            ImGui::TreePop(); // Cierra el nodo UDP
        }
        
        // Pasa los datos al siguiente nivel (la capa de aplicación)
        // Resta 8 bytes que es el tamaño fijo de la cabecera UDP para obtener los datos reales
        DrawApplicationLayer(appProtocol, udpLen - 8); 
    }

    // Mostrar información de un paquete TCP
    void DrawTCP(const unsigned char* raw, int offset, size_t captureSize, int ipTotalLen, int ipHeaderLen, const std::string& appProtocol) {
        // TCP requiere mínimo 20 bytes
        if (captureSize < offset + 20) return; 
       
        TcpHeader* tcp = (TcpHeader*)(raw + offset);    // Superpone el molde TCP sobre los bytes correspondientes
        int tcpHeaderLen = (tcp->dataOffset >> 4) * 4;  // Obtiene el tamaño de la cabecera TCP
        
        // Construye el título del nodo combinando los puertos de salida y llegada
        std::string title = "Transmission Control Protocol, Src Port: " + std::to_string(ntohs(tcp->sourcePort)) + 
                            ", Dst Port: " + std::to_string(ntohs(tcp->destPort));
        
        // Abre el nodo de info TCP 
        if (ImGui::TreeNode(title.c_str())) { 
            ImGui::Text("Source Port: %d", ntohs(tcp->sourcePort));     // Imprime puerto origen
            ImGui::Text("Destination Port: %d", ntohs(tcp->destPort));  // Imprime puerto destino
            
            // Llama a ntohl (Network-To-Host-Long) porque el número de secuencia TCP usa enteros largos de 32 bits (4 bytes)
            ImGui::Text("Sequence Number (raw): %u", ntohl(tcp->sequenceNum)); 
            ImGui::Text("Acknowledgment Number (raw): %u", ntohl(tcp->acknowledgmentNum)); 
            ImGui::Text("Header Length: %d bytes", tcpHeaderLen); // Tamaño cabecera
            
            char flagsTitle[64]; // Texto temporal para flags
            snprintf(flagsTitle, sizeof(flagsTitle), "Flags: 0x%03x", tcp->controlFlags); // Empaqueta todos los estados booleanos en un solo código hexadecimal
            
            // Abre un sub-nodo anidado para explicar bandera por bandera
            if (ImGui::TreeNode(flagsTitle)) { 
                // Aplica máscaras lógicas AND (&) bit a bit contra los valores físicos estandarizados de cada bandera 
                if (tcp->controlFlags & 0x20) ImGui::Text("[Set] Urgent"); else ImGui::Text("[Not set] Urgent"); 
                if (tcp->controlFlags & 0x10) ImGui::Text("[Set] Acknowledgment"); else ImGui::Text("[Not set] Acknowledgment"); 
                if (tcp->controlFlags & 0x08) ImGui::Text("[Set] Push"); else ImGui::Text("[Not set] Push"); 
                if (tcp->controlFlags & 0x04) ImGui::Text("[Set] Reset"); else ImGui::Text("[Not set] Reset");
                if (tcp->controlFlags & 0x02) ImGui::Text("[Set] Syn"); else ImGui::Text("[Not set] Syn"); 
                if (tcp->controlFlags & 0x01) ImGui::Text("[Set] Fin"); else ImGui::Text("[Not set] Fin");
                ImGui::TreePop(); // Cierra el sub-nodo de las banderas
            }
            
            ImGui::Text("Window size value: %d", ntohs(tcp->windowSize)); 
            ImGui::TreePop(); // Cierra el nodo padre de TCP
        }
        
        // Calcula los bytes de datos reales: total IP - cabecera IP - cabecera TCP = payload
        int payloadSize = ipTotalLen - ipHeaderLen - tcpHeaderLen; 
        DrawApplicationLayer(appProtocol, payloadSize); // Pasa los datos al dibujador de la capa de aplicación
    }

    // ============================================================================
    // CONFIGURACIÓN ESTÉTICA (ImGui Style)
    // ============================================================================
    
    // Configura todas las propiedades de color para la interfaz gráfica
    void SetupColors() {
        ImGuiStyle& style = ImGui::GetStyle(); // Obtiene el acceso directo a la memoria real de estilo
        
        // Redondeamos las esquinas de los botones y ventanas
        style.FrameRounding = 4.0f; //
        style.WindowRounding = 6.0f; //
        
        // Color Primario (Gris Azulado): #8695A5 -> Invertido a A59586 + Alpha FF (Totalmente Opaco)
        /* Se invierte ya que el procesador utiliza una arquitectura Little Endian para el almacenamiento en memoria
        por lo que debemos invertir el color para que lo guarde en el orden correcto */
        ImVec4 primaryColor = ImGui::ColorConvertU32ToFloat4(0xFFA59586); 
        
        style.Colors[ImGuiCol_Header] = primaryColor;   // Color de fila seleccionada en listas
        style.Colors[ImGuiCol_Button] = primaryColor;   // Color de fondo de botones
        style.Colors[ImGuiCol_TitleBg] = primaryColor;  // Color del título de las ventanas
        
        // Color Hover (Color Primario mas claro): #909FAF -> FFAF9F90
        ImVec4 hoverColor = ImGui::ColorConvertU32ToFloat4(0xFFAF9F90);
        style.Colors[ImGuiCol_HeaderHovered] = hoverColor; 
        style.Colors[ImGuiCol_ButtonHovered] = hoverColor;
        
        // Color Active (Color que toma al hacer clic): #7C8B9B -> FF9B8B7C
        ImVec4 activeColor = ImGui::ColorConvertU32ToFloat4(0xFF9B8B7C);
        style.Colors[ImGuiCol_HeaderActive] = activeColor; 
        style.Colors[ImGuiCol_ButtonActive] = activeColor; 
        
        // Colores de Fondo, Paneles y Texto 
        style.Colors[ImGuiCol_WindowBg] = ImGui::ColorConvertU32ToFloat4(0xFFFFFFFF);    // Fondo de la ventana -> Blanco Puro (#FFFFFF) 
        style.Colors[ImGuiCol_FrameBg] = ImGui::ColorConvertU32ToFloat4(0xFFFFFFFF);     // Fondo de campos y controles -> Blanco Puro (#FFFFFF)
        style.Colors[ImGuiCol_ChildBg] = ImGui::ColorConvertU32ToFloat4(0xFFF5F5F5);     // Fondo de sub-paneles -> Gris Claro (#F5F5F5)
        style.Colors[ImGuiCol_Text] = ImGui::ColorConvertU32ToFloat4(0xFF1A1A1A);        // Color de Texto -> Gris Oscuro (#1A1A1A)
        style.Colors[ImGuiCol_TableHeaderBg] = ImGui::ColorConvertU32ToFloat4(0xFFD9D9D9); // Fondo del encabezado de columnas -> Gris Plomo (#D9D9D9)
    }

    // ============================================================================
    // INICIALIZAR Y CERRAR LA VENTANA DEL PROGRAMA
    // ============================================================================

    GLFWwindow* InitializeWindow() {
        if (!glfwInit()) return nullptr; // Aborta y retorna null si el SO rechaza la creación gráfica
        
        // Crea la ventana del programa
        GLFWwindow* window = glfwCreateWindow(1280, 800, "PacketSniffer", NULL, NULL);
        glfwMakeContextCurrent(window); // Le dice a la tarjeta de video que dibuje to_do esta ventana
        glfwSwapInterval(1);            // Enciende la Sincronización Vertical (V-Sync) para empatar los frames con los Hz del monitor
        
        IMGUI_CHECKVERSION();       // Macro de seguridad que verifica que la versión de ImGui instalada coincide con la que se usó al compilar
        ImGui::CreateContext();     // Reserva la memoria que ImGui necesita para funcionar
        
        // Cargamos la fuente del programa
        ImFont* font = ImGui::GetIO().Fonts->AddFontFromFileTTF("fonts/segoeui.ttf", 18.0f); 
        if (font == nullptr) { ImGui::GetIO().FontGlobalScale = 1.5f; } // Usa la fuente predeterminada
        
        ImGui_ImplGlfw_InitForOpenGL(window, true);  // Conecta los eventos del mouse/teclado de GLFW hacia ImGui
        ImGui_ImplOpenGL3_Init("#version 130");     // Inicializa el renderizado con OpenGL
        
        SetupColors(); // Aplica los colores y el estilo definidos
        return window; // Devuelve la ventana lista para usar
    }

    void ShutdownWindow(GLFWwindow* window) {
        ImGui_ImplOpenGL3_Shutdown();   // Libera los recursos de renderizado en la tarjeta de video
        ImGui_ImplGlfw_Shutdown();      // Desconecta los eventos del mouse y teclado
        ImGui::DestroyContext();        // Aniquila la memoria dinámica de ImGui
        glfwDestroyWindow(window);      // Destruye la ventana del sistema operativo
        glfwTerminate();                //  Apaga completamente el motor gráfico GLFW
    }

    // ============================================================================
    // INTERFACES DEL PROGRAMA
    // ============================================================================

    // Pantalla Inicial - Lista de Interfaces de Red 
    void RenderInterfaceSelectionScreen() {

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(Colores::AZULMARINOOSCURO), "Selecciona una interfaz haciendo doble clic para comenzar a capturar trafico");
        ImGui::Separator();  // Dibuja una línea horizontal separadora
        ImGui::Spacing();    // Añade un espacio vertical
        
        // Dibujamos un boton decorativo que sirve como encabezado para la interfaz
        ImGui::PushStyleColor(ImGuiCol_Button, ImGui::ColorConvertU32ToFloat4(Colores::MORADOGRISACEO));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::ColorConvertU32ToFloat4(Colores::MORADOGRISACEO));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Colores::NEGRO));   // Color del texto sobre el boton
        ImGui::Button("Tarjetas de red locales:", ImVec2(-FLT_MIN, 0));                     // Boton que ocupa to_do el ancho disponible
        ImGui::PopStyleColor(3); // Quita las 3 reglas de color que se aplicaron arriba (limpieza)

        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(Colores::CREMAPASTEL));
        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImGui::ColorConvertU32ToFloat4(Colores::MORADOVIEJO));
        ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImGui::ColorConvertU32ToFloat4(Colores::VERDEMENTAGRISACEO));
        // Abre una lista desplazable que ocupa to_do el espacio restante de la ventana
        if (ImGui::BeginListBox("##NetworkCards", ImVec2(-FLT_MIN, -FLT_MIN))) { 
            // Pide el vector de tarjetas al Core y lo itera uno por uno
            ImGui::Indent(10.0f);
            for (auto& iface : SnifferCore::GetInterfaces()) {
                // Crea un elemento de lista interactivo con el nombre de la tarjeta
                if (ImGui::Selectable(iface.description.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick)) { 
                    if (ImGui::IsMouseDoubleClicked(0)) { // Si el usuario hace doble clic izquierdo...
                        currentInterfaceName = iface.description;   // Guarda el nombre de la tarjeta elegida
                        isShowingCaptureScreen = true;              // Cambia a la pantalla de captura
                        SnifferCore::StartCapture(iface.name);      // Ordena al motor que empiece a capturar paquetes
                    }
                }
            }
            ImGui::EndListBox(); // Cierra la lista
        }
        ImGui::PopStyleColor(3);
    }

    // Barra Superior ubicada antes de la tabla de captura de paquetes
    void RenderCaptureToolbar() {
        ImGui::PushStyleColor(ImGuiCol_Button, ImGui::ColorConvertU32ToFloat4(Colores::BOTONESGENERAL));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImGui::ColorConvertU32ToFloat4(Colores::BOTONESGENERALPRESS));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::ColorConvertU32ToFloat4(Colores::BOTONESGENERALHOVER));
        if (SnifferCore::IsCapturing()) { // Si la captura de paquetes está activa...
            if (ImGui::Button("Detener Captura", ImVec2(150, 30))) { // Dibuja el boton
                SnifferCore::StopCapture(); // Al hacer clic, detiene la captura
            }
            ImGui::SameLine(); // El siguiente elemento se dibuja en la misma línea (no baja al renglón)
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(Colores::ROSAVIEJOOSCURO), " Capturando...");

        } 
        else { // Si la captura ya terminó o no ha iniciado...

            if (ImGui::Button("Volver a Interfaces", ImVec2(200, 30))) {
                tipoFiltroActivo=0;
                SnifferCore::StopCapture();         // Para la captura por seguridad (si es que habia algo activo)
                isShowingCaptureScreen = false;     // Vuelve al menú de selección de interfaz
                selectedPacketIndex = -1;           // Limpia la selección para evitar leer memoria de un paquete que ya no existe
            }
            ImGui::SameLine();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(Colores::ROSAVIEJOOSCURO), " Captura finalizada. Haz clic en un paquete para inspeccionarlo");
        }
        ImGui::PopStyleColor(3);
    }

    //Menu superior (algunas funciones son redundantes)
    void RenderToolbarTop() {
        //Fondo de lo desplegable
        ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(Colores::TOOLBAR));
        //Color del texto
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Colores::NEGRO));
        //Color de los botones al pasar el mouse por encima
        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImGui::ColorConvertU32ToFloat4(Colores::AZULGRISACEO));
        //pa seleccion en barra
        ImGui::PushStyleColor(ImGuiCol_Header, ImGui::ColorConvertU32ToFloat4(Colores::AZULGRISACEO));

        if (ImGui::BeginMenuBar()) {
            //Crear pestañas para el menu superior
            if (ImGui::BeginMenu("Captura")) {
                viewWindowTag=false;
                if (ImGui::MenuItem("Detener Captura")) {
                    if (SnifferCore::IsCapturing()) {
                        SnifferCore::StopCapture();
                    }
                }
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("Filtros")) {
                viewWindowTag=false;
                //Las opciones de esa pestaña, retorna true si es que se cliquea esa opcion
                if (ImGui::MenuItem("IP"))
                {
                    ipExactaGlobal = false;
                    tipoFiltroActivo = 1;
                    memset(textoFiltro, 0, sizeof(textoFiltro));
                }
                if (ImGui::MenuItem("IP Origen")) {
                    tipoFiltroActivo = 2;
                    memset(textoFiltro, 0, sizeof(textoFiltro));
                }
                if (ImGui::MenuItem("IP Destino")) {
                    tipoFiltroActivo = 3;
                    memset(textoFiltro, 0, sizeof(textoFiltro));
                }
                ImGui::Separator();                     //estetica
                if (ImGui::MenuItem("Protocolo")) {
                    tipoFiltroActivo = 4;
                    memset(textoFiltro, 0, sizeof(textoFiltro));
                }
                if (ImGui::MenuItem("Combinado")) {
                    ipExactaGlobal = false;
                    tipoFiltroActivo = 5;
                    memset(filtroProtocolo, 0, sizeof(filtroProtocolo));
                    memset(filtroIP, 0, sizeof(filtroIP));
                    memset(filtroIPOrigen, 0, sizeof(filtroIPOrigen));
                    memset(filtroIPDestino, 0, sizeof(filtroIPDestino));
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Eliminar Filtros")) {
                    tipoFiltroActivo = 0;
                }
                ImGui::EndMenu();       //pa cerrar el menú
            }
            if (ImGui::BeginMenu("Etiquetas")) {
                if (ImGui::MenuItem("Gestionar Etiquetas")) {
                    viewWindowTag=true;
                }
                ImGui::EndMenu();
            }
            ImGui::EndMenuBar();
        }
        ImGui::PopStyleColor(4);
    }

    //Para la ventana de gestión de etiquetas
    void RenderTagManagment() {
        //Si no es necesario no la dibuja
        if (!viewWindowTag) return;

        static char textEdit[15]=" ";

        static char inputIP[46] = "";
        static char inputName[32] = "";
        static ImVec4 inputColor = ImVec4(0.937f, 0.792f, 0.898f, 1.0f);
        ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::ColorConvertU32ToFloat4(Colores::CREMAPASTEL));
        ImGui::PushStyleColor(ImGuiCol_TitleBgActive, ImGui::ColorConvertU32ToFloat4(Colores::AZULGRISACEO));//Barra de titulo
        // Creamos una ventana normal e independiente que flotará sobre el sniffer
        ImGui::Begin("Gestión de Etiquetas", &viewWindowTag, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoCollapse);

        //Si el usuario cliquea fuera de la ventana entonces la desactiva
        if (ImGui::IsMouseClicked(0) && !ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) {
            viewWindowTag = false; // Cerramos la ventana automáticamente
        }
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(0xFF000000), "Añadir / Modificar Etiqueta:");

        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(Colores::INPUT));         // Fondo Blanco
        ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImGui::ColorConvertU32ToFloat4(Colores::INPUT));  // Fondo al pasar mouse
        ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImGui::ColorConvertU32ToFloat4(Colores::INPUT));   // Fondo al escribir
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Colores::TEXTINPUT));           // Texto Negro
        ImGui::PushStyleColor(ImGuiCol_TextSelectedBg, ImGui::ColorConvertU32ToFloat4(Colores::NEGRO)); // Cursor/Selección Negro


        //Placeholder en un gris suave para que se note la sugerencia
        ImGui::PushStyleColor(ImGuiCol_TextDisabled, ImGui::ColorConvertU32ToFloat4(Colores::ROSAVIEJOOSCURO));

        ImGui::InputTextWithHint("Dirección IP", "Ej: 192.168.1.1", inputIP, IM_ARRAYSIZE(inputIP));
        if (ImGui::IsItemActivated() && editTag) {
            editTag = false;
            inputColor = ImVec4(0.937f, 0.792f, 0.898f, 1.0f);
        }

        ImGui::InputTextWithHint("Nombre Etiqueta", "Ej: Servidor", inputName, IM_ARRAYSIZE(inputName));

        ImGui::PopStyleColor(6);



        //Botones
        ImGui::PushStyleColor(ImGuiCol_Button, ImGui::ColorConvertU32ToFloat4(Colores::BOTONESGENERAL));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImGui::ColorConvertU32ToFloat4(Colores::BOTONESGENERALPRESS));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::ColorConvertU32ToFloat4(Colores::BOTONESGENERALHOVER));

        ImGui::ColorEdit4("Color Visual", (float*)&inputColor, ImGuiColorEditFlags_NoAlpha | ImGuiColorEditFlags_NoInputs);
        if (editTag) {
            strcpy(textEdit, "Actualizar");
        }
        else {
            strcpy(textEdit, "Guardar");
        }

        if (ImGui::Button(textEdit, ImVec2(120, 0))) {
            ImU32 colorU32 = ImGui::ColorConvertFloat4ToU32(inputColor);
            SnifferCore::AddTag(inputIP, inputName, colorU32);
            memset(inputIP, 0, sizeof(inputIP));
            memset(inputName, 0, sizeof(inputName));
            editTag=false;
        }

        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(Colores::NEGRO), "Etiquetas Existentes:");

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::ColorConvertU32ToFloat4(Colores::CREMACLARO));    //contenedor de las etiquetas
        if (ImGui::BeginChild("ListaTags", ImVec2(400, 200), true)) {
            for (const auto& [ip, tag] : SnifferCore::GetAllTags()) {
                ImGui::PushID(ip.c_str());
                ImGui::ColorButton("##color", ImGui::ColorConvertU32ToFloat4(tag.colorHex));
                ImGui::SameLine();
                ImGui::Text("%s -> %s", ip.c_str(), tag.name.c_str());
                ImGui::SameLine(ImGui::GetWindowWidth() - 70);

                if (ImGui::Button("Eliminar")) {
                    SnifferCore::RemoveTag(ip);
                }

                ImGui::SameLine(ImGui::GetWindowWidth() - 120);
                if (ImGui::Button("Editar")) {
                    strcpy(inputIP, ip.c_str());
                    editTag = true;
                    inputColor=ImGui::ColorConvertU32ToFloat4(tag.colorHex);
                }
                ImGui::PopID();
            }
            ImGui::EndChild();
        }
        ImGui::PopStyleColor();
        ImGui::Spacing();

        //Botón cerrar manual que también apaga la bandera
        if (ImGui::Button("Cerrar", ImVec2(120, 0))) {
            viewWindowTag = false;
        }
        ImGui::PopStyleColor(3);

        ImGui::End(); //Cierra la sub-ventana
        ImGui::PopStyleColor(2);
    }

    // Tabla de captura de paquetes
    void RenderPacketTable(const std::vector<PacketData>& packets, float tableHeight) {
        //Colores
        //fondo del panel
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::ColorConvertU32ToFloat4(Colores::CREMACLARO));

        //fondo de los encabezados
        ImGui::PushStyleColor(ImGuiCol_TableHeaderBg, ImGui::ColorConvertU32ToFloat4(Colores::VERDEMENTAGRISACEO));

        //Lineas divisoras
        ImGui::PushStyleColor(ImGuiCol_TableBorderLight, ImGui::ColorConvertU32ToFloat4(Colores::GRISVERDIOSOCLARO));
        ImGui::PushStyleColor(ImGuiCol_TableBorderStrong, ImGui::ColorConvertU32ToFloat4(Colores::AZULGRISACEO));

        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImGui::ColorConvertU32ToFloat4(Colores::VERDEMENTAGRISACEO));
        ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImGui::ColorConvertU32ToFloat4(Colores::GRISVERDIOSOCLARO));
        ImGui::PushStyleColor(ImGuiCol_Header, ImGui::ColorConvertU32ToFloat4(Colores::ROSAVIEJO));

        // Crea una región desplazable e independiente del resto de la ventana
        if (ImGui::BeginChild("Tabla", ImVec2(0, tableHeight), true)) {
            // Crea una tabla de 7 columnas con bordes y  filas alternadas 
            if (ImGui::BeginTable("paquetes", 7, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                
                // Definimos el ancho fijo de cada columna en píxeles
                ImGui::TableSetupColumn("No.", ImGuiTableColumnFlags_WidthFixed, 65.0f);
                ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 200.0f);
                ImGui::TableSetupColumn("Destination", ImGuiTableColumnFlags_WidthFixed, 200.0f);
                ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 60.0f);
                ImGui::TableSetupColumn("Info", ImGuiTableColumnFlags_WidthStretch); // Esta columna se expande para llenar el espacio restante
                ImGui::TableHeadersRow(); // Dibujamos la configuracion anterior

                // ImGuiListClipper es una herramienta de optimización:
                // En lugar de dibujar las 10,000 filas, solo dibuja las que el usuario puede ver en pantalla
                ImGuiListClipper clipper; 
                clipper.Begin(packets.size()); // Le dice cuántas filas hay en totals
                
                // Calcula dinámicamente qué filas están a la vista de la resolución del monitor
                while (clipper.Step()) { 
                    for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) { // Dibujaremos solo sobre ese rango
                        const auto& pkt = packets[i];   // Obtiene el paquete correspondiente a esta fila
                        ImGui::TableNextRow();          // Avanza a la siguiente fila de la tabla
                        
                        bool isSelected = (selectedPacketIndex == i); // Es esta la fila que el usuario seleccionó?
                        
                        if (isSelected) { 
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, Colores::VERDEMENTAGRISACEO); // Pinta el fondo en azul
                            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Colores::NEGRO)); // Pone el texto en blanco para que se lea bien
                        }
                        
                        ImGui::TableNextColumn();
                        char label[32]; // Búfer para procesar Los ID's gráficos
                        // Genera el texto de la celda de número: el "##" es invisible, pero ImGui lo necesita para identificar el elemento internamente
                        snprintf(label, sizeof(label), "%d##%d", i + 1, i); 
                        
                        // Hace toda la fila clickeable
                        if (ImGui::Selectable(label, isSelected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) { 
                            if (SnifferCore::IsCapturing() == false) { // Solo permite seleccionar si la captura ya terminó
                                selectedPacketIndex = i; // Guarda el índice del paquete seleccionado
                            }
                        }
                        
                        // Rellenamos el resto de columnas con los datos del paquete 
                        ImGui::TableNextColumn(); ImGui::Text("%s", pkt.time.c_str());  //.c_str() ayuda a ImGui a procesar el texto

                        //Origen columna
                        ImGui::TableNextColumn();
                        SnifferCore::Tag srcTag;
                        if (SnifferCore::getTag(pkt.source,srcTag)) {
                            //Dibujado
                            ImVec2 pos = ImGui::GetCursorScreenPos();
                            ImVec2 textSize = ImGui::CalcTextSize(pkt.source.c_str());

                            //rectángulo de fondo redondeado detrás del texto de la IP
                            ImGui::GetWindowDrawList()->AddRectFilled(
                                ImVec2(pos.x - 3, pos.y - 1),
                                ImVec2(pos.x + textSize.x + 3, pos.y + textSize.y + 1),
                                srcTag.colorHex, 4.0f
                            );
                            //imprimir el nombre
                            ImGui::Text("%s (%s)", pkt.source.c_str(), srcTag.name.c_str());
                        } else {
                            //si no tiene etiqueta solo la IP
                            ImGui::Text("%s", pkt.source.c_str()); // IP normal sin etiqueta
                        }

                        //Destino columna
                        ImGui::TableNextColumn();
                        SnifferCore::Tag destTag;
                        if (SnifferCore::getTag(pkt.destination, destTag)) {
                            //Dibujado
                            ImVec2 pos = ImGui::GetCursorScreenPos();
                            ImVec2 textSize = ImGui::CalcTextSize(pkt.destination.c_str());

                            ImGui::GetWindowDrawList()->AddRectFilled(
                                ImVec2(pos.x - 3, pos.y - 1),
                                ImVec2(pos.x + textSize.x + 3, pos.y + textSize.y + 1),
                                destTag.colorHex, 4.0f
                            );
                            ImGui::Text("%s (%s)", pkt.destination.c_str(), destTag.name.c_str());
                        } else {
                            ImGui::Text("%s", pkt.destination.c_str());
                        }

                        ImGui::TableNextColumn(); ImGui::Text("%s", pkt.protocol.c_str());
                        ImGui::TableNextColumn(); ImGui::Text("%d", pkt.length); 
                        ImGui::TableNextColumn(); ImGui::Text("%s", pkt.info.c_str());
                        
                        if (isSelected) ImGui::PopStyleColor(); // Quita el color blanco del texto (solo aplica a la fila seleccionada)
                    }
                }
                ImGui::EndTable(); // Cierra la tabla
            }
            
            // Auto-scroll: Si está capturando, si hay paquetes y si el usuario no ha seleccionado nada
            if (SnifferCore::IsCapturing() && packets.size() > 0 && selectedPacketIndex == -1) { 
                ImGui::SetScrollHereY(1.0f); // Desplaza la barra de scroll al 100% (al final)
            }
        }
        ImGui::EndChild(); // Cierra la zona desplazable
        ImGui::PopStyleColor(7);
    }

    // Interfaz - Inspeccion Profunda
    // Se divide en dos columnas:
    //   - Izquierda: árbol jerárquico de las capas del paquete
    //   - Derecha: los bytes crudos del paquete en formato hexadecimal
    void RenderPacketDetails(const std::vector<PacketData>& packets) {
        // Solo dibuja si hay un paquete seleccionado y el índice es válido
        if (selectedPacketIndex >= 0 && selectedPacketIndex < packets.size()) {
            ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImGui::ColorConvertU32ToFloat4(Colores::VERDEMENTAGRISACEO));
            ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImGui::ColorConvertU32ToFloat4(Colores::GRISVERDIOSOCLARO));
            ImGui::PushStyleColor(ImGuiCol_Header, ImGui::ColorConvertU32ToFloat4(Colores::ROSAVIEJO));

            const auto& sel_pkt = packets[selectedPacketIndex]; // El paquete seleccionado
            const unsigned char* raw = sel_pkt.rawBytes.data(); // Puntero al inicio de los bytes crudos del paquete
            size_t capSize = sel_pkt.rawBytes.size();           // Cantidad total de bytes capturados
            
            // Crea un panel dividido en 2 columnas
            if (ImGui::BeginTable("bottom", 2, ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable)) {
                ImGui::TableNextRow(); 
                
                // ---------------------------------------------------------------
                // COLUMNA IZQUIERDA: Árbol de capas del modelo OSI
                // Muestra la información descompuesta capa por capa 
                // ---------------------------------------------------------------
                ImGui::TableNextColumn();
                if (ImGui::BeginChild("Arbol", ImVec2(0,0), false, ImGuiWindowFlags_AlwaysHorizontalScrollbar)) { 
                    
                    // --- CAPA 1: Frame (información física de la captura) ---
                    // Muestra el número de frame y su tamaño total
                    if (ImGui::TreeNode(std::string("Frame " + std::to_string(selectedPacketIndex + 1) + ": " + std::to_string(sel_pkt.length) + " bytes on wire").c_str())) { // Abre la capa física
                        ImGui::Text("Arrival Time: %s", sel_pkt.time.c_str()); // Hora exacta en que llego el paquete
                        ImGui::Text("Frame Length: %d bytes", sel_pkt.length); // Tamaño total del paquete en bytes
                        ImGui::TreePop();
                    }
                    
                    // --- CAPA 2: Ethernet (direcciones MAC de hardware) ---
                    // Solo se muestra si hay direcciones MAC válidas (no aplica para túneles VPN)
                    if (sel_pkt.macSource != "N/A" && capSize >= 14) {
                        if (ImGui::TreeNode(std::string("Ethernet II, Src: " + sel_pkt.macSource + ", Dst: " + sel_pkt.macDest).c_str())) { // Abre capa de enlace
                            ImGui::Text("Destination: %s", sel_pkt.macDest.c_str());    // MAC del dispositivo destino
                            ImGui::Text("Source: %s", sel_pkt.macSource.c_str());       // MAC del dispositivo origen
                            ImGui::TreePop();
                        }
                    }
                    
                    // --- CAPA 3: IPv4 (direcciones IP) ---
                    // Salta los primeros 14 bytes (la cabecera Ethernet) para leer el encabezado IP
                    if (capSize > 14) { // Verifica que el tamaño del paquete sea mayor a 14 bytes (la cabecera física de Ethernet II mide eso)
                        IpHeader* ip = (IpHeader*)(raw + 14); // Saltamos la cabecera de Ethernet
                        
                        // Verifica que la versión del protocolo es realmente IPv4
                        if ((ip->versionAndHeader >> 4) == 4) {
                            // Calcular el tamaño real exacto (en bytes) que mide la cabecera del protocolo IPv4
                            int ipHeaderLen = (ip->versionAndHeader & 0x0f) * 4; 
                            int ipTotalLen = ntohs(ip->totalLength); 
                            
                            // Abre capa de red
                            if (ImGui::TreeNode(std::string("Internet Protocol Version 4, Src: " + sel_pkt.source + ", Dst: " + sel_pkt.destination).c_str())) { 
                                ImGui::Text("Version: %d", (ip->versionAndHeader >> 4)); 
                                ImGui::Text("Header Length: %d bytes", ipHeaderLen);                    // Tamaño de la cabecera IP
                                ImGui::Text("Total Length: %d", ipTotalLen);                            // Tamaño total del paquete
                                ImGui::Text("Identification: 0x%04x (%d)", ntohs(ip->identification),   // ID del paquete (se usa para reensamblar fragmentos)
                                    ntohs(ip->identification));                                         
                                ImGui::Text("Time to Live: %d", ip->timeToLive);                        // Número máximo de saltos permitidos antes de descartar el paquete
                                ImGui::Text("Protocol: %d", ip->protocol);                              // Número que indica qué protocolo viene después (6=TCP, 17=UDP, 1=ICMP, 2=IGMP)
                                ImGui::TreePop();
                            }
                            
                            // Calcula dónde empieza el protocolo de transporte:
                            // 14 bytes de Ethernet + tamaño variable de cabecera IP
                            int transportOffset = 14 + ipHeaderLen;
                            
                            // Dibujamos info del protocolo correspondiente
                            if (ip->protocol == 6) DrawTCP(raw, transportOffset, capSize, ipTotalLen, ipHeaderLen, sel_pkt.protocol);
                            else if (ip->protocol == 17) DrawUDP(raw, transportOffset, capSize, sel_pkt.protocol);
                            else if (ip->protocol == 1) DrawICMP(raw, transportOffset, capSize);
                            else if (ip->protocol == 2) DrawIGMP(raw, transportOffset, capSize);
                        }
                    }
                }
                ImGui::EndChild(); // Fin de columna del árbol

                // ---------------------------------------------------------------
                // COLUMNA DERECHA: Hex Dump (los bytes crudos del paquete)
                // Muestra los datos en dos formatos: hexadecimal y ASCII
                // ---------------------------------------------------------------
                ImGui::TableNextColumn(); // Pasa el cursor a la columna dos
                if (ImGui::BeginChild("Hex", ImVec2(0,0), false, ImGuiWindowFlags_AlwaysHorizontalScrollbar)) {
                    
                    // Recorre el paquete de 16 bytes en 16 bytes (cada línea muestra 16 bytes)
                    for (size_t i = 0; i < capSize; i += 16) { 
                        
                        ImGui::Text("%04zx  ", i); // Muestra la posición actual en hexadecimal (offset): 0000, 0010, 0020...
                        ImGui::SameLine();
                        
                        // Sub-bucle A: Muestra los 16 bytes en formato hexadecimal (00 a FF)
                        for (size_t j = 0; j < 16; j++) { 
                            if (i + j < capSize) ImGui::Text("%02x ", raw[i+j]); // Byte en hex con formato de 2 dígitos
                            else ImGui::Text("   "); // Si el paquete se acabó a la mitad del bloque, imprime espacios vacíos para sostener la estética
                            ImGui::SameLine();
                        }
                        
                        ImGui::Text("  "); ImGui::SameLine(); // Espacio visual entre la columna hex y la columna ASCII
                        
                        // Sub-bucle B: Muestra los mismos bytes como caracteres ASCII 
                        for (size_t j = 0; j < 16 && (i + j) < capSize; j++) { 
                            char c = raw[i+j]; // Copia el byte crudo
                            if (c >= 32 && c <= 126) ImGui::Text("%c", c);  // Imprime únicamente si es una letra humana válida
                            else ImGui::Text(".");                          // Si es un carácter de control o especial, muestra un punto
                            ImGui::SameLine(0, 0);                          // Fuerza espaciado nulo entre letras
                        }
                        ImGui::NewLine(); // Termina la línea actual y pasa a la siguiente
                    }
                }
                ImGui::EndChild(); // Fin de columna hexadecimal
                ImGui::EndTable(); // Fin tabla
            }
            ImGui::PopStyleColor(3);
        }
    }

    // ============================================================================
    // FUNCION DE RENDERIZADO PRINCIPAL
    // ============================================================================

    void RenderMainUI() {
        ImGui::SetNextWindowPos(ImVec2(0, 0));                        // Establecemos posicion de la ventana
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);         // Establecemos el tamaño
        //Color de fondo de la barra
        ImGui::PushStyleColor(ImGuiCol_MenuBarBg, ImGui::ColorConvertU32ToFloat4(Colores::TOOLBAR));
        ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::ColorConvertU32ToFloat4(Colores::VENTANA));  //Color ventana


        ImGui::Begin("MainWindow", NULL, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove|ImGuiWindowFlags_MenuBar); // Creamos la ventana

        // Si el usuario todavía no eligió una tarjeta de red, muestra el menú de selección
        if (isShowingCaptureScreen == false) { 
            RenderInterfaceSelectionScreen(); 
        } 
        else {
            // Si ya está capturando, muestra la interfaz de captura
            ImGui::Text("Interfaz actual: %s", currentInterfaceName.c_str()); 
            ImGui::Spacing();
            RenderToolbarTop();         //Barra de funciones
            RenderTagManagment();        //ventana de etiquetas
            RenderCaptureToolbar(); // Barra de operaciones

            //Si los filtros estan activos
            if (tipoFiltroActivo > 0) {

                ImGui::Separator();
                ImGui::Spacing();

                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(0xFF65784D), "Filtro Activo:");

                //Estilo de las areas de texto
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(0xFF77723E));
                ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImGui::ColorConvertU32ToFloat4(0xFF756E26));
                ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImGui::ColorConvertU32ToFloat4(0xFFF0EAE6));
                ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(0xFFFFEBF7));
                ImGui::PushStyleColor(ImGuiCol_TextDisabled, ImGui::ColorConvertU32ToFloat4(0xFFDBD7B2));
                ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(0xFF303030));
                ImGui::PushStyleColor(ImGuiCol_NavHighlight, ImGui::ColorConvertU32ToFloat4(0xFF00FF00));
                ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);

                //Para ahorrar la configuración de cada caja de texto
                auto RenderInputFiltro = [&](const char* id, const char* placeholder, char* buffer, size_t size) {
                    ImGui::SetNextItemWidth(250.0f); //límite de ancho
                    ImGui::InputTextWithHint(id, placeholder, buffer, size);
                };

                if (tipoFiltroActivo == 5) {
                    //posiblemente 4 filtros

                    ImGui::SameLine();

                    ImGui::BeginGroup();
                    RenderInputFiltro("##filtro_ip", "Buscar IP (Parcial)...", filtroIP, sizeof(filtroIP));
                    ImGui::SameLine();
                    //Por como funcionan los colores, estos se agregan solo en el momento de la checkBox, para así no afectar a los de las cajas de texto
                    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(0xFFF0EAE6));
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(0xFF000000));
                    ImGui::Checkbox("Exacta##glob", &ipExactaGlobal);
                    ImGui::PopStyleColor(2);
                    ImGui::EndGroup();

                    ImGui::SameLine();
                    ImGui::BeginGroup();
                    RenderInputFiltro("##filtro_origen", "IP Origen Exacta...", filtroIPOrigen, sizeof(filtroIPOrigen));
                    ImGui::Dummy(ImVec2(0, 15)); // Espaciador para alinear horizontalmente
                    ImGui::EndGroup();

                    ImGui::SameLine();
                    ImGui::BeginGroup();
                    RenderInputFiltro("##filtro_destino", "IP Destino Exacta...", filtroIPDestino, sizeof(filtroIPDestino));
                    ImGui::Dummy(ImVec2(0, 15));
                    ImGui::EndGroup();

                    ImGui::SameLine();
                    ImGui::BeginGroup();
                    RenderInputFiltro("##filtro_protocolo", "Protocolo...", filtroProtocolo, sizeof(filtroProtocolo));
                    ImGui::Dummy(ImVec2(0, 15));
                    ImGui::EndGroup();


                }
                else {
                    std::string placeholder = "Buscar ";        //placehoilder, las letras que se ven cuando no hay texto en la caja
                    if (tipoFiltroActivo == 1) {
                        placeholder += "IP ...";
                        ImGui::SameLine();
                        RenderInputFiltro("##filtro_input", placeholder.c_str(), textoFiltro, sizeof(textoFiltro));
                        ImGui::SameLine();
                        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(0xFFF0EAE6));
                        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(0xFF000000));
                        ImGui::Checkbox("Exacta##glob", &ipExactaGlobal);       //el checkbox puedes solo verdadero o falso
                        ImGui::PopStyleColor(2);
                    }
                    else {
                        if (tipoFiltroActivo == 2) placeholder += "IP Origen...";
                        if (tipoFiltroActivo == 3) placeholder += "IP Destino...";
                        if (tipoFiltroActivo == 4) placeholder += "Protocolo...";

                        ImGui::SameLine();
                        RenderInputFiltro("##filtro_input", placeholder.c_str(), textoFiltro, sizeof(textoFiltro));
                    }
                }

                ImGui::PopStyleColor(7);
                ImGui::PopStyleVar(1);

                //boton
                ImGui::SameLine();
                ImGui::PushStyleColor(ImGuiCol_Button, ImGui::ColorConvertU32ToFloat4(0xFF0000FC));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::ColorConvertU32ToFloat4(0xFF2020BD));
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImGui::ColorConvertU32ToFloat4(0xFF0000A3));

                if (ImGui::Button("X")) {
                    tipoFiltroActivo = 0;
                    //limpiamos absolutamente todos los buffers al cerrar
                    memset(textoFiltro, 0, sizeof(textoFiltro));
                    memset(filtroIP, 0, sizeof(filtroIP));
                    memset(filtroIPOrigen, 0, sizeof(filtroIPOrigen));
                    memset(filtroIPDestino, 0, sizeof(filtroIPDestino));
                    memset(filtroProtocolo, 0, sizeof(filtroProtocolo));
                    ipExactaGlobal = false;
                }
                ImGui::PopStyleColor(3);
                ImGui::Spacing();
            }

            // SECCION CRITICA
            // El programa usa dos hilos simultáneos:
            //   - Hilo 1 (este): dibuja la interfaz gráfica
            //   - Hilo 2 (Npcap): captura paquetes y los agrega a la lista
            // El mutex actua asi: si el Hilo 2 está escribiendo datos, el Hilo 1 espera, evitando crashes
            std::lock_guard<std::mutex> lock(SnifferCore::GetPacketMutex());
            const auto& packets = SnifferCore::GetCapturedPackets(); // Obtiene la lista completa de paquetes capturados

            //Se hace la función de filtrado y se almacena en una copia, si se aplican filtros solo contendra esos elementos, si no contendra to_do
            std::vector<PacketData> paquetesFiltrados = SnifferCore::FiltrarPaquetes(packets, tipoFiltroActivo, textoFiltro, filtroIP, filtroIPOrigen, filtroIPDestino, filtroProtocolo,ipExactaGlobal);

            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(0xFFFFFFFF)); // Fuerza fondo blanco en la tabla crudo

            /* Si hay un paquete seleccionado, la tabla ocupa solo la mitad de la pantalla
            para dejar espacio al panel de detalles inferior */
            float tableHeight = 0.0f;
            if (selectedPacketIndex >= 0) tableHeight = ImGui::GetContentRegionAvail().y * 0.5f;

            //Para dibujar siempre sera la copia

            RenderPacketTable(paquetesFiltrados, tableHeight);    // Dibuja la tabla de paquetes
            RenderPacketDetails(paquetesFiltrados);               // Dibuja el panel de detalles (si hay algo seleccionado)

            ImGui::PopStyleColor(); // Restaura el color de fondo original
        }

        ImGui::End(); // Finaliza la ventana y le indica a OpenGL que dibuje to_do en pantalla
        ImGui::PopStyleColor(2);
    }
}