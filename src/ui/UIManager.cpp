// ============================================================================
// UIManager.cpp
// Se encarga de dibujar todo lo que se ve en la pantalla:
// la tabla de paquetes, los botones, los colores y los menús desplegables 
// ============================================================================

#define STB_IMAGE_IMPLEMENTATION
#include <winsock2.h>
#include <windows.h>
#include <commdlg.h>                    // Para el diálogo de guardar archivos
#include "stb_image.h"
#include <GL/gl.h>                      // Headers de OpenGL/GLFW (<GLFW/glfw3.h>)
#include "UIManager.h"
#include "imgui.h"                      // Librería para crear la interfaz gráfica (ventanas, botones, etc)
#include "imgui_impl_glfw.h"            // Conecta el mouse y teclado con la interfaz gráfica
#include "imgui_impl_opengl3.h"         // Conecta la interfaz gráfica con la tarjeta de video
#include "../core/SnifferCore.h"        // Acceso al motor que captura paquetes de red
#include "../parser/PacketParser.h"     // Herramientas para leer y analizar paquetes de red
#include "Colores.h"                    // Gama de colores
#include <string>

std::vector<GLuint> splashFrames;
const int TOTAL_FRAMES = 2;

// Para la opción de ayuda
struct TextureInfo {
    GLuint id;
    int width;
    int height;
};

struct Slide {
    TextureInfo tex; // Aquí guardas el ID, width y height
    std::string descripcion;
};

std::vector<Slide> ayudaSlides; // Sera un carrusel de imagenes
int slideActual = 0;

namespace UIManager {
    // Variables Globales de Estado
    bool isShowingCaptureScreen = false;     // Está mostrando la tabla de paquetes o el menú inicial?
    std::string currentInterfaceName = "";   // Nombre del dispositivo de red seleccionado
    int selectedPacketIndex = -1;            // Registra qué fila de la tabla le dio clic el usuario (-1 es ninguna)

    static bool requestExportCSV = false;
    static bool requestExportXLSX = false;
    static bool mostrarPuertos = false;     // Controla si se dibujan las columnas de puertos

    // Fuente tipografica
    ImFont* fontBold = nullptr;
    ImFont* fontMedium = nullptr;

    // Filtros
    static int tipoFiltroActivo = 0;        // Tipo de filtro activo
    static char filtroIP[64] = "";
    static char filtroIPOrigen[64] = "";
    static char filtroIPDestino[64] = "";
    static char filtroProtocolo[64] = "";
    static char textoFiltro[64] = "";       // Buffer para el filtro
    static char filtroPuertoOrigen[16] = "";
    static char filtroPuertoDestino[16] = "";
    static bool ipExactaGlobal=false;
    static bool etiquetaSearch=false;
    static bool etiquetaSearchSrc=false;
    static bool etiquetaSearchDest=false;
    static bool etiquetaSearchAnd=false;

    // Filtro / Busqueda
    static char filtroID[16] = "";
    static bool buscar=false;
    static bool requestScrollToSelection = false;

    // Etiquetas
    static bool viewWindowTag = false;
    static bool editTag=false;

    // Para el reinicio de la captura
    static std::string currentInterfaceInternalName = "";

    // Para ayuda
    static bool isAyudaActive = false;


    // Funcion para traducir los nombres de los Protocolos
    std::string GetFullProtocolName(const std::string& shortName) {
        if (shortName == "TLS/SSL" || shortName == "HTTPS") return "Transport Layer Security";
        if (shortName == "HTTP") return "Hypertext Transfer Protocol"; 
        if (shortName == "DNS") return "Domain Name System";
        if (shortName == "SSH/SFTP") return "Secure Shell Protocol";
        if (shortName == "FTP (Data)" || shortName == "FTP (Control)") return "File Transfer Protocol";
        if (shortName == "DHCP (Server)" || shortName == "DHCP (Client)") return "Dynamic Host Configuration Protocol";
        if (shortName == "BGP") return "Border Gateway Protocol";
        return shortName + " Application Data"; // Etiqueta genérica si el protocolo no es reconocido por el programa
    }
    
    // Ayuda
    TextureInfo LoadTextureFromFile(const char* filename) {
        int w, h, channels;
        // Carga la imagen
        unsigned char* data = stbi_load(filename, &w, &h, &channels, 4);

        // Si falla, devuelve ceros
        if (data == nullptr) return {0, 0, 0};

        GLuint textureID;
        glGenTextures(1, &textureID);
        glBindTexture(GL_TEXTURE_2D, textureID);

        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR); // Usar LINEAR para mejor calidad al escalar
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, data);
        stbi_image_free(data);

        return {textureID, w, h};
    }

    void LoadAyudaResources() {//Se carga imagen con su descripción
        const char* textos[] = {
                "Indicador en pantalla de la interfaz actual.",
                "Estado de la captura de paquetes (Capturando/Detenido).",
                "Botón para detener la captura de paquetes.",
                "Una vez detenida la captura, el botón permite regresar a la selección de interfaces.",
                "Tabla de paquetes capturados.",
                "Leyenda de colores para los paquetes.",
                "Información detallada del paquete seleccionado.",
                "Opción en la barra de herramientas para detener la captura.",
                "Opción en la barra de herramientas para reiniciar la captura.",
                "Opción en la barra de herramientas para regresar a la selección de interfaces.",
                "Filtros disponibles en la barra de herramientas.",
                "Algunos filtros permiten buscar coincidencias exactas o parciales; esto se activa o desactiva mediante su respectiva casilla de verificación.",
                "Los filtros de IP pueden buscar coincidencias según la dirección IP o la etiqueta; esto se activa o desactiva con su respectiva casilla de verificación.",
                "En el filtro combinado esta la opción de realizar filtrado con AND (marcar casilla de modo estricto) o con OR (casilla modo estricto desmarcada)"
                "Los filtros pueden eliminarse mediante la barra de herramientas o el botón ubicado a un costado.",
                "El apartado vista nos proporciona la opción para activar o desactivar la visualización de puertos en la tabla de paquetes.",
                "El apartado de búsqueda permite localizar un paquete específico mediante su ID.",
                "La búsqueda puede cancelarse desde la barra de herramientas o con el botón ubicado a un costado.",
                "El apartado de etiquetas permite gestionarlas (se guardan automáticamente, por lo que el sniffer las recordará a menos que se eliminen manualmente).",
                "En el apartado de etiquetas se habilita una ventana para asignar una etiqueta a una dirección IP.",
                "Permite asignar un color mediante el selector de color.",
                "Al pulsar el botón de editar en una etiqueta, la IP se colocará automáticamente en el campo de texto.",
                "Para eliminar una etiqueta, basta con presionar su respectivo botón de eliminar.",
                "Al exportar a .csv, se abrirá el explorador de archivos para guardar el archivo (se guardarán los datos que se muestren en la tabla).",
                "Al exportar a .xlsx, se abrirá el explorador de archivos para guardar el archivo (se guardarán los datos que se muestren en la tabla)."
        };

        for (int i = 1; i <= 25; i++) {
            std::string path = "assets/ayuda/ayuda" + std::to_string(i) + ".png";

            TextureInfo info = LoadTextureFromFile(path.c_str());
            if (info.id != 0) {
                ayudaSlides.push_back({info, textos[i-1]});
            } else {
                printf("Error fatal: No se cargo %s\n", path.c_str());
            }
        }
    }
    //Función para escalar las imagenes
    ImVec2 GetProportionalSize(float originalW, float originalH, float maxWidth, float maxHeight) {
        float aspectRatio = originalW / originalH;
        float newW = maxWidth;
        float newH = maxWidth / aspectRatio;

        //si la altura calculada excede el máximo permitido se ajustamos por la altura
        if (newH > maxHeight) {
            newH = maxHeight;
            newW = maxHeight * aspectRatio;
        }
        return ImVec2(newW, newH);
    }

    void RenderVentanaAyuda() {
        if (!isAyudaActive) return;

        ImGui::SetNextWindowSize(ImVec2(700, 500), ImGuiCond_Always);
        ImGui::PushStyleColor(ImGuiCol_TitleBgActive, ImGui::ColorConvertU32ToFloat4(Colores::AZULGRISACEO));

        if (ImGui::Begin("Ayuda del Sistema", &isAyudaActive, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse)) {
            //Si el usuario cliquea fuera de la ventana entonces la desactiva
            if (ImGui::IsMouseClicked(0) && !ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) {
                isAyudaActive = false; // Cerramos la ventana automáticamente
            }

            if (!ayudaSlides.empty()) {
                Slide& actual = ayudaSlides[slideActual];

                //Mostrar el texto
                ImGui::TextWrapped("%s", actual.descripcion.c_str());
                ImGui::Separator();
                ImGui::Spacing();

                //calcular espacio disponible para la imagen
                ImVec2 availableSpace = ImGui::GetContentRegionAvail();
                //Restamos espacio del texto de arriba, botones y márgenes
                float maxH = availableSpace.y - 50.0f;
                float maxW = availableSpace.x;

                ImVec2 size = GetProportionalSize(actual.tex.width, actual.tex.height, maxW, maxH);

                if (size.x > 0 && size.y > 0 && actual.tex.id != 0) {
                    float windowWidth = ImGui::GetWindowContentRegionMax().x - ImGui::GetWindowContentRegionMin().x;
                    ImGui::SetCursorPosX((windowWidth - size.x) * 0.5f);
                    ImGui::Image((void*)(intptr_t)actual.tex.id, size);
                } else {
                    ImGui::Text("Error: Textura invalida o tamaño cero.");
                }
                float footerHeight = 50.0f;
                float windowHeight = ImGui::GetWindowSize().y;
                ImGui::SetCursorPosY(windowHeight - footerHeight);

                ImGui::Separator(); // Línea divisoria justo antes de los botones
                ImGui::Spacing();

                //Botones navegación
                if (ImGui::Button("Anterior") && slideActual > 0) slideActual--;
                ImGui::SameLine();

                //contador de paginas
                float windowWidth = ImGui::GetWindowSize().x;
                float textWidth = ImGui::CalcTextSize("99 / 99").x;
                ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
                ImGui::Text("%d / %d", slideActual + 1, (int)ayudaSlides.size());

                ImGui::SameLine(windowWidth - 90.0f); // Pegado a la derecha
                if (ImGui::Button("Siguiente") ) {
                    if (slideActual < ayudaSlides.size() - 1) {
                        slideActual++; // Avanza normal
                    } else {
                        slideActual = 0; //cicla al inicio
                    }
                }
            }
        }
        ImGui::End();
        ImGui::PopStyleColor();
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
        ImGuiStyle& style = ImGui::GetStyle();

        //redondeado de bordes, estética
        style.FrameRounding = 4.0f;
        style.WindowRounding = 6.0f;
        style.ChildRounding = 4.0f;

        ImVec4 colorFondoBase = ImGui::ColorConvertU32ToFloat4(Colores::CREMAPASTEL);
        ImVec4 colorTextoBase = ImGui::ColorConvertU32ToFloat4(Colores::NEGRO);

        style.Colors[ImGuiCol_WindowBg]         = colorFondoBase;
        style.Colors[ImGuiCol_Text]             = colorTextoBase;

        //configuración global de botones
        style.Colors[ImGuiCol_Button]           = ImGui::ColorConvertU32ToFloat4(Colores::BOTONESGENERAL);
        style.Colors[ImGuiCol_ButtonHovered]    = ImGui::ColorConvertU32ToFloat4(Colores::BOTONESGENERALHOVER);
        style.Colors[ImGuiCol_ButtonActive]     = ImGui::ColorConvertU32ToFloat4(Colores::BOTONESGENERALPRESS);

        //cabeceras y elementos seleccionables por defecto
        style.Colors[ImGuiCol_Header]           = ImGui::ColorConvertU32ToFloat4(Colores::MORADOVIEJO);
        style.Colors[ImGuiCol_HeaderHovered]    = ImGui::ColorConvertU32ToFloat4(Colores::VERDEMENTAGRISACEO);
        style.Colors[ImGuiCol_HeaderActive]     = ImGui::ColorConvertU32ToFloat4(Colores::GRISVERDIOSOCLARO);

        //Input
        style.Colors[ImGuiCol_FrameBg]        = ImGui::ColorConvertU32ToFloat4(Colores::INPUT);
        style.Colors[ImGuiCol_FrameBgHovered] = ImGui::ColorConvertU32ToFloat4(Colores::INPUT);
        style.Colors[ImGuiCol_FrameBgActive]  = ImGui::ColorConvertU32ToFloat4(Colores::INPUT);

        style.Colors[ImGuiCol_TextSelectedBg] = ImGui::ColorConvertU32ToFloat4(Colores::ROSAVIEJO);

        style.Colors[ImGuiCol_TextDisabled]   = ImGui::ColorConvertU32ToFloat4(Colores::ROSAVIEJOOSCURO);
    }

    // ============================================================================
    // INICIALIZAR Y CERRAR LA VENTANA DEL PROGRAMA
    // ============================================================================

    GLFWwindow* InitializeWindow() {
        if (!glfwInit()) return nullptr; // Aborta y retorna null si el SO rechaza la creación gráfica

        // Crea la ventana del programa
        GLFWwindow* window = glfwCreateWindow(600, 500, "PacketSniffer", NULL, NULL);

        GLFWimage icon[1];
        // stbi_load lee el archivo físico. El '4' al final obliga a que tenga el canal Alfa (transparencia RGBA)
        icon[0].pixels = stbi_load("assets/imagenes/icon.png", &icon[0].width, &icon[0].height, 0, 4);
        if(icon[0].pixels != nullptr){
            glfwSetWindowIcon(window, 1, icon); // Le inyecta la imagen a la ventana
            stbi_image_free(icon[0].pixels); //Libera la RAM temporal que usamos para leer el archivo
        }
        else{
            printf("No pudo cargarse elicono");
        }

        glfwMakeContextCurrent(window); // Le dice a la tarjeta de video que dibuje to_do esta ventana
        glfwSwapInterval(1);            // Enciende la Sincronización Vertical (V-Sync) para empatar los frames con los Hz del monitor
        
        IMGUI_CHECKVERSION();       // Macro de seguridad que verifica que la versión de ImGui instalada coincide con la que se usó al compilar
        ImGui::CreateContext();     // Reserva la memoria que ImGui necesita para funcionar
        
        // Cargamos la fuente del programa (Regular, Medium & Bold)
        ImFont* font = ImGui::GetIO().Fonts->AddFontFromFileTTF("assets/fonts/segoeui.ttf", 18.0f); 
        fontMedium = ImGui::GetIO().Fonts->AddFontFromFileTTF("assets/fonts/seguisb.ttf", 18.0f);
        fontBold = ImGui::GetIO().Fonts->AddFontFromFileTTF("assets/fonts/segoeuib.ttf", 18.0f);
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
        ImGui::Spacing();

        // Encabezado de bienvenida
        if (fontBold) ImGui::PushFont(fontBold); // Activa la fuente bold
        ImGui::SetWindowFontScale(2.5f); // Hace la fuente al doble de tamaño
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(Colores::AZULMARINOOSCURO), "Bienvenido a Packet Sniffer");
        ImGui::SetWindowFontScale(1.0f); // Restaura el tamaño normal para lo que sigue
        if (fontBold) ImGui::PopFont();

        ImGui::Spacing();
        ImGui::Spacing();

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(Colores::AZULMARINOOSCURO), "Selecciona una interfaz haciendo doble clic para comenzar a capturar trafico");
        ImGui::Separator();  // Dibuja una línea horizontal separadora
        ImGui::Spacing();    // Añade un espacio vertical
        
        // Dibujamos un boton decorativo que sirve como encabezado para la interfaz
        ImGui::PushStyleColor(ImGuiCol_Button, ImGui::ColorConvertU32ToFloat4(Colores::MORADOGRISACEO));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::ColorConvertU32ToFloat4(Colores::MORADOGRISACEO));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Colores::NEGRO));   // Color del texto sobre el boton
        ImGui::PushStyleVar(ImGuiStyleVar_ButtonTextAlign, ImVec2(0.01f, 0.42f)); // Alineado a la izquierda
        ImGui::SetWindowFontScale(1.3f);
        ImGui::Button("Tarjetas de red locales", ImVec2(-FLT_MIN, 35));  // Boton que ocupa todo el ancho disponible

        // Limpiamos las modificaciones para no afectar a los siguientes elementos
        ImGui::SetWindowFontScale(1.0f); 
        ImGui::PopStyleVar(); 
        ImGui::PopStyleColor(3); // Quita las 3 reglas de color que se aplicaron arriba (limpieza)

        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(Colores::CREMAPASTEL));
        // Abre una lista desplazable que ocupa to_do el espacio restante de la ventana
        if (ImGui::BeginListBox("##NetworkCards", ImVec2(-FLT_MIN, -FLT_MIN))) { 
            // Pide el vector de tarjetas al Core y lo itera uno por uno
            ImGui::Indent(10.0f);
            for (auto& iface : SnifferCore::GetInterfaces()) {
                // Crea un elemento de lista interactivo con el nombre de la tarjeta
                if (ImGui::Selectable(iface.description.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick)) { 
                    if (ImGui::IsMouseDoubleClicked(0)) { // Si el usuario hace doble clic izquierdo...
                        currentInterfaceName = iface.description;   // Guarda el nombre de la tarjeta elegida
                        currentInterfaceInternalName = iface.name;
                        isShowingCaptureScreen = true;              // Cambia a la pantalla de captura
                        SnifferCore::StartCapture(iface.name);      // Ordena al motor que empiece a capturar paquetes
                    }
                }
            }
            ImGui::EndListBox(); // Cierra la lista
        }
        ImGui::PopStyleColor();
    }

    // Barra Superior ubicada antes de la tabla de captura de paquetes
    void RenderCaptureToolbar() {
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

    }

    //función auxiliar de busqueda
    void CancelarBusqueda() {
        int idEnCaja = std::atoi(filtroID);

        // Si el seleccionado coincide con lo que había en la caja, deseleccionamos
        if (selectedPacketIndex == idEnCaja && selectedPacketIndex != -1) {
            selectedPacketIndex = -1;
        }

        // Limpiamos estado
        memset(filtroID, 0, sizeof(filtroID));
        buscar = false;
    }

    //Menu superior (algunas funciones son redundantes)
    void RenderToolbarTop() {
        //Fondo de lo desplegable
        ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(Colores::TOOLBAR));
        //pa seleccion en barra
        ImGui::PushStyleColor(ImGuiCol_Header, ImGui::ColorConvertU32ToFloat4(Colores::AZULGRISACEO));
        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImGui::ColorConvertU32ToFloat4(Colores::AZULGRISACEO));

        if (ImGui::BeginMenuBar()) {
            //Crear pestañas para el menu superior
            //--------- CAPTURA ------------
            if (ImGui::BeginMenu("Captura")) {
                viewWindowTag=false;
                if (ImGui::MenuItem("Detener Captura")) {
                    if (SnifferCore::IsCapturing()) {
                        SnifferCore::StopCapture();
                    }
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Reiniciar Captura")) {
                    if (!currentInterfaceInternalName.empty()) {
                        if (SnifferCore::IsCapturing()) { //Paramos si es que esta capturando
                            SnifferCore::StopCapture();
                        }
                        //Iniciar nueva captura en la misma tarjeta
                        SnifferCore::StartCapture(currentInterfaceInternalName);
                        tipoFiltroActivo = 0;
                        selectedPacketIndex = -1;
                    }
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Regresar a Interfaces")) {
                    if (SnifferCore::IsCapturing()) {
                        SnifferCore::StopCapture();         // Para la captura por seguridad (si es que habia algo activo)
                    }
                    isShowingCaptureScreen = false;     // Vuelve al menú de selección de interfaz
                    selectedPacketIndex = -1;
                    tipoFiltroActivo=0;
                }
                ImGui::EndMenu();
            }
            //--------- FILTROS ------------
            if (ImGui::BeginMenu("Filtros")) {
                viewWindowTag=false;
                //Las opciones de esa pestaña, retorna true si es que se cliquea esa opcion
                if (ImGui::MenuItem("IP"))
                {
                    etiquetaSearchSrc=false;
                    ipExactaGlobal = false;
                    tipoFiltroActivo = 1;
                    memset(textoFiltro, 0, sizeof(textoFiltro));
                }
                if (ImGui::MenuItem("IP Origen")) {
                    etiquetaSearchSrc=false;
                    tipoFiltroActivo = 2;
                    memset(textoFiltro, 0, sizeof(textoFiltro));
                }
                if (ImGui::MenuItem("IP Destino")) {
                    etiquetaSearchDest=false;
                    tipoFiltroActivo = 3;
                    memset(textoFiltro, 0, sizeof(textoFiltro));
                }
                ImGui::Separator();                     //estetica
                if (ImGui::MenuItem("Protocolo")) {
                    tipoFiltroActivo = 4;
                    memset(textoFiltro, 0, sizeof(textoFiltro));
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Puerto Origen")) {
                    tipoFiltroActivo = 6;
                    memset(textoFiltro, 0, sizeof(textoFiltro));
                }
                if (ImGui::MenuItem("Puerto Destino")) {
                    tipoFiltroActivo = 7;
                    memset(textoFiltro, 0, sizeof(textoFiltro));
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Combinado")) {
                    etiquetaSearchSrc=false;
                    etiquetaSearchDest=false;
                    etiquetaSearch=false;
                    ipExactaGlobal = false;
                    tipoFiltroActivo = 5;
                    memset(filtroProtocolo, 0, sizeof(filtroProtocolo));
                    memset(filtroIP, 0, sizeof(filtroIP));
                    memset(filtroIPOrigen, 0, sizeof(filtroIPOrigen));
                    memset(filtroIPDestino, 0, sizeof(filtroIPDestino));
                    memset(filtroPuertoOrigen, 0, sizeof(filtroPuertoOrigen));
                    memset(filtroPuertoDestino, 0, sizeof(filtroPuertoDestino));
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Eliminar Filtros")) {
                    tipoFiltroActivo = 0;
                }
                ImGui::EndMenu();       //pa cerrar el menú
            }
            //--------- VISTA ------------
            if (ImGui::BeginMenu("Vista")) {
                // Al pasarle &mostrarPuertos, ImGui crea un checkbox automáticamente
                ImGui::MenuItem("Mostrar columnas de Puertos", NULL, &mostrarPuertos);
                ImGui::EndMenu();
            }
            // -------- BUSQUEDA -------------
            if (ImGui::BeginMenu("Búsqueda")) {
                if (ImGui::MenuItem("Paquete ID")) {
                    buscar=true;
                    memset(filtroID, 0, sizeof(filtroID));
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Cancelar Busqueda")) {
                    CancelarBusqueda();
                }
                ImGui::EndMenu();
            }
            //--------- ETIQUETAS ------------
            if (ImGui::BeginMenu("Etiquetas")) {
                if (ImGui::MenuItem("Gestionar Etiquetas")) {
                    viewWindowTag=true;
                }
                ImGui::EndMenu();
            }
            //--------- EXPORTACIÓN ------------
            if (ImGui::BeginMenu("Exportación")) {
                if (ImGui::MenuItem("Exportar .csv")) {
                    requestExportCSV = true; // Activa la bandera para exportar a CSV en el siguiente ciclo de renderizado
                }
                if (ImGui::MenuItem("Exportar .xlsx")){
                    requestExportXLSX = true;
                }
                ImGui::EndMenu();
            }
            //--------- AYUDA ------------
            if (ImGui::BeginMenu("Ayuda")) {
                if (ImGui::MenuItem("Indicaciones")) {
                    isAyudaActive=true;
                }
                ImGui::EndMenu();
            }
            ImGui::EndMenuBar();
        }
        ImGui::PopStyleColor(3);
    }

    //Para la ventana de gestión de etiquetas
    void RenderTagManagment() {
        //Si no es necesario no la dibuja
        if (!viewWindowTag) return;

        static char inputIP[46] = "";
        static char inputName[32] = "";
        static ImVec4 inputColor = ImVec4(0.937f, 0.792f, 0.898f, 1.0f);

        ImGui::PushStyleColor(ImGuiCol_TitleBgActive, ImGui::ColorConvertU32ToFloat4(Colores::AZULGRISACEO)); // Activa
        ImGui::PushStyleColor(ImGuiCol_TitleBg, ImGui::ColorConvertU32ToFloat4(Colores::AZULGRISACEO));       // Inactiva
        
        // Creamos una ventana normal e independiente que flotará sobre el sniffer
        ImGui::Begin("Gestión de Etiquetas", &viewWindowTag, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoCollapse);

        //Si el usuario cliquea fuera de la ventana entonces la desactiva
        if (ImGui::IsMouseClicked(0) && !ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) {
            viewWindowTag = false; // Cerramos la ventana automáticamente
        }
        ImGui::Text("Añadir / Modificar Etiqueta:");

        ImGui::InputTextWithHint("Dirección IP", "Ej: 192.168.1.1", inputIP, IM_ARRAYSIZE(inputIP));
        if (ImGui::IsItemActivated() && editTag) {
            editTag = false;
            inputColor= ImGui::ColorConvertU32ToFloat4(Colores::DEFAULTETIQUETA);
        }

        ImGui::InputTextWithHint("Nombre Etiqueta", "Ej: Servidor", inputName, IM_ARRAYSIZE(inputName));

        // Variable estática para recordar el color antes de abrir la paleta
        static ImVec4 backupColor;

        ImGui::Text("Color Visual");
        if (ImGui::ColorButton("##boton_color", inputColor, ImGuiColorEditFlags_NoAlpha)) {
            backupColor = inputColor; 
            ImGui::OpenPopup("Selector de Color"); 
        }

        // Color de fondo durante seleccion de color
        ImGui::PushStyleColor(ImGuiCol_ModalWindowDimBg, ImGui::ColorConvertU32ToFloat4(0xCC494549));  
        ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(0xFF252525));

        if (ImGui::BeginPopupModal("Selector de Color", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
            
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Colores::BLANCO));
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(0xFF151515));

            // Dibujar el selector de colores
            ImGui::BeginGroup();
            ImGui::ColorPicker4("##picker", (float*)&inputColor, ImGuiColorEditFlags_NoAlpha | ImGuiColorEditFlags_NoSidePreview | ImGuiColorEditFlags_NoSmallPreview);
            ImGui::EndGroup();

            ImGui::SameLine(); 

            ImGui::BeginGroup();            
            ImGui::Text("Nuevo");
            ImGui::ColorButton("##nuevo", inputColor, ImGuiColorEditFlags_NoAlpha, ImVec2(65, 65));
            
            ImGui::Spacing();
            ImGui::Spacing();
            
            ImGui::Text("Original");
            if (ImGui::ColorButton("##original", backupColor, ImGuiColorEditFlags_NoAlpha, ImVec2(65, 65))) {
                inputColor = backupColor;
            }
            
            ImGui::EndGroup();

            ImGui::PopStyleColor(2); // Limpiamos el texto blanco y las cajitas oscuras

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            // Botones inferiores
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Colores::NEGRO));

            float mitadAncho = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x) / 2.0f;

            if (ImGui::Button("Aceptar", ImVec2(mitadAncho, 30.0f))) { 
                ImGui::CloseCurrentPopup(); 
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancelar", ImVec2(mitadAncho, 30.0f))) { 
                inputColor = backupColor; 
                ImGui::CloseCurrentPopup(); 
            }

            ImGui::PopStyleColor(); // Limpiamos el texto negro de los botones
            ImGui::EndPopup();
        }
        ImGui::PopStyleColor(2); // Limpiamos el fondo del popup y la cortina oscurecida
        
        const char* btnText = editTag ? "Actualizar" : "Guardar";

        if (ImGui::Button(btnText, ImVec2(120, 0))) {
            ImU32 colorU32 = ImGui::ColorConvertFloat4ToU32(inputColor);
            SnifferCore::AddTag(inputIP, inputName, colorU32);
            memset(inputIP, 0, sizeof(inputIP));
            memset(inputName, 0, sizeof(inputName));
            editTag=false;
        }

        ImGui::Separator();
        ImGui::Text("Etiquetas Existentes:");

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

        // Crea una región desplazable e independiente del resto de la ventana
        if (ImGui::BeginChild("Tabla", ImVec2(0, tableHeight), true)) {
            // Calculamos las columnas dinamicamente
            int numeroColumnas = mostrarPuertos ? 9 : 7;

            // Crea una tabla de 7 columnas con bordes y  filas alternadas 
            if (ImGui::BeginTable("paquetes", numeroColumnas, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                
                // Definimos el ancho fijo de cada columna en píxeles
                ImGui::TableSetupColumn("No.", ImGuiTableColumnFlags_WidthFixed, 65.0f);
                ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 200.0f);
                ImGui::TableSetupColumn("Destination", ImGuiTableColumnFlags_WidthFixed, 200.0f);
                ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 60.0f);
                if (mostrarPuertos) {
                    ImGui::TableSetupColumn("Src Port", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                    ImGui::TableSetupColumn("Dst Port", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                }
                ImGui::TableSetupColumn("Info", ImGuiTableColumnFlags_WidthStretch); // Esta columna se expande para llenar el espacio restante
                ImGui::TableHeadersRow(); // Dibujamos la configuracion anterior

                //Buscamos el índice real del paquete en el vector, esto para mantenerlo enfocado si esta seleccionado uno
                int targetIndex = -1;
                if (selectedPacketIndex != -1) {
                    for (int i = 0; i < packets.size(); ++i) {
                        if (packets[i].id == selectedPacketIndex) {
                            targetIndex = i;
                            break;
                        }
                    }
                }

                // ImGuiListClipper es una herramienta de optimización:
                // En lugar de dibujar las 10,000 filas, solo dibuja las que el usuario puede ver en pantalla
                ImGuiListClipper clipper; 
                clipper.Begin(packets.size()); // Le dice cuántas filas hay en totals
                
                // Calcula dinámicamente qué filas están a la vista de la resolución del monitor
                while (clipper.Step()) { 
                    for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) { // Dibujaremos solo sobre ese rango
                        const auto& pkt = packets[i];   // Obtiene el paquete correspondiente a esta fila
                        ImGui::TableNextRow();          // Avanza a la siguiente fila de la tabla
                        
                        bool isSelected = (selectedPacketIndex == pkt.id); // Es esta la fila que el usuario seleccionó?
                        
                        if (isSelected) {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, Colores::VERDEMENTAGRISACEO); // Pinta el fondo
                            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Colores::NEGRO)); // Pone el texto en blanco para que se lea bien
                        }
                        
                        ImGui::TableNextColumn();
                        char label[32]; // Búfer para procesar Los ID's gráficos
                        // Genera el texto de la celda de número: el "##" es invisible, pero ImGui lo necesita para identificar el elemento internamente
                        snprintf(label, sizeof(label), "%d##%d", pkt.id, i);
                        
                        // Hace toda la fila clickeable
                        if (ImGui::Selectable(label, isSelected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                            if (selectedPacketIndex == pkt.id) {
                                //si ya estaba seleccionado, lo deseleccionamos
                                selectedPacketIndex = -1;
                            } else {
                                //si era otro o no había nada, seleccionamos este
                                selectedPacketIndex = pkt.id;
                                requestScrollToSelection = false;
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
                        if (mostrarPuertos) {
                            ImGui::TableNextColumn(); 
                            if (pkt.srcPort != -1) ImGui::Text("%d", pkt.srcPort); // Solo dibuja si es TCP/UDP
                            else ImGui::Text("-"); // Guion para paquetes ICMP/IGMP que no tienen puerto

                            ImGui::TableNextColumn(); 
                            if (pkt.dstPort != -1) ImGui::Text("%d", pkt.dstPort);
                            else ImGui::Text("-");
                        }
                        ImGui::TableNextColumn(); ImGui::Text("%s", pkt.info.c_str());

                        if (isSelected) ImGui::PopStyleColor(); // Quita el color blanco del texto (solo aplica a la fila seleccionada)
                    }
                }
                ImGui::EndTable(); // Cierra la tabla
                if (requestScrollToSelection && selectedPacketIndex != -1) {
                    // Calculamos la posición relativa del índice buscado
                    float scrollY = (float)targetIndex * ImGui::GetTextLineHeightWithSpacing();
                    ImGui::SetScrollY(scrollY - (tableHeight * 0.5f));
                    requestScrollToSelection = false;
                }
                else if (SnifferCore::IsCapturing() && packets.size() > 0 && selectedPacketIndex == -1) { // Auto-scroll: Si está capturando, si hay paquetes y si el usuario no ha seleccionado nada
                    ImGui::SetScrollHereY(1.0f); // Desplaza la barra de scroll al 100% (al final)
                }
            }
        }
        ImGui::EndChild(); // Cierra la zona desplazable
        ImGui::PopStyleColor(4);
    }

    // Interfaz - Inspeccion Profunda
    // Se divide en dos columnas:
    //   - Izquierda: árbol jerárquico de las capas del paquete
    //   - Derecha: los bytes crudos del paquete en formato hexadecimal
    void RenderPacketDetails(const PacketData* sel_pkt) {
        if (sel_pkt == nullptr) return;
        // Solo dibuja si un paquete esta seleccionado

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::ColorConvertU32ToFloat4(Colores::CREMACLARO));
        const unsigned char* raw = sel_pkt->rawBytes.data();
        size_t capSize = sel_pkt->rawBytes.size();

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
                if (ImGui::TreeNode(std::string("Frame " + std::to_string(sel_pkt->id) + ": " + std::to_string(sel_pkt->length) + " bytes on wire").c_str())) { // Abre la capa física
                    ImGui::Text("Arrival Time: %s", sel_pkt->time.c_str()); // Hora exacta en que llego el paquete
                    ImGui::Text("Frame Length: %d bytes", sel_pkt->length); // Tamaño total del paquete en bytes
                    ImGui::TreePop();
                }

                // --- CAPA 2: Ethernet (direcciones MAC de hardware) ---
                // Solo se muestra si hay direcciones MAC válidas (no aplica para túneles VPN)
                if (sel_pkt->macSource != "N/A" && capSize >= 14) {
                    if (ImGui::TreeNode(std::string("Ethernet II, Src: " + sel_pkt->macSource + ", Dst: " + sel_pkt->macDest).c_str())) { // Abre capa de enlace
                        ImGui::Text("Destination: %s", sel_pkt->macDest.c_str());    // MAC del dispositivo destino
                        ImGui::Text("Source: %s", sel_pkt->macSource.c_str());       // MAC del dispositivo origen
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
                        if (ImGui::TreeNode(std::string("Internet Protocol Version 4, Src: " + sel_pkt->source + ", Dst: " + sel_pkt->destination).c_str())) {
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
                        if (ip->protocol == 6) DrawTCP(raw, transportOffset, capSize, ipTotalLen, ipHeaderLen, sel_pkt->protocol);
                        else if (ip->protocol == 17) DrawUDP(raw, transportOffset, capSize, sel_pkt->protocol);
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

                    // Muestra la posición actual en hexadecimal (offset): 0000, 0010, 0020...
                    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(Colores::ROSAVIEJOOSCURO), "%04zx", i);
                    std::string hexStr = "";
                    std::string asciiStr = "";

                    // Ensamblamos la fila entera en dos cadenas de texto antes de dibujarla
                    for (size_t j = 0; j < 16; j++) {
                        if (i + j < capSize) {
                            char hexByte[4];
                            snprintf(hexByte, sizeof(hexByte), "%02x ", raw[i+j]); // Byte en hex con formato de 2 dígitos
                            hexStr += hexByte;

                            char c = raw[i+j]; // Copia el byte crudo
                            if (c >= 32 && c <= 126) asciiStr += c; // Imprime únicamente si es una letra humana válida
                            else asciiStr += "."; // Si es un carácter de control o especial, muestra un punto
                        } else {
                            // Relleno invisible para alinear el ASCII si la línea esta incompleta
                            hexStr += "   "; 
                        }
                        if (j == 7) {
                            hexStr += " "; 
                            asciiStr += " ";
                        }
                    }

                    // DATOS HEXADECIMALES
                    ImGui::SameLine(48.0f); 
                    ImGui::Text("%s", hexStr.c_str());

                    // TEXTO ASCII
                    ImGui::SameLine(360.0f); 
                    ImGui::Text("%s", asciiStr.c_str());
                }
            }
            ImGui::EndChild(); // Fin de columna hexadecimal
            ImGui::EndTable(); // Fin tabla
        }
        ImGui::PopStyleColor();
    }

    // ============================================================================
    // FUNCION PARA ABRIR LA VENTANA NATIVA DE GUARDADO DE ARCHIVOS DEL SISTEMA OPERATIVO
    // ============================================================================
    std::string AbriDialogoGuardaCSV(){
        OPENFILENAME ofn;
        CHAR szFile[MAX_PATH] = { 0 };

        strcpy(szFile, "captura.csv"); // Nombre de archivo por defecto

        ZeroMemory(&ofn, sizeof(OPENFILENAME));
        ofn.lStructSize = sizeof(OPENFILENAME);
        ofn.hwndOwner = NULL;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = "Archivos CSV (*.csv)\0*.csv\0Todos los archivos (*.*)\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.lpstrDefExt = "csv";
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    
        if (GetSaveFileName(&ofn)) {
            return std::string(ofn.lpstrFile);
        }

        return "";
    }

    std::string AbriDialogoGuardaXLSX(){
         OPENFILENAME ofn;
        CHAR szFile[MAX_PATH] = { 0 };

        strcpy(szFile, "captura.xlsx"); // Nombre de archivo por defecto

        ZeroMemory(&ofn, sizeof(OPENFILENAME));
        ofn.lStructSize = sizeof(OPENFILENAME);
        ofn.hwndOwner = NULL;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = "Archivos XLSX (*.xlsx)\0*.xlsx\0Todos los archivos (*.*)\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.lpstrDefExt = "xlsx";
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
        if (GetSaveFileName(&ofn)) {
            return std::string(ofn.lpstrFile);
        }

        return "";
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
            RenderVentanaAyuda();       //ventana ayuda
            RenderCaptureToolbar(); // Barra de operaciones




            //Si los filtros estan activos
            if (tipoFiltroActivo > 0) {

                ImGui::Separator();
                ImGui::Spacing();

                float espacioTexto = ImGui::CalcTextSize("Filtro Activo: ").x + ImGui::GetStyle().ItemSpacing.x;
                float posYTecho = ImGui::GetCursorPosY(); //Posicion para despues


                ImGui::Text("Filtro Activo:");


                ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Colores::NEGRO));

                //Para ahorrar la configuración de cada caja de texto
                auto RenderInputFiltro = [&](const char* id, const char* placeholder, char* buffer, size_t size) {
                    ImGui::SetNextItemWidth(250.0f); //límite de ancho
                    ImGui::InputTextWithHint(id, placeholder, buffer, size);
                };

                if (tipoFiltroActivo == 5) {
                    //IP GLOBAL
                    ImGui::SameLine();
                    ImGui::BeginGroup();
                    RenderInputFiltro("##filtro_ip", "Buscar IP (Parcial)...", filtroIP, sizeof(filtroIP));
                    ImGui::SameLine();
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Colores::NEGRO));
                    ImGui::Checkbox("Exacta##glob", &ipExactaGlobal);
                    ImGui::SameLine();
                    ImGui::Checkbox("Etiqueta##search_Global", &etiquetaSearch);
                    ImGui::PopStyleColor();
                    ImGui::EndGroup();

                    //IP ORIGEN
                    ImGui::SameLine(0.0f,25.0f);
                    ImGui::BeginGroup();
                    RenderInputFiltro("##filtro_origen", "IP Origen Exacta...", filtroIPOrigen, sizeof(filtroIPOrigen));
                    ImGui::SameLine(); // <--- Para ponerlo al lado de la caja de texto
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Colores::NEGRO));
                    ImGui::Checkbox("Etiqueta##search_origen", &etiquetaSearchSrc);
                    ImGui::PopStyleColor();
                    ImGui::EndGroup();

                    //IP DESTINO
                    ImGui::SetCursorPosX(ImGui::GetStyle().WindowPadding.x + espacioTexto);
                    ImGui::BeginGroup();
                    RenderInputFiltro("##filtro_destino", "IP Destino Exacta...", filtroIPDestino, sizeof(filtroIPDestino));
                    ImGui::SameLine(); // <--- Para ponerlo al lado
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Colores::NEGRO));
                    ImGui::Checkbox("Etiqueta##search_destino", &etiquetaSearchDest);
                    ImGui::PopStyleColor();
                    ImGui::EndGroup();

                    //PROTOCOLO
                    ImGui::SameLine(0.0f,97.0f);
                    ImGui::BeginGroup();
                    RenderInputFiltro("##filtro_protocolo", "Protocolo...", filtroProtocolo, sizeof(filtroProtocolo));
                    ImGui::EndGroup();

                    //PUERTO ORIGEN
                    ImGui::SetCursorPosX(ImGui::GetStyle().WindowPadding.x + espacioTexto);
                    ImGui::BeginGroup();
                    RenderInputFiltro("##filtro_port_orig", "Puerto Orig...", filtroPuertoOrigen, sizeof(filtroPuertoOrigen));
                    ImGui::EndGroup();

                    //PUERTO DESTINO
                    ImGui::SameLine(0.0f,183.0f);
                    ImGui::BeginGroup();
                    RenderInputFiltro("##filtro_port_dest", "Puerto Dest...", filtroPuertoDestino, sizeof(filtroPuertoDestino));
                    ImGui::EndGroup();
                }
                else {
                    std::string placeholder = "Buscar ";        //placehoilder, las letras que se ven cuando no hay texto en la caja
                    if (tipoFiltroActivo == 1) {
                        placeholder += "IP ...";
                        ImGui::SameLine();
                        RenderInputFiltro("##filtro_input", placeholder.c_str(), textoFiltro, sizeof(textoFiltro));
                        ImGui::SameLine();
                        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Colores::NEGRO));
                        ImGui::Checkbox("Exacta##glob", &ipExactaGlobal);       //el checkbox puedes solo verdadero o falso
                        ImGui::SameLine();
                        ImGui::Checkbox("Etiqueta##search", &etiquetaSearch);
                        ImGui::PopStyleColor(1);
                    }
                    else {
                        if (tipoFiltroActivo == 2) {
                            placeholder += "IP Origen...";
                            ImGui::SameLine();
                            RenderInputFiltro("##filtro_input", placeholder.c_str(), textoFiltro, sizeof(textoFiltro));
                            ImGui::SameLine();
                            ImGui::Checkbox("Etiqueta##search", &etiquetaSearchSrc);
                        }
                        if (tipoFiltroActivo == 3) {
                            placeholder += "IP Destino...";
                            ImGui::SameLine();
                            RenderInputFiltro("##filtro_input", placeholder.c_str(), textoFiltro, sizeof(textoFiltro));
                            ImGui::SameLine();
                            ImGui::Checkbox("Etiqueta##search", &etiquetaSearchDest);
                        }
                        if (tipoFiltroActivo == 4) {
                            placeholder += "Protocolo...";
                            ImGui::SameLine();
                            RenderInputFiltro("##filtro_input", placeholder.c_str(), textoFiltro, sizeof(textoFiltro));
                        }
                        if (tipoFiltroActivo == 6) {
                            std::string placeholder = "Buscar Puerto Origen...";
                            ImGui::SameLine();
                            RenderInputFiltro("##filtro_input", placeholder.c_str(), textoFiltro, sizeof(textoFiltro));
                        }
                        if (tipoFiltroActivo == 7) {
                            std::string placeholder = "Buscar Puerto Destino...";
                            ImGui::SameLine();
                            RenderInputFiltro("##filtro_input", placeholder.c_str(), textoFiltro, sizeof(textoFiltro));
                        }

                    }
                }

                ImGui::PopStyleColor();
                float posYSuelo = ImGui::GetCursorPosY();   //Para el boton de X en opcion 5

                //boton
                bool pulsarBoton = false;
                float altoDinamicoBoton = (posYSuelo - posYTecho) - ImGui::GetStyle().ItemSpacing.y;

                if (tipoFiltroActivo == 5) {
                    ImGui::SameLine(0.0f, 120.0f);
                    //El botón es más grande en la posición adecuada
                    ImGui::SetCursorPosY(posYTecho);


                    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);
                    ImGui::SetWindowFontScale(2.0f); // Texto grande

                    if (ImGui::Button("X##gigante", ImVec2(45.0f, altoDinamicoBoton-20.0f))) {
                        pulsarBoton = true;
                    }
                    ImGui::SameLine();
                    ImGui::SetWindowFontScale(1.0f);
                    ImGui::SetCursorPosY(posYTecho);
                    ImGui::Checkbox("Modo Estricto##search", &etiquetaSearchAnd);
                    ImGui::PopStyleVar();
                }
                else {
                    ImGui::SameLine();
                    //Boton clásico
                    if (ImGui::Button("X")) {
                        pulsarBoton = true;
                    }
                }
                ImGui::SetCursorPosY(posYSuelo);    //Devolver el cursor a la posición correcta

                //Acción
                if (pulsarBoton) {
                    tipoFiltroActivo = 0;
                    memset(textoFiltro, 0, sizeof(textoFiltro));
                    memset(filtroIP, 0, sizeof(filtroIP));
                    memset(filtroIPOrigen, 0, sizeof(filtroIPOrigen));
                    memset(filtroIPDestino, 0, sizeof(filtroIPDestino));
                    memset(filtroProtocolo, 0, sizeof(filtroProtocolo));
                    memset(filtroPuertoOrigen, 0, sizeof(filtroPuertoOrigen));
                    memset(filtroPuertoDestino, 0, sizeof(filtroPuertoDestino));
                }
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
            std::vector<PacketData> paquetesFiltrados = SnifferCore::FiltrarPaquetes(
                packets, 
                tipoFiltroActivo, 
                textoFiltro, 
                filtroIP, 
                filtroIPOrigen, 
                filtroIPDestino, 
                filtroProtocolo, 
                filtroPuertoOrigen,  
                filtroPuertoDestino, 
                ipExactaGlobal, 
                etiquetaSearch, 
                etiquetaSearchSrc, 
                etiquetaSearchDest,
                etiquetaSearchAnd
            );

            //Si se desea buscar
            if (buscar) {
                ImGui::Separator();
                ImGui::SetNextItemWidth(100.0f);
                ImGui::Text("Búsqueda de paquete:");
                ImGui::SameLine();

                if (ImGui::InputTextWithHint("##filtro_id", "Buscar por ID", filtroID, sizeof(filtroID))) {
                    int idBuscado = std::atoi(filtroID);
                    bool encontrado = false;
                    //buscamos el número de índice en la lista
                    for (const auto& pkt : paquetesFiltrados) {
                        if (pkt.id == idBuscado) {
                            selectedPacketIndex = pkt.id;
                            requestScrollToSelection = true;
                            encontrado = true;
                            break;
                        }
                    }
                    if (!encontrado) selectedPacketIndex = -1;
                }
                ImGui::SameLine();
                //Boton de eliminar
                if (ImGui::Button("X##cancel_busqueda")) {
                    CancelarBusqueda();
                }
            }

            if (requestExportCSV) {
               std::string ruta = AbriDialogoGuardaCSV();
               if (!ruta.empty()) {
                if (SnifferCore::ExportToCSV(ruta, paquetesFiltrados)) {
                    printf("Exportación exitosa a %s\n", ruta.c_str());
                } else {
                    printf("Error al exportar a %s\n", ruta.c_str());
                }
               }
                requestExportCSV = false; // Reseteamos la bandera para evitar exportaciones múltiples no deseadas
            }

            if (requestExportXLSX) {
               std::string ruta = AbriDialogoGuardaXLSX();
               if (!ruta.empty()) {
                if (SnifferCore::ExportToXLSX(ruta, paquetesFiltrados)) {
                    printf("Exportación exitosa a %s\n", ruta.c_str());
                } else {
                    printf("Error al exportar a %s\n", ruta.c_str());
                }
               }
                requestExportXLSX = false; // Reseteamos la bandera para evitar exportaciones múltiples no deseadas
            }

            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(0xFFFFFFFF)); // Fuerza fondo blanco en la tabla crudo

            /* Si hay un paquete seleccionado, la tabla ocupa solo la mitad de la pantalla
            para dejar espacio al panel de detalles inferior */
            float tableHeight = 0.0f;
            if (selectedPacketIndex >= 0) tableHeight = ImGui::GetContentRegionAvail().y * 0.5f;

            //Para poder ver los detalles del paquete seleccionado mediante su ID
            const PacketData* paqueteSeleccionadoPtr = nullptr;
            if (selectedPacketIndex != -1) {
                for (const auto& pkt : paquetesFiltrados) {
                    if (pkt.id == selectedPacketIndex) {
                        paqueteSeleccionadoPtr = &pkt;
                        break;
                    }
                }
            }
            //Para dibujar siempre sera la copia
            RenderPacketTable(paquetesFiltrados, tableHeight);    // Dibuja la tabla de paquetes
            RenderPacketDetails(paqueteSeleccionadoPtr);               // Dibuja el panel de detalles (si se le manda paquete)

            ImGui::PopStyleColor(); // Restaura el color de fondo original
        }

        ImGui::End(); // Finaliza la ventana y le indica a OpenGL que dibuje to_do en pantalla
        ImGui::PopStyleColor(2);
    }

    void TextCenter(const char* texto, ImU32 colorU32) {
        float anchoVentana = ImGui::GetWindowSize().x;
        float anchoTexto = ImGui::CalcTextSize(texto).x;

        //calculamos la posición exacta para que quede simétrico
        ImGui::SetCursorPosX((anchoVentana - anchoTexto) * 0.5f);

        ImVec4 colorConvertido = ImGui::ColorConvertU32ToFloat4(colorU32);

        ImGui::TextColored(colorConvertido, "%s", texto);
    }

    void RenderSplashScreen(float currentTimer, float totalDuration) {
        //centrar la ventana
        ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize, ImGuiCond_Always);
        //Diseñito
        ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::ColorConvertU32ToFloat4(Colores::CREMAPASTEL));

        ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoCollapse;

        ImGui::Begin("SplashWindow", nullptr, flags);
        float anchoVentana = ImGui::GetWindowSize().x;

        ImGui::Spacing();
        ImGui::Spacing();
        //Animación
        if (!splashFrames.empty()) {
            const float tiempoPorFrame = 0.35f;
            int frameIndex = static_cast<int>(currentTimer / tiempoPorFrame) % splashFrames.size();

            float anchoImagen = 270.0f;
            float altoImagen = 180.0f;
            // Centrado horizontal matemático exacto
            ImGui::SetCursorPosX((anchoVentana - anchoImagen) * 0.5f);
            ImGui::SetCursorPosY(35.0f); // Le damos un poquito más de aire arriba

            // Renderizamos con el alto corregido
            ImGui::Image((ImTextureID)(uintptr_t)splashFrames[frameIndex], ImVec2(anchoImagen, altoImagen));
        }

        ImGui::SetCursorPosY(230.0f);
        //Titulo
        TextCenter("=== PACKET SNIFFER ===", Colores::AZULMARINOOSCURO);
        ImGui::Spacing();

        //Mensajes de carga
        TextCenter("Inicializando hilos de escucha...", Colores::AZULMARINOOSCURO);
        TextCenter("Cargando base de datos de etiquetas...", Colores::AZULMARINOOSCURO);

        ImGui::Spacing(); ImGui::Spacing();

        //barra de progreso
        float progreso = currentTimer / totalDuration;

        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImGui::ColorConvertU32ToFloat4(Colores::MORADOVIEJO));
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(Colores::CREMACLARO));

        float anchoBarra = 480.0f;
        ImGui::SetCursorPosX((anchoVentana - anchoBarra) * 0.5f);
        ImGui::ProgressBar(progreso, ImVec2(anchoBarra, 16.0f), "");
        ImGui::PopStyleColor(2);

        //Una info
        ImGui::SetCursorPosY(ImGui::GetWindowSize().y - 45.0f);
        TextCenter("Packet Sniffer - 2026", Colores::ROSAVIEJOOSCURO);
        ImGui::End();
        ImGui::PopStyleColor();
    }

    void LoadSplashResources() {
        for (int i = 1; i <= TOTAL_FRAMES; i++) {
            std::string path = "assets/splash/frame" + std::to_string(i) + ".png";

            TextureInfo info = LoadTextureFromFile(path.c_str());

            if (info.id != 0) {
                // Solo guardamos el ID, ignorando las dimensiones
                splashFrames.push_back(info.id);
            } else {
                printf("Error: No se pudo cargar la imagen en la ruta: %s\n", path.c_str());
            }
        }
    }

    void CleanupResources() {
        // Liberar texturas de splash
        for (GLuint tex : splashFrames) {
            glDeleteTextures(1, &tex);
        }
        splashFrames.clear();

        // Liberar texturas de ayuda
        for (const auto& slide : ayudaSlides) {
            glDeleteTextures(1, &slide.tex.id);
        }
        ayudaSlides.clear();
    }
}