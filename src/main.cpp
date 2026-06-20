// ============================================================================
// Packet Sniffer - Proyecto Redes de Computadoras I
// ---------------------------------------------------------------------------
//  Integrantes:
//
//
//
//
// ============================================================================


// -- main.cpp ---
// Es el corazón y punto de arranque del software. Se encarga de prender la 
// interfaz gráfica y mantiene vivo el programa en un ciclo infinito (dibujando 
// la pantalla 60 veces por segundo) hasta que se cierre.

#include "ui/UIManager.h"       // Funciones de la Interfaz Grafica
#include "core/SnifferCore.h"   // Funciones del Sniffer (capturar y gestionar los paquetes de red)

#include "imgui.h"              
#include "imgui_impl_glfw.h"    // Librerías de render final y sincronización
#include "imgui_impl_opengl3.h" // Librerías para enviar información en tiempo real a la gráfica

int main() {
    
    // Consulta y carga las tarjetas de red del equipo
    SnifferCore::LoadLocalInterfaces();
    
    // Crea la ventana del programa y enciende el sistema gráfico completo
    GLFWwindow* window = UIManager::InitializeWindow();
    
    if (window == nullptr) { // Si la ventana no se creo, sale del programa
        return 1;
    }

    // -- Main Loop --
    // Se repite decenas de veces por segundo mientras la ventana esté abierta
    // Cada vuelta del bucle dibuja un nuevo fotograma en pantalla
    // El bucle termina cuando el usuario cierra la ventana 
    while (glfwWindowShouldClose(window) == false) { 
        
        glfwPollEvents(); // Verifica los clicks y botones apretados para reportar a ImGui
        
        // Señala el fin del fotograma anterior y el comienzo de uno nuevo
        ImGui_ImplGlfw_NewFrame();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui::NewFrame();

        // Renderizamos la Interfaz Grafica

        UIManager::RenderMainUI();
        ImGui::Render();
        
        // Cuando se quiere ajustar al tamaño real de la ventana
        int width, height; 
        glfwGetFramebufferSize(window, &width, &height); // Detecta de la máquina el tamaño real alterado
        glViewport(0, 0, width, height); // Aplica escalabilidad del contenido interno hacia esa medida
        
        // Borra todos los píxeles del fotograma anterior poniéndolos en negro
        // (necesario para que los elementos que ya no están no queden "fantasmas")
        glClear(GL_COLOR_BUFFER_BIT);         

        // Enviar el fotograma a la pantalla 
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        
        // Indica que la GPU ya dibujo la interfaz y ahora debe enseñarla al usuario
        glfwSwapBuffers(window); 
    }

    SnifferCore::StopCapture(); // Detiene el hilo de captura de red de forma ordenada
    
    UIManager::ShutdownWindow(window); // Destruye y desocupa la memoria gráfica

    return 0; 
}