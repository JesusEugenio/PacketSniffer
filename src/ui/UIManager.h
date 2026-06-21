// ============================================================================
// UIManager.h
// Proporciona las funciones que son necesarias para controlar la ventana del 
// programa -> Encender, Dibujar y Apagar
// Funciona como un control remoto simple para la interfaz gráfica
// ============================================================================

#pragma once            // Evita que el compilador procese este archivo de cabecera más de una vez por compilación
#include <GLFW/glfw3.h> 

// Módulo encargado de gestionar todo lo que el usuario ve en pantalla
namespace UIManager {
    GLFWwindow* InitializeWindow();             // Arranca el motor gráfico OpenGL
    void RenderMainUI();                        // Función principal de renderizado
    void ShutdownWindow(GLFWwindow* window);    // Apaga y limpia la memoria de video
    void SetupColors();
    void RenderSplashScreen(float currentTimer, float totalDuration);
    void LoadSplashResources();
}