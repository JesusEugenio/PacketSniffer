# Nivel minimo requerido de CMake
cmake_minimum_required(VERSION 3.15)

# Nombre del proyecto
project(PacketSniffer)

# Establecer el estándar de C++ a usar (C++17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Incluir las carpetas secundarias
add_subdirectory(thirdParty/imgui)
add_subdirectory(src)