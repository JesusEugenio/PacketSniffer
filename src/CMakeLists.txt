# Crear el archivo ejecutable final .exe uniendo los archivos .cpp
add_executable(PacketSniffer
        main.cpp
        core/SnifferCore.cpp
        parser/PacketParser.cpp
        ui/UIManager.cpp
)

# Definimos las rutas exactas de tus librerías externas
set(NPCAP_SDK "C:/npcap-sdk")
set(MSYS2_DIR "C:/msys64/mingw64")

# Le indicamos al compilador dónde buscar los archivos .h
target_include_directories(PacketSniffer PRIVATE
        core
        parser
        ui
        "${NPCAP_SDK}/Include"
        "${MSYS2_DIR}/include"
        thirdParty/imgui
)

# Le indicamos al compilador dónde buscar los binarios precompilados (.lib o .a)
target_link_directories(PacketSniffer PRIVATE
        "${NPCAP_SDK}/Lib/x64"
        "${MSYS2_DIR}/lib"
)

# Vincular las librerías necesarias
target_link_libraries(PacketSniffer PRIVATE 
    imgui 
    ws2_32 
    wpcap 
    Packet 
    glfw3 
    opengl32
    iphlpapi
    winmm
    comdlg32
    xlsxwriter
    z
)

# Le decimos a CMake que copie la carpeta de fuentes justo al lado del .exe
file(COPY "${CMAKE_SOURCE_DIR}/assets" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")