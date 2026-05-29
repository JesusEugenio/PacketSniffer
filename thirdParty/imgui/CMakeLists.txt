# Crear una libreria estatica solo con los archivos de ImGui
# Esto evita que ImGui se compile junto con tu codigo cada vez, ahorrando tiempo
add_library(imgui STATIC
    imgui.cpp
    imgui_demo.cpp
    imgui_draw.cpp
    imgui_tables.cpp
    imgui_widgets.cpp
    imgui_impl_glfw.cpp
    imgui_impl_opengl3.cpp
)

# Indicar donde estan los encabezados para que otras carpetas los encuentren
target_include_directories(imgui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})