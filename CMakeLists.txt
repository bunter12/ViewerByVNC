cmake_minimum_required(VERSION 3.21)

project(ViewerByVNC LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Xcode: generate schemes and keep auto-regeneration enabled.
if(CMAKE_GENERATOR STREQUAL "Xcode")
    set(CMAKE_XCODE_GENERATE_SCHEME ON)
    set(CMAKE_SUPPRESS_REGENERATION OFF)
endif()

find_package(Threads REQUIRED)

# Core library: everything from src except src/app.
file(GLOB_RECURSE VBV_CORE_SOURCES CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/src/*.cpp"
)
list(FILTER VBV_CORE_SOURCES EXCLUDE REGEX "/src/app/")

file(GLOB_RECURSE VBV_CORE_HEADERS CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/include/*.h"
    "${PROJECT_SOURCE_DIR}/include/*.hpp"
    "${PROJECT_SOURCE_DIR}/src/*.h"
    "${PROJECT_SOURCE_DIR}/src/*.hpp"
)
list(FILTER VBV_CORE_HEADERS EXCLUDE REGEX "/src/app/")

if(VBV_CORE_SOURCES)
    add_library(vnc_core STATIC ${VBV_CORE_SOURCES} ${VBV_CORE_HEADERS})
    target_include_directories(vnc_core PUBLIC "${PROJECT_SOURCE_DIR}/include")
    target_link_libraries(vnc_core PUBLIC Threads::Threads)
    source_group(TREE "${PROJECT_SOURCE_DIR}" FILES ${VBV_CORE_SOURCES} ${VBV_CORE_HEADERS})
endif()

# Qt viewer app (optional, when src/app/main.cpp appears).
if(EXISTS "${PROJECT_SOURCE_DIR}/src/app/main.cpp")
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTOUIC ON)
    set(CMAKE_AUTORCC ON)

    find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

    file(GLOB_RECURSE VBV_APP_SOURCES CONFIGURE_DEPENDS
        "${PROJECT_SOURCE_DIR}/src/app/*.cpp"
        "${PROJECT_SOURCE_DIR}/src/app/*.h"
        "${PROJECT_SOURCE_DIR}/src/app/*.hpp"
        "${PROJECT_SOURCE_DIR}/src/app/*.ui"
        "${PROJECT_SOURCE_DIR}/src/app/*.qrc"
    )

    qt_add_executable(viewerbyvnc
        MANUAL_FINALIZATION
        ${VBV_APP_SOURCES}
    )

    if(TARGET vnc_core)
        target_link_libraries(viewerbyvnc PRIVATE vnc_core)
    endif()

    target_link_libraries(viewerbyvnc PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets)
    source_group(TREE "${PROJECT_SOURCE_DIR}" FILES ${VBV_APP_SOURCES})

    if(APPLE AND CMAKE_GENERATOR STREQUAL "Xcode")
        set_target_properties(viewerbyvnc PROPERTIES
            MACOSX_BUNDLE TRUE
            XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "NO"
            XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "NO"
            XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ""
        )
    endif()

    qt_finalize_executable(viewerbyvnc)
endif()
