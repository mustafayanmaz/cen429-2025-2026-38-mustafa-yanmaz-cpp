# crypto/CMakeLists.txt
set(ROOT src)
set(LIBNAME petcare)

message(STATUS "[${ROOT}/${LIBNAME}] Module Processing...")

# Collect files without having to explicitly list each header and source file
file(GLOB LIB_HEADERS
  "${CMAKE_CURRENT_SOURCE_DIR}/header/*.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/header/*.hpp")

file(GLOB LIB_SOURCES
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc")

# Keep all sources including database.cpp (will use stub implementations if SQLite3 not available)

# Create named folders for the sources within the project
source_group("header" FILES ${LIB_HEADERS})
source_group("src" FILES ${LIB_SOURCES})

# Set Properties->General->Configuration Type to Dynamic Library (.dll/.so/.dylib)
add_library(${LIBNAME} STATIC ${LIB_HEADERS} ${LIB_SOURCES}) # for dynamic library use SHARED

target_include_directories(${LIBNAME} PUBLIC
						   ${CMAKE_CURRENT_SOURCE_DIR}/../utility/header
						   ${CMAKE_CURRENT_SOURCE_DIR}/header)

# Add any dependencies or compile options specific to crypto
target_link_libraries(${LIBNAME} PRIVATE utility)

# SQLite3 library
find_package(SQLite3 QUIET)
if(SQLite3_FOUND)
    message(STATUS "[${ROOT}/${LIBNAME}] SQLite3 found via find_package: ${SQLite3_LIBRARIES}")
    target_link_libraries(${LIBNAME} PRIVATE SQLite::SQLite3)
    target_compile_definitions(${LIBNAME} PRIVATE HAVE_SQLITE3)
else()
    message(STATUS "[${ROOT}/${LIBNAME}] SQLite3 not found via find_package, searching manually...")
    
    if(WIN32)
        # Common SQLite3 installation paths on Windows
        set(SQLITE3_SEARCH_PATHS
            "${CMAKE_SOURCE_DIR}/external/sqlite3"
            "C:/ProgramData/chocolatey/lib/sqlite/tools"
            "C:/sqlite3"
            "C:/Program Files/sqlite3"
            "C:/Program Files (x86)/CodeBlocks/MinGW/opt"
            "C:/MinGW"
            "C:/msys64/mingw64"
            "$ENV{ProgramFiles}/sqlite3"
            "$ENV{LOCALAPPDATA}/sqlite3"
        )
        
        # Try to find sqlite3.h
        find_path(SQLITE3_INCLUDE_DIR 
            NAMES sqlite3.h
            PATHS ${SQLITE3_SEARCH_PATHS}
            PATH_SUFFIXES include
            NO_DEFAULT_PATH
        )
        
        # Also try system paths
        if(NOT SQLITE3_INCLUDE_DIR)
            find_path(SQLITE3_INCLUDE_DIR NAMES sqlite3.h)
        endif()
        
        # Try to find sqlite3 library (DLL on Windows)
        find_library(SQLITE3_LIBRARY
            NAMES sqlite3 sqlite3.lib sqlite3.dll libsqlite3 libsqlite3.a
            PATHS ${SQLITE3_SEARCH_PATHS}
            PATH_SUFFIXES lib bin "" .
            NO_DEFAULT_PATH
        )
        
        # Also try system paths
        if(NOT SQLITE3_LIBRARY)
            find_library(SQLITE3_LIBRARY NAMES sqlite3 sqlite3.lib libsqlite3)
        endif()
        
        if(SQLITE3_INCLUDE_DIR AND SQLITE3_LIBRARY)
            message(STATUS "[${ROOT}/${LIBNAME}] SQLite3 found manually:")
            message(STATUS "  Include: ${SQLITE3_INCLUDE_DIR}")
            message(STATUS "  Library: ${SQLITE3_LIBRARY}")
            target_include_directories(${LIBNAME} PUBLIC ${SQLITE3_INCLUDE_DIR})
            target_link_libraries(${LIBNAME} PRIVATE ${SQLITE3_LIBRARY})
            message(STATUS "[${ROOT}/${LIBNAME}] Database features enabled")
        elseif(SQLITE3_INCLUDE_DIR)
            # Try to find just the DLL if no .lib was found
            find_file(SQLITE3_DLL
                NAMES sqlite3.dll
                PATHS ${SQLITE3_SEARCH_PATHS}
                PATH_SUFFIXES bin "" .
                NO_DEFAULT_PATH
            )
            if(SQLITE3_DLL)
                message(STATUS "[${ROOT}/${LIBNAME}] SQLite3 DLL found at: ${SQLITE3_DLL}")
                message(STATUS "  Include: ${SQLITE3_INCLUDE_DIR}")
                target_include_directories(${LIBNAME} PUBLIC ${SQLITE3_INCLUDE_DIR})
                target_link_libraries(${LIBNAME} PRIVATE ${SQLITE3_DLL})
                message(STATUS "[${ROOT}/${LIBNAME}] Database features enabled with DLL")
            else()
                message(STATUS "[${ROOT}/${LIBNAME}] SQLite3 headers found at: ${SQLITE3_INCLUDE_DIR}")
                message(WARNING "[${ROOT}/${LIBNAME}] SQLite3 library not found - database features will be disabled")
                message(WARNING "  To enable database features, install SQLite3 with library:")
                message(WARNING "  Option 1: vcpkg install sqlite3:x64-windows")
                message(WARNING "  Option 2: Download precompiled DLL from https://www.sqlite.org/download.html")
                target_include_directories(${LIBNAME} PUBLIC ${SQLITE3_INCLUDE_DIR})
                target_compile_definitions(${LIBNAME} PUBLIC SQLITE3_HEADER_ONLY)
                # Don't link library if it doesn't exist
            endif()
        else()
            message(WARNING "[${ROOT}/${LIBNAME}] SQLite3 headers not found!")
            message(WARNING "  Please install SQLite3: choco install sqlite -y")
            message(WARNING "  Or place sqlite3.h in one of these directories:")
            foreach(path ${SQLITE3_SEARCH_PATHS})
                message(WARNING "    ${path}")
            endforeach()
            # Try linking anyway in case it's in system path
            target_link_libraries(${LIBNAME} PRIVATE sqlite3)
        endif()
    else()
        # Linux/Unix: Use pkg-config or system libraries
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(SQLITE3 QUIET sqlite3)
            if(SQLITE3_FOUND)
                message(STATUS "[${ROOT}/${LIBNAME}] SQLite3 found via pkg-config")
                target_include_directories(${LIBNAME} PRIVATE ${SQLITE3_INCLUDE_DIRS})
                target_link_libraries(${LIBNAME} PRIVATE ${SQLITE3_LIBRARIES})
            else()
                target_link_libraries(${LIBNAME} PRIVATE sqlite3)
            endif()
        else()
            target_link_libraries(${LIBNAME} PRIVATE sqlite3)
        endif()
    endif()
endif()

# creates preprocessor definition used for library exports
add_compile_definitions("CORUH_petcare_LIB_EXPORTS")

install(TARGETS ${LIBNAME}
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin )
		
# Copy required header to the installation include folder		
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/header/petcare.h
        DESTINATION include)

# Export the crypto target so other modules can use it
# export(TARGETS ${LIBNAME} FILE ${LIBNAME}Targets.cmake)

message(STATUS "[${ROOT}/${LIBNAME}] Added library target: ${LIBNAME}")
