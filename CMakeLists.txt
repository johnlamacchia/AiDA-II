cmake_minimum_required(VERSION 3.20)
project(AiDA VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------- platform detection ----------
if(WIN32)
    set(AIDA_PLATFORM "windows")
    add_compile_definitions(AIDA_WINDOWS=1)
elseif(UNIX AND NOT APPLE)
    set(AIDA_PLATFORM "linux")
    add_compile_definitions(AIDA_LINUX=1)
elseif(APPLE)
    set(AIDA_PLATFORM "macos")
    add_compile_definitions(AIDA_MACOS=1)
endif()
message(STATUS "AiDA platform: ${AIDA_PLATFORM}")

option(AIDA_ENABLE_KERNEL "Enable kernel driver features (Windows only)" ON)
if(NOT WIN32)
    set(AIDA_ENABLE_KERNEL OFF CACHE BOOL "" FORCE)
    message(STATUS "AiDA: kernel features disabled (non-Windows)")
endif()
if(AIDA_ENABLE_KERNEL)
    add_compile_definitions(AIDA_KERNEL=1)
endif()

option(AIDA_BUILD_GUI "Build the graphical frontend" ON)
option(AIDA_BUILD_MCP "Build the MCP stdio server" ON)

# ---------- dependencies ----------

# capstone (disassembler)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "" FORCE)
set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_MIPS_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_RISCV_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_PPC_SUPPORT ON CACHE BOOL "" FORCE)
include(FetchContent)
FetchContent_Declare(capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG        5.0.9)
FetchContent_MakeAvailable(capstone)

# sqlite (project storage)
FetchContent_Declare(sqlite3
    URL https://www.sqlite.org/2025/sqlite-amalgamation-3490100.zip)
FetchContent_MakeAvailable(sqlite3)
add_library(sqlite3_lib STATIC ${sqlite3_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3_lib PUBLIC ${sqlite3_SOURCE_DIR})
if(UNIX)
    target_link_libraries(sqlite3_lib PRIVATE pthread dl m)
endif()

# nlohmann/json (single header, vendored)
add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json INTERFACE ${CMAKE_SOURCE_DIR}/vendor)

# ---------- ghidra decompiler (native C++) ----------
option(AIDA_BUILD_DECOMPILER "Build Ghidra native decompiler" ON)
if(AIDA_BUILD_DECOMPILER)
    FetchContent_Declare(ghidra_source
        GIT_REPOSITORY https://github.com/rizinorg/ghidra.git
        GIT_TAG        3e5d774389b3c4ff1c089ddf822f071c10f548a8
        GIT_SHALLOW    OFF)
    FetchContent_Declare(pugixml
        GIT_REPOSITORY https://github.com/zeux/pugixml.git
        GIT_TAG        v1.14)
    FetchContent_Declare(zlib_src
        GIT_REPOSITORY https://github.com/madler/zlib.git
        GIT_TAG        v1.3.1)
    FetchContent_MakeAvailable(pugixml)
    FetchContent_Populate(ghidra_source)
    FetchContent_Populate(zlib_src)

    # build zlib as static
    add_library(zlib_static STATIC
        ${zlib_src_SOURCE_DIR}/adler32.c
        ${zlib_src_SOURCE_DIR}/compress.c
        ${zlib_src_SOURCE_DIR}/crc32.c
        ${zlib_src_SOURCE_DIR}/deflate.c
        ${zlib_src_SOURCE_DIR}/infback.c
        ${zlib_src_SOURCE_DIR}/inffast.c
        ${zlib_src_SOURCE_DIR}/inflate.c
        ${zlib_src_SOURCE_DIR}/inftrees.c
        ${zlib_src_SOURCE_DIR}/trees.c
        ${zlib_src_SOURCE_DIR}/uncompr.c
        ${zlib_src_SOURCE_DIR}/zutil.c)
    target_include_directories(zlib_static PUBLIC ${zlib_src_SOURCE_DIR} ${zlib_src_BINARY_DIR})
    # generate zconf.h
    if(NOT EXISTS "${zlib_src_BINARY_DIR}/zconf.h")
        file(COPY "${zlib_src_SOURCE_DIR}/zconf.h" DESTINATION "${zlib_src_BINARY_DIR}")
    endif()

    set(GHIDRA_DECOMP_DIR "${ghidra_source_SOURCE_DIR}/Ghidra/Features/Decompiler/src/decompile/cpp")

    # base library
    set(GHIDRA_BASE_SRC
        ${GHIDRA_DECOMP_DIR}/xml.cc
        ${GHIDRA_DECOMP_DIR}/marshal.cc
        ${GHIDRA_DECOMP_DIR}/space.cc
        ${GHIDRA_DECOMP_DIR}/float.cc
        ${GHIDRA_DECOMP_DIR}/address.cc
        ${GHIDRA_DECOMP_DIR}/pcoderaw.cc
        ${GHIDRA_DECOMP_DIR}/translate.cc
        ${GHIDRA_DECOMP_DIR}/opcodes.cc
        ${GHIDRA_DECOMP_DIR}/globalcontext.cc)
    add_library(ghidra_base STATIC ${GHIDRA_BASE_SRC})
    target_include_directories(ghidra_base PUBLIC ${GHIDRA_DECOMP_DIR})
    set_target_properties(ghidra_base PROPERTIES POSITION_INDEPENDENT_CODE ON)
    if(WIN32)
        target_compile_definitions(ghidra_base PRIVATE _WINDOWS NOMINMAX)
    endif()
    if(NOT MSVC)
        target_compile_options(ghidra_base PRIVATE -w)
    else()
        target_compile_options(ghidra_base PRIVATE /W0)
        target_compile_definitions(ghidra_base PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()

    # decompiler library
    set(GHIDRA_DECOMP_SRC
        ${GHIDRA_DECOMP_DIR}/capability.cc
        ${GHIDRA_DECOMP_DIR}/architecture.cc
        ${GHIDRA_DECOMP_DIR}/options.cc
        ${GHIDRA_DECOMP_DIR}/graph.cc
        ${GHIDRA_DECOMP_DIR}/cover.cc
        ${GHIDRA_DECOMP_DIR}/block.cc
        ${GHIDRA_DECOMP_DIR}/cast.cc
        ${GHIDRA_DECOMP_DIR}/typeop.cc
        ${GHIDRA_DECOMP_DIR}/database.cc
        ${GHIDRA_DECOMP_DIR}/cpool.cc
        ${GHIDRA_DECOMP_DIR}/comment.cc
        ${GHIDRA_DECOMP_DIR}/fspec.cc
        ${GHIDRA_DECOMP_DIR}/action.cc
        ${GHIDRA_DECOMP_DIR}/loadimage.cc
        ${GHIDRA_DECOMP_DIR}/varnode.cc
        ${GHIDRA_DECOMP_DIR}/op.cc
        ${GHIDRA_DECOMP_DIR}/type.cc
        ${GHIDRA_DECOMP_DIR}/variable.cc
        ${GHIDRA_DECOMP_DIR}/varmap.cc
        ${GHIDRA_DECOMP_DIR}/jumptable.cc
        ${GHIDRA_DECOMP_DIR}/emulate.cc
        ${GHIDRA_DECOMP_DIR}/emulateutil.cc
        ${GHIDRA_DECOMP_DIR}/flow.cc
        ${GHIDRA_DECOMP_DIR}/userop.cc
        ${GHIDRA_DECOMP_DIR}/funcdata.cc
        ${GHIDRA_DECOMP_DIR}/funcdata_block.cc
        ${GHIDRA_DECOMP_DIR}/funcdata_varnode.cc
        ${GHIDRA_DECOMP_DIR}/unionresolve.cc
        ${GHIDRA_DECOMP_DIR}/funcdata_op.cc
        ${GHIDRA_DECOMP_DIR}/pcodeinject.cc
        ${GHIDRA_DECOMP_DIR}/heritage.cc
        ${GHIDRA_DECOMP_DIR}/prefersplit.cc
        ${GHIDRA_DECOMP_DIR}/rangeutil.cc
        ${GHIDRA_DECOMP_DIR}/ruleaction.cc
        ${GHIDRA_DECOMP_DIR}/subflow.cc
        ${GHIDRA_DECOMP_DIR}/blockaction.cc
        ${GHIDRA_DECOMP_DIR}/merge.cc
        ${GHIDRA_DECOMP_DIR}/double.cc
        ${GHIDRA_DECOMP_DIR}/coreaction.cc
        ${GHIDRA_DECOMP_DIR}/condexe.cc
        ${GHIDRA_DECOMP_DIR}/override.cc
        ${GHIDRA_DECOMP_DIR}/dynamic.cc
        ${GHIDRA_DECOMP_DIR}/crc32.cc
        ${GHIDRA_DECOMP_DIR}/prettyprint.cc
        ${GHIDRA_DECOMP_DIR}/printlanguage.cc
        ${GHIDRA_DECOMP_DIR}/printc.cc
        ${GHIDRA_DECOMP_DIR}/printjava.cc
        ${GHIDRA_DECOMP_DIR}/memstate.cc
        ${GHIDRA_DECOMP_DIR}/opbehavior.cc
        ${GHIDRA_DECOMP_DIR}/paramid.cc
        ${GHIDRA_DECOMP_DIR}/transform.cc
        ${GHIDRA_DECOMP_DIR}/string_ghidra.cc
        ${GHIDRA_DECOMP_DIR}/stringmanage.cc
        ${GHIDRA_DECOMP_DIR}/bitfield.cc
        ${GHIDRA_DECOMP_DIR}/expression.cc
        ${GHIDRA_DECOMP_DIR}/multiprecision.cc
        ${GHIDRA_DECOMP_DIR}/modelrules.cc
        ${GHIDRA_DECOMP_DIR}/constseq.cc)
    add_library(ghidra_decompiler_lib STATIC ${GHIDRA_DECOMP_SRC})
    target_link_libraries(ghidra_decompiler_lib PUBLIC ghidra_base)
    target_include_directories(ghidra_decompiler_lib PUBLIC ${GHIDRA_DECOMP_DIR})
    set_target_properties(ghidra_decompiler_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)
    if(WIN32)
        target_compile_definitions(ghidra_decompiler_lib PRIVATE _WINDOWS NOMINMAX)
    endif()
    if(NOT MSVC)
        target_compile_options(ghidra_decompiler_lib PRIVATE -w)
    else()
        target_compile_options(ghidra_decompiler_lib PRIVATE /W0)
        target_compile_definitions(ghidra_decompiler_lib PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()

    # sleigh library
    set(GHIDRA_SLEIGH_SRC
        ${GHIDRA_DECOMP_DIR}/sleigh_arch.cc
        ${GHIDRA_DECOMP_DIR}/sleigh.cc
        ${GHIDRA_DECOMP_DIR}/inject_sleigh.cc
        ${GHIDRA_DECOMP_DIR}/filemanage.cc
        ${GHIDRA_DECOMP_DIR}/semantics.cc
        ${GHIDRA_DECOMP_DIR}/slaformat.cc
        ${GHIDRA_DECOMP_DIR}/compression.cc
        ${GHIDRA_DECOMP_DIR}/slghsymbol.cc
        ${GHIDRA_DECOMP_DIR}/context.cc
        ${GHIDRA_DECOMP_DIR}/sleighbase.cc
        ${GHIDRA_DECOMP_DIR}/slghpatexpress.cc
        ${GHIDRA_DECOMP_DIR}/slghpattern.cc
        ${GHIDRA_DECOMP_DIR}/pcodecompile.cc
        ${GHIDRA_DECOMP_DIR}/pcodeparse.cc
        ${GHIDRA_DECOMP_DIR}/grammar.cc)
    add_library(ghidra_sleigh STATIC ${GHIDRA_SLEIGH_SRC})
    target_link_libraries(ghidra_sleigh PUBLIC ghidra_base zlib_static)
    target_include_directories(ghidra_sleigh PUBLIC ${GHIDRA_DECOMP_DIR})
    set_target_properties(ghidra_sleigh PROPERTIES POSITION_INDEPENDENT_CODE ON)
    if(WIN32)
        target_compile_definitions(ghidra_sleigh PRIVATE _WINDOWS NOMINMAX)
    endif()
    if(NOT MSVC)
        target_compile_options(ghidra_sleigh PRIVATE -w)
    else()
        target_compile_options(ghidra_sleigh PRIVATE /W0)
        target_compile_definitions(ghidra_sleigh PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()

    # libdecomp (ties decompiler + sleigh together)
    add_library(ghidra_libdecomp STATIC ${GHIDRA_DECOMP_DIR}/libdecomp.cc)
    target_link_libraries(ghidra_libdecomp PUBLIC ghidra_decompiler_lib ghidra_sleigh)
    set_target_properties(ghidra_libdecomp PROPERTIES POSITION_INDEPENDENT_CODE ON)
    if(WIN32)
        target_compile_definitions(ghidra_libdecomp PRIVATE _WINDOWS NOMINMAX)
    endif()
    if(NOT MSVC)
        target_compile_options(ghidra_libdecomp PRIVATE -w)
    else()
        target_compile_options(ghidra_libdecomp PRIVATE /W0)
        target_compile_definitions(ghidra_libdecomp PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()

    # sleigh compiler (to compile .slaspec -> .sla)
    set(GHIDRA_SLEIGHC_SRC
        ${GHIDRA_DECOMP_DIR}/slgh_compile.cc
        ${GHIDRA_DECOMP_DIR}/slghparse.cc
        ${GHIDRA_DECOMP_DIR}/slghscan.cc)
    add_executable(sleighc ${GHIDRA_SLEIGHC_SRC})
    target_link_libraries(sleighc ghidra_sleigh)
    if(WIN32)
        target_compile_definitions(sleighc PRIVATE _WINDOWS NOMINMAX)
    endif()
    if(NOT MSVC)
        target_compile_options(sleighc PRIVATE -w)
    else()
        target_compile_options(sleighc PRIVATE /W0)
        target_compile_definitions(sleighc PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()

    # compile .slaspec files for supported architectures
    set(GHIDRA_PROC_DIR "${ghidra_source_SOURCE_DIR}/Ghidra/Processors")
    set(SLEIGH_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/sleigh")
    file(MAKE_DIRECTORY "${SLEIGH_OUT_DIR}")

    set(AIDA_SLASPEC_LIST
        "${GHIDRA_PROC_DIR}/x86/data/languages/x86.slaspec"
        "${GHIDRA_PROC_DIR}/x86/data/languages/x86-64.slaspec"
        "${GHIDRA_PROC_DIR}/ARM/data/languages/ARM8_le.slaspec"
        "${GHIDRA_PROC_DIR}/ARM/data/languages/ARM8_be.slaspec"
        "${GHIDRA_PROC_DIR}/AARCH64/data/languages/AARCH64.slaspec"
        "${GHIDRA_PROC_DIR}/AARCH64/data/languages/AARCH64BE.slaspec"
        "${GHIDRA_PROC_DIR}/MIPS/data/languages/mips32be.slaspec"
        "${GHIDRA_PROC_DIR}/MIPS/data/languages/mips32le.slaspec"
        "${GHIDRA_PROC_DIR}/MIPS/data/languages/mips64be.slaspec"
        "${GHIDRA_PROC_DIR}/MIPS/data/languages/mips64le.slaspec"
        "${GHIDRA_PROC_DIR}/RISCV/data/languages/riscv.lp64d.slaspec"
        "${GHIDRA_PROC_DIR}/PowerPC/data/languages/ppc_32_be.slaspec"
        "${GHIDRA_PROC_DIR}/PowerPC/data/languages/ppc_64_be.slaspec")

    set(AIDA_SLA_FILES "")
    foreach(slaspec ${AIDA_SLASPEC_LIST})
        get_filename_component(sla_name "${slaspec}" NAME_WE)
        get_filename_component(sla_dir "${slaspec}" DIRECTORY)
        set(sla_file "${SLEIGH_OUT_DIR}/${sla_name}.sla")
        add_custom_command(OUTPUT "${sla_file}"
            COMMAND sleighc "${slaspec}" "${sla_file}"
            MAIN_DEPENDENCY "${slaspec}"
            WORKING_DIRECTORY "${sla_dir}"
            DEPENDS sleighc)
        list(APPEND AIDA_SLA_FILES "${sla_file}")
    endforeach()
    add_custom_target(sla_specs ALL DEPENDS ${AIDA_SLA_FILES})

    # copy .cspec, .pspec, .ldefs alongside .sla files
    set(AIDA_PROC_DIRS x86 ARM AARCH64 MIPS RISCV PowerPC)
    foreach(proc ${AIDA_PROC_DIRS})
        file(GLOB spec_files
            "${GHIDRA_PROC_DIR}/${proc}/data/languages/*.cspec"
            "${GHIDRA_PROC_DIR}/${proc}/data/languages/*.pspec"
            "${GHIDRA_PROC_DIR}/${proc}/data/languages/*.ldefs")
        file(COPY ${spec_files} DESTINATION "${SLEIGH_OUT_DIR}")
    endforeach()

    add_compile_definitions(AIDA_HAS_DECOMP=1)
    set(AIDA_SLEIGH_DIR "${SLEIGH_OUT_DIR}" CACHE STRING "Path to compiled SLEIGH specs")
endif()

# ---------- core analysis library ----------
add_library(aida_core STATIC
    src/core/binary.cpp
    src/core/pe.cpp
    src/core/elf.cpp
    src/core/loader.cpp
    src/core/disasm.cpp
    src/core/analysis.cpp
    src/core/firmware.cpp
    src/core/project.cpp
    src/core/crypto_scan.cpp
    src/core/entropy.cpp
    src/core/imphash.cpp
    src/core/decrypt.cpp
    $<$<BOOL:${AIDA_BUILD_DECOMPILER}>:src/core/decompiler.cpp>
)
target_include_directories(aida_core PUBLIC src)
target_link_libraries(aida_core PUBLIC capstone sqlite3_lib nlohmann_json)
if(AIDA_BUILD_DECOMPILER)
    target_link_libraries(aida_core PUBLIC ghidra_libdecomp ghidra_decompiler_lib ghidra_sleigh ghidra_base pugixml-static zlib_static)
    # force linker to pull in PrintC/PrintJava static registration objects from static lib
    if(NOT MSVC)
        target_link_options(aida_core PUBLIC
            "LINKER:-u,_ZN6ghidra16PrintCCapability16printCCapabilityE"
            "LINKER:-u,_ZN6ghidra19PrintJavaCapability19printJavaCapabilityE")
    endif()
    target_compile_definitions(aida_core PUBLIC AIDA_SLEIGH_DIR="${AIDA_SLEIGH_DIR}")
    add_dependencies(aida_core sla_specs)
endif()
if(MSVC)
    target_compile_options(aida_core PRIVATE /W3 /wd4244 /wd4267)
    target_compile_definitions(aida_core PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
else()
    target_compile_options(aida_core PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

# ---------- MCP server library ----------
if(AIDA_BUILD_MCP)
    add_library(aida_mcp STATIC
        src/mcp/server.cpp
        src/mcp/tools.cpp
    )
    target_include_directories(aida_mcp PUBLIC src)
    target_link_libraries(aida_mcp PUBLIC aida_core nlohmann_json)
    if(MSVC)
        target_compile_definitions(aida_mcp PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    endif()
endif()

# ---------- GUI ----------
if(AIDA_BUILD_GUI)
    # GLFW
    set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(glfw
        GIT_REPOSITORY https://github.com/glfw/glfw.git
        GIT_TAG        3.4)
    FetchContent_MakeAvailable(glfw)

    # ImGui (fetched)
    FetchContent_Declare(imgui_src
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG        v1.91.8-docking)
    FetchContent_Populate(imgui_src)
    set(IMGUI_DIR ${imgui_src_SOURCE_DIR})

    add_library(imgui STATIC
        ${IMGUI_DIR}/imgui.cpp
        ${IMGUI_DIR}/imgui_demo.cpp
        ${IMGUI_DIR}/imgui_draw.cpp
        ${IMGUI_DIR}/imgui_tables.cpp
        ${IMGUI_DIR}/imgui_widgets.cpp
        ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
        ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
    )
    target_include_directories(imgui PUBLIC ${IMGUI_DIR} ${IMGUI_DIR}/backends)
    target_link_libraries(imgui PUBLIC glfw)
    if(WIN32)
        target_link_libraries(imgui PUBLIC opengl32)
    else()
        find_package(OpenGL REQUIRED)
        target_link_libraries(imgui PUBLIC OpenGL::GL)
    endif()
    if(MSVC)
        target_compile_options(imgui PRIVATE /W0)
    endif()
endif()

# ---------- main executable ----------
add_executable(aida src/main.cpp)
target_link_libraries(aida PRIVATE aida_core)
if(AIDA_BUILD_MCP)
    target_link_libraries(aida PRIVATE aida_mcp)
    target_compile_definitions(aida PRIVATE AIDA_HAS_MCP=1)
endif()
if(AIDA_BUILD_GUI)
    add_library(aida_ui STATIC
        src/ui/app.cpp
    )
    target_include_directories(aida_ui PUBLIC src)
    target_link_libraries(aida_ui PUBLIC aida_core imgui)
    if(MSVC)
        target_compile_definitions(aida_ui PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    endif()

    if(AIDA_BUILD_MCP)
        target_link_libraries(aida_ui PUBLIC aida_mcp)
        target_compile_definitions(aida_ui PRIVATE AIDA_HAS_MCP=1)
    endif()
    target_link_libraries(aida PRIVATE aida_ui imgui)
    target_compile_definitions(aida PRIVATE AIDA_HAS_GUI=1)
endif()
if(WIN32)
    target_link_libraries(aida PRIVATE ws2_32 comdlg32)
    if(AIDA_ENABLE_KERNEL)
        target_link_libraries(aida PRIVATE ntdll)
    endif()
endif()
if(MSVC)
    target_compile_definitions(aida PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    set_target_properties(aida PROPERTIES WIN32_EXECUTABLE $<$<BOOL:${AIDA_BUILD_GUI}>:TRUE>)
else()
    target_link_options(aida PRIVATE -static)
endif()
