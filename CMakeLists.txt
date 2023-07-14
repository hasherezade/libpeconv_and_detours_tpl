cmake_minimum_required ( VERSION 3.0 )
project ( template_project )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

include_directories (
  include
)
# modules:
set ( M_DETOURS_LIB "libdetours" )
set ( M_PARSER "libpeconv/libpeconv" )

# modules paths:
set (PECONV_DIR "${CMAKE_SOURCE_DIR}/${M_PARSER}" CACHE PATH "PEConv main path")
set (DETOURS_DIR "${CMAKE_SOURCE_DIR}/${M_DETOURS_LIB}" CACHE PATH "Detours main path")

# libs
add_subdirectory ( libdetours )
set ( DETOURS_LIB $<TARGET_FILE:libdetours> CACHE PATH "Detours library path" )

add_subdirectory ( ${PECONV_DIR} )
set ( PECONV_LIB $<TARGET_FILE:libpeconv> CACHE PATH "PEConvLib library path" )

# main project
add_subdirectory ( project_tpl )
