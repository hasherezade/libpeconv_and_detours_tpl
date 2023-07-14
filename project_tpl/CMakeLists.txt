cmake_minimum_required (VERSION 3.0)

project ( project_tpl )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include libdetours headers:
include_directories ( ${DETOURS_DIR}/Detours/src )
include_directories ( ${PECONV_DIR}/include )

set (srcs
	main.cpp
)
set (hdrs
#put your headers here
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} main.cpp )

# link with libdetours.lib
target_link_libraries ( ${PROJECT_NAME} ${DETOURS_LIB} ${PECONV_LIB} )
add_dependencies(${PROJECT_NAME} libdetours libpeconv )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
