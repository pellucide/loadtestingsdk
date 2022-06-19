# CMakeList.txt : CMake project for transmitlib, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

set(TRANSMIT_LIB transmit)
project(${TRANSMIT_LIB})
set(OPENSSL_ROOT_DIR ./openssl-3/x86)
set(OPENSSL_INCLUDE_DIR ./openssl-3/x86/include)
set(OPENSSL_LIBRARIES ./openssl-3/x86/lib)
file(GLOB HEADERS transmitlib.h)
set(SOURCES transmitlib.c)
 

add_library("${TRANSMIT_LIB}" SHARED "${HEADERS}" "${SOURCES}")
add_library("${TRANSMIT_LIB}-static" STATIC "${HEADERS}" "${SOURCES}")
set_target_properties("${TRANSMIT_LIB}-static" PROPERTIES OUTPUT_NAME "${TRANSMIT_LIB}")
set_target_properties("${TRANSMIT_LIB}-static" PROPERTIES PREFIX "lib")

set(libcrypto_DIR ./openssl-3/x86/lib)
set(libssl_DIR ./openssl-3/x86/lib)
find_package (libssl PATHS ${OPENSSL_LIBRARIES} NO_DEFAULT_PATH)
find_package (libcrypto PATHS ${OPENSSL_LIBRARIES} NO_DEFAULT_PATH)

target_include_directories(${TRANSMIT_LIB} PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_directories(${TRANSMIT_LIB} PUBLIC ${OPENSSL_LIBRARIES} .)
target_link_libraries(${TRANSMIT_LIB} libssl libcrypto cjson)
