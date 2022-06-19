# CMakeList.txt : CMake project for transmitlib, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

set(TRANSMIT_LIB transmitlib)

project (${TRANSMIT_LIB})

set(OPENSSL_ROOT_DIR ../openssl-3/x86)
set(OPENSSL_INCLUDE_DIR ../openssl-3/x86/include)
set(OPENSSL_LIBRARIES ../openssl-3/x86/lib)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS true)

# Add source to this project's executable.
add_library (${TRANSMIT_LIB} SHARED ../transmitlib.c "transmitlib.cpp" "transmitlib.h")
#add_library("${TRANSMIT_LIB}-static" STATIC ../transmitlib.c "transmitlib.cpp" "transmitlib.h")
#set_target_properties("${TRANSMIT_LIB}-static" PROPERTIES OUTPUT_NAME "${TRANSMIT_LIB}")
#set_target_properties("${TRANSMIT_LIB}-static" PROPERTIES PREFIX "lib")

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS true)
target_sources(${TRANSMIT_LIB} PRIVATE ../transmitlib.def)

set_target_properties(${TRANSMIT_LIB} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS true)

target_include_directories(${TRANSMIT_LIB} PUBLIC ${OPENSSL_INCLUDE_DIR} ..)
target_link_directories(${TRANSMIT_LIB} PUBLIC ${OPENSSL_LIBRARIES} ..)
target_link_libraries(${TRANSMIT_LIB} libssl libcrypto cjson)

#target_include_directories("${TRANSMIT_LIB}-static" PUBLIC ${OPENSSL_INCLUDE_DIR} ..)
#target_link_directories("${TRANSMIT_LIB}-statid" PUBLIC ${OPENSSL_LIBRARIES} ..)
#target_link_libraries("${TRANSMIT_LIB}-static" libssl libcrypto cjson)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET transmitlib PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
