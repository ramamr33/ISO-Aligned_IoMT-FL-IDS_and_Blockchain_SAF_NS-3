set(target_prefix scratch_)

function(create_scratch source_files)
  # Return early if no sources in the subdirectory
  list(LENGTH source_files number_sources)
  if(number_sources EQUAL 0)
    return()
  endif()

  # If the scratch has more than a source file, we need to find the source with
  # the main function
  set(scratch_src)
  foreach(source_file ${source_files})
    file(READ ${source_file} source_file_contents)
    string(REGEX MATCHALL "main[(| (]" main_position "${source_file_contents}")
    if(CMAKE_MATCH_0)
      list(APPEND scratch_src ${source_file})
    endif()
  endforeach()

  list(LENGTH scratch_src scratch_src_len)

  # If there is no main function, raise an error
  if(${scratch_src_len} EQUAL 0)
    message(FATAL_ERROR "The following scratch source files do not contain a main function: ${source_files}")
  endif()

  # If there are multiple main functions, raise an error
  if(${scratch_src_len} GREATER 1)
    message(FATAL_ERROR "The following scratch source files contain ${scratch_src_len} files with a main function: ${scratch_src}")
  endif()

  # If there is a single main function, continue normally

  # Get parent directory name
  get_filename_component(scratch_dirname ${scratch_src} DIRECTORY)
  string(REPLACE "${CMAKE_CURRENT_SOURCE_DIR}" "" scratch_dirname
                 "${scratch_dirname}"
  )
  string(REPLACE "/" "_" scratch_dirname "${scratch_dirname}")

  # Get source name
  if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.14.0")
    get_filename_component(scratch_name ${scratch_src} NAME_WLE)
  else()
    get_filename_component(scratch_name ${scratch_src} NAME)
    string(FIND "${scratch_name}" "." ext_position REVERSE)
    if(${ext_position} EQUAL -1)
      message(FATAL_ERROR "Source file has no extension: ${scratch_src}")
    else()
      string(SUBSTRING "${scratch_name}" 0 ${ext_position} scratch_name)
    endif()
  endif()

  set(target_prefix scratch_)
  if(scratch_dirname)
    # Join the names together if dirname is not the scratch folder
    set(target_prefix scratch${scratch_dirname}_)
  endif()

  # Get source absolute path and transform into relative path
  get_filename_component(scratch_src ${scratch_src} ABSOLUTE)
  get_filename_component(scratch_absolute_directory ${scratch_src} DIRECTORY)
  string(REPLACE "${PROJECT_SOURCE_DIR}" "${CMAKE_OUTPUT_DIRECTORY}"
                 scratch_directory ${scratch_absolute_directory}
  )
  build_exec(
          EXECNAME ${scratch_name}
          EXECNAME_PREFIX ${target_prefix}
          SOURCE_FILES "${source_files}"
          LIBRARIES_TO_LINK "${ns3-libs}" "${ns3-contrib-libs}"
          EXECUTABLE_DIRECTORY_PATH ${scratch_directory}/
  )
endfunction()

# Scan *.cc files in ns-3-dev/scratch and build a target for each
file(GLOB single_source_file_scratches CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/[^.]*.cc)
foreach(scratch_src ${single_source_file_scratches})
  create_scratch(${scratch_src})
endforeach()

# Scan ns-3-dev/scratch subdirectories
file(
  GLOB scratch_subdirectories
  CONFIGURE_DEPENDS
  LIST_DIRECTORIES true
  ${CMAKE_CURRENT_SOURCE_DIR}/**
)
# Filter out files
foreach(entry ${scratch_subdirectories})
  if(NOT (IS_DIRECTORY ${entry}))
    list(REMOVE_ITEM scratch_subdirectories ${entry})
  endif()
endforeach()

# Build scratches per directory or following CMakeLists.txt instructions
foreach(subdir ${scratch_subdirectories})
  if(EXISTS ${subdir}/CMakeLists.txt)
    # If the subdirectory contains a CMakeLists.txt file
    # we let the CMake file manage the source files
    #
    # Use this if you want to link to external libraries
    # without creating a module
    add_subdirectory(${subdir})
  else()
    # Otherwise we pick all the files in the subdirectory
    # and create a scratch for them automatically
    file(GLOB scratch_sources CONFIGURE_DEPENDS ${subdir}/[^.]*.cc)
    create_scratch("${scratch_sources}")
  endif()
endforeach()
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt2 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt3 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt8 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt9 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt10 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt11 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt12 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt13 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt14 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt15 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt16 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt17 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt18 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt19 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl2 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl3 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm OpenSSL::Crypto OpenSSL::SSL)
link_directories(${OPENSSL_LIBRARY_DIR})
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl4 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl5 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl6 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl7 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl8 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl9 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl10 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl11 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl12 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl13 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl14 OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm OpenSSL::Crypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec12 OpenSSL::Crypto)

set(OPENSSL_ROOT_DIR /usr/lib/x86_64-linux-gnu)
set(OPENSSL_LIBRARIES /usr/lib/x86_64-linux-gnu)
set(OPENSSL_LIBRARIES /usr/lib/x86_64-linux-gnu)
set(OPENSSL_INCLUDE_DIR /usr/include)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_dos
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_ddos
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_dos
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_ddos
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_black
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_black
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

cmake_minimum_required(VERSION 3.10)

# Find OpenSSL
find_package(OpenSSL REQUIRED)


# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include OpenSSL headers
#target_include_directories(IoMT-wifi_wip_blocksec_mitm_sec PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_sec ssl crypto)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_black2
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_black2
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec7
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec8
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec9
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm2_sec8
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm2_sec9
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec10
  ssl
  crypto
)
target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm2_sec10
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mqtt
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec5
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_sol2
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm2
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec12
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec15
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm2_sec15
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec17
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm2_sec17
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec17
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm4
  crypto
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm4
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec23
  ssl
  crypto
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm2_sec23
  ssl
  crypto
)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec2
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec2
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_dos2
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_dos2
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

find_library(SSL_LIBRARY ssl)
find_library(CRYPTO_LIBRARY crypto)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_ddos2
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_ddos2
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_black
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_black
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_fed
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_fed2
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm2_sec
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec2
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec5
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec7
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mqtt
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm2_sec2
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm2_sec3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_mitm_blocksec_mitm3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec4
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec5
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec5_last
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec6
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_secc
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl10
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl11
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl12
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl13
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl6
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_dl7
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt18
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt2
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_crypt4
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_multi_blocksec_mitm_edit
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm_sol2
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_dos3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_ddos3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_black3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_dos3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_ddos3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mqtt3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_black3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_black3
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec12
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec14
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec15
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)


target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm2_sec15
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec18
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm4
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm4
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm4
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_wip_blocksec_mitm2_sec23
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

target_link_libraries(scratch_IoMT-wifi_hex_blocksec_mitm2_sec23
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

# Link OpenSSL explicitly for scratch programs
find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    link_libraries(${OPENSSL_LIBRARIES})
endif()
