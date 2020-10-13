IF(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  ADD_SUBDIRECTORY(fuzz)

  ADD_EXECUTABLE(dhpf-san dns_handle_packet_file.c)
  TARGET_INCLUDE_DIRECTORIES(dhpf-san PRIVATE ${PROJECT_SOURCE_DIR})
  TARGET_COMPILE_OPTIONS(dhpf-san PRIVATE -g -fno-omit-frame-pointer -fsanitize=undefined,address,leak -fno-sanitize-recover=all)
  TARGET_LINK_OPTIONS(dhpf-san PRIVATE -fsanitize=undefined,address,leak)
  TARGET_LINK_LIBRARIES(dhpf-san umdns-lib-san)
ENDIF()

ADD_EXECUTABLE(dhpf dns_handle_packet_file.c)
TARGET_INCLUDE_DIRECTORIES(dhpf PRIVATE ${PROJECT_SOURCE_DIR})
TARGET_LINK_LIBRARIES(dhpf umdns-lib)
