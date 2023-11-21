cmake_minimum_required(VERSION 2.6)

PROJECT(umdns C)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES dns.c announce.c cache.c service.c util.c ubus.c interface.c)

FIND_PATH(ubox_include_dir NAMES libubox/usock.h)
FIND_PATH(ubus_include_dir NAMES libubus.h)
FIND_PATH(udebug_include_dir NAMES udebug.h)
INCLUDE_DIRECTORIES(${ubox_include_dir} ${ubus_include_dir} ${udebug_include_dir})

FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(ubus NAMES ubus)
FIND_LIBRARY(blobmsg_json NAMES blobmsg_json)
FIND_LIBRARY(json NAMES json json-c)
FIND_LIBRARY(udebug NAMES udebug)

SET(LIBS ${ubox} ${ubus} ${blobmsg_json} ${json} resolv ${udebug})

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3)
ENDIF()

ADD_LIBRARY(umdns-lib STATIC ${SOURCES})
TARGET_LINK_LIBRARIES(umdns-lib ${LIBS})

ADD_EXECUTABLE(umdns main.c)
TARGET_LINK_LIBRARIES(umdns umdns-lib)

IF(UNIT_TESTING)
  ENABLE_TESTING()
  ADD_SUBDIRECTORY(tests)

  IF(CMAKE_C_COMPILER_ID STREQUAL "Clang")
	ADD_LIBRARY(umdns-lib-san STATIC ${SOURCES})
	TARGET_COMPILE_OPTIONS(umdns-lib-san PRIVATE -g -fno-omit-frame-pointer -fsanitize=undefined,address,leak -fno-sanitize-recover=all)
    TARGET_LINK_OPTIONS(umdns-lib-san PRIVATE -fsanitize=undefined,address,leak)
	TARGET_LINK_LIBRARIES(umdns-lib-san ${LIBS})

    ADD_EXECUTABLE(umdns-san main.c ${SOURCES})
	TARGET_COMPILE_OPTIONS(umdns-san PRIVATE -g -fno-omit-frame-pointer -fsanitize=undefined,address,leak -fno-sanitize-recover=all)
    TARGET_LINK_OPTIONS(umdns-san PRIVATE -fsanitize=undefined,address,leak)
	TARGET_LINK_LIBRARIES(umdns-san umdns-lib-san)
  ENDIF()

ENDIF()

INSTALL(TARGETS umdns
	RUNTIME DESTINATION sbin
)
