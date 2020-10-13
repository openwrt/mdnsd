cmake_minimum_required(VERSION 2.6)

PROJECT(umdns C)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES dns.c announce.c cache.c service.c util.c ubus.c interface.c)

FIND_PATH(ubox_include_dir NAMES libubox/usock.h)
FIND_PATH(ubus_include_dir NAMES libubus.h)
INCLUDE_DIRECTORIES(${ubox_include_dir} ${ubus_include_dir})

FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(ubus NAMES ubus)
FIND_LIBRARY(blobmsg_json NAMES blobmsg_json)
FIND_LIBRARY(json NAMES json json-c)

SET(LIBS ${ubox} ${ubus} ${blobmsg_json} ${json} resolv)

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3)
ENDIF()

ADD_LIBRARY(umdns-lib STATIC ${SOURCES})
TARGET_LINK_LIBRARIES(umdns-lib ${LIBS})

ADD_EXECUTABLE(umdns main.c)
TARGET_LINK_LIBRARIES(umdns umdns-lib)

INSTALL(TARGETS umdns
	RUNTIME DESTINATION sbin
)
