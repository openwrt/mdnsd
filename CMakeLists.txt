cmake_minimum_required(VERSION 2.6)

PROJECT(umdns C)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES main.c dns.c announce.c cache.c service.c util.c ubus.c interface.c)

SET(LIBS ubox ubus resolv blobmsg_json json-c)

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3)
ENDIF()

ADD_EXECUTABLE(umdns ${SOURCES})

TARGET_LINK_LIBRARIES(umdns ${LIBS})

INSTALL(TARGETS umdns
	RUNTIME DESTINATION sbin
)
