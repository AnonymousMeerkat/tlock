set(SOURCES
  main.c
  )

add_executable(tlock ${SOURCES})
target_link_libraries(tlock curses m crypt)

install(TARGETS tlock DESTINATION bin
  PERMISSIONS SETUID OWNER_EXECUTE OWNER_READ OWNER_WRITE GROUP_EXECUTE GROUP_READ WORLD_READ WORLD_EXECUTE)
