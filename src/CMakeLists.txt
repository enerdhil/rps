file(GLOB_RECURSE SOURCES "*.go")

add_go_component(rps-bin
  ${SOURCES}
)
