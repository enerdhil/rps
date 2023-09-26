
function(go_component_common NAME)
    add_custom_target(${NAME} ALL)

    set(GOPATH "${CMAKE_BINARY_DIR}/go")
    file(MAKE_DIRECTORY ${GOPATH})
    list(LENGTH ARGN len)

    add_custom_command(
        TARGET ${NAME}
        DEPENDS
            ${ARGN}
        COMMAND
            export CC=${CMAKE_C_COMPILER} &&
            export GOPATH=${GOPATH} && export GO111MODULE=on &&
            export GOMOD=${CMAKE_SOURCE_DIR}/go.mod &&
            export GOSUMDB=off &&
            /usr/bin/env bash -c \"echo -e \\\"[100%] \\e[0;32mBuilding ${NAME} Go objects: ${len} files\\e[0m\\\"\" &&
            /usr/bin/env bash -c \"set -o pipefail && ${COMPILE_COMMAND} 2>&1 | { grep -v 'unsafe.*cross-compilation' || true\; } | { grep -v "^#.*" || true\; }\"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endfunction(go_component_common)

function(add_go_component NAME)

    set(COMPILE_COMMAND ${GO_COMPILER} "build" 
        "-o" "${CMAKE_CURRENT_BINARY_DIR}/${NAME}"
    )

    go_component_common(${NAME} ${ARGN})
endfunction(add_go_component)

function(add_go_build_test NAME)

    set(COMPILE_COMMAND ${GO_COMPILER} "test"
        "--ldflags" "'-linkmode" "external"
        "-extldflags" "\"-static\"'"
        "-o" "${CMAKE_CURRENT_BINARY_DIR}/${NAME}"
        "-c" "-v")

    go_component_common(${NAME} ${ARGN})
endfunction(add_go_build_test)

function(add_go_embedded_directory NAME DIRECTORY PKG)
    add_custom_target(
        ${NAME}-${DIRECTORY}-assets
        DEPENDS go-bindata 
        BYPRODUCTS ${CMAKE_CURRENT_SOURCE_DIR}/${DIRECTORY}/bindata.go
        COMMAND
            ${CMAKE_BINARY_DIR}/tools/go-bindata/go-bindata -fs -pkg ${PKG} -ignore ".*go" ./...
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${DIRECTORY}
    )

    add_dependencies(${NAME} ${NAME}-${DIRECTORY}-assets)
endfunction(add_go_embedded_directory)
