
if(NOT TARGET retdec::unpacker)
    find_package(retdec 5.0
        REQUIRED
        COMPONENTS
            loader
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-unpacker-targets.cmake)
endif()
