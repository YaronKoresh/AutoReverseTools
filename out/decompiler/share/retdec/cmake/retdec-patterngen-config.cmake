
if(NOT TARGET retdec::patterngen)
    find_package(retdec 5.0
        REQUIRED
        COMPONENTS
            fileformat
            utils
            yaramod
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-patterngen-targets.cmake)
endif()
