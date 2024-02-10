
if(NOT TARGET retdec::loader)
    find_package(retdec 5.0
        REQUIRED
        COMPONENTS
            fileformat
            common
            utils
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-loader-targets.cmake)
endif()
