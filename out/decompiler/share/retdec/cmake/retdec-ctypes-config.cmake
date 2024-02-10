
if(NOT TARGET retdec::ctypes)
    find_package(retdec 5.0
        REQUIRED
        COMPONENTS
            utils
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-ctypes-targets.cmake)
endif()
