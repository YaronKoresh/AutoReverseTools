
if(NOT TARGET retdec::yaracpp)
    find_package(retdec 5.0
        REQUIRED
        COMPONENTS
            libyara
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-yaracpp-targets.cmake)
endif()
