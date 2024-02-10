
if(NOT TARGET retdec::demangler)
    find_package(retdec 5.0
        REQUIRED
        COMPONENTS
            ctypesparser
            llvm
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-demangler-targets.cmake)
endif()
