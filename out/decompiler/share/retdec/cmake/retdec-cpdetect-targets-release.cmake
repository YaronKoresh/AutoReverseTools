#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "retdec::cpdetect" for configuration "Release"
set_property(TARGET retdec::cpdetect APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(retdec::cpdetect PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/retdec-cpdetect.lib"
  )

list(APPEND _cmake_import_check_targets retdec::cpdetect )
list(APPEND _cmake_import_check_files_for_retdec::cpdetect "${_IMPORT_PREFIX}/lib/retdec-cpdetect.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
