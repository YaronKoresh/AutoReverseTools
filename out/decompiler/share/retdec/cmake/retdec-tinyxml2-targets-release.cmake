#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "retdec::deps::tinyxml2" for configuration "Release"
set_property(TARGET retdec::deps::tinyxml2 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(retdec::deps::tinyxml2 PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/retdec-tinyxml2.lib"
  )

list(APPEND _cmake_import_check_targets retdec::deps::tinyxml2 )
list(APPEND _cmake_import_check_files_for_retdec::deps::tinyxml2 "${_IMPORT_PREFIX}/lib/retdec-tinyxml2.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
