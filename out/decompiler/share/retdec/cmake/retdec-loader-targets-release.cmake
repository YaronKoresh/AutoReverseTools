#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "retdec::loader" for configuration "Release"
set_property(TARGET retdec::loader APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(retdec::loader PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/retdec-loader.lib"
  )

list(APPEND _cmake_import_check_targets retdec::loader )
list(APPEND _cmake_import_check_files_for_retdec::loader "${_IMPORT_PREFIX}/lib/retdec-loader.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
