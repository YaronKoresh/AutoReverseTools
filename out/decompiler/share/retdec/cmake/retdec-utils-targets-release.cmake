#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "retdec::utils" for configuration "Release"
set_property(TARGET retdec::utils APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(retdec::utils PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C;CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/retdec-utils.lib"
  )

list(APPEND _cmake_import_check_targets retdec::utils )
list(APPEND _cmake_import_check_files_for_retdec::utils "${_IMPORT_PREFIX}/lib/retdec-utils.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
