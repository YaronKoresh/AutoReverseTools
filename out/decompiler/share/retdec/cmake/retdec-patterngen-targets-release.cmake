#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "retdec::patterngen" for configuration "Release"
set_property(TARGET retdec::patterngen APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(retdec::patterngen PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/retdec-patterngen.lib"
  )

list(APPEND _cmake_import_check_targets retdec::patterngen )
list(APPEND _cmake_import_check_files_for_retdec::patterngen "${_IMPORT_PREFIX}/lib/retdec-patterngen.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
