#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "retdec::ar-extractor" for configuration "Release"
set_property(TARGET retdec::ar-extractor APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(retdec::ar-extractor PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/retdec-ar-extractor.lib"
  )

list(APPEND _cmake_import_check_targets retdec::ar-extractor )
list(APPEND _cmake_import_check_files_for_retdec::ar-extractor "${_IMPORT_PREFIX}/lib/retdec-ar-extractor.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
