# - Try to find etesync
# Once done this will define
#  ETESYNC_FOUND - System has etesync
#  ETESYNC_INCLUDE_DIRS - The etesync include directories
#  ETESYNC_LIBRARIES - The libraries needed to use etesync
#  ETESYNC_DEFINITIONS - Compiler switches required for using etesync

find_package(PkgConfig)
if ("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}.${CMAKE_PATCH_VERSION}" VERSION_GREATER "2.8.1")
   # "QUIET" was introduced in 2.8.2
   set(_QUIET QUIET)
endif ()
pkg_check_modules(PC_ETESYNC ${_QUIET} etesync)

find_library(ETESYNC_LIBRARY
             NAMES ${PC_ETESYNC_LIBRARIES}
             HINTS ${PC_ETESYNC_LIBDIR} ${PC_ETESYNC_LIBRARY_DIRS} )

set(ETESYNC_DEFINITIONS ${PC_ETESYNC_CFLAGS_OTHER})
set(ETESYNC_LIBRARIES ${ETESYNC_LIBRARY})
set(ETESYNC_INCLUDE_DIRS ${PC_ETESYNC_INCLUDE_DIRS})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set ETESYNC_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(EteSync DEFAULT_MSG
   ETESYNC_LIBRARIES ETESYNC_INCLUDE_DIRS)

mark_as_advanced(ETESYNC_INCLUDE_DIRS ETESYNC_LIBRARY ETESYNC_LIBRARIES ETESYNC_DEFINITIONS)
