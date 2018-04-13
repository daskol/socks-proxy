#   FindGLog.cmake
#   TODO: Add doc string and target GLog::GLog.

find_library(GLOG_LIBRARIES NAMES glog)
find_path(GLOG_INCLUDE_DIR glog/logging.h)

mark_as_advanced(GLOG_INCLUDE_DIR)
