find_path(APR_INC
        NAMES apr.h
        HINTS
        /usr/include/apr-1
        /usr/include/apr-1.0
        /usr/local/include/apr-1
        /usr/local/include/apr-1.0)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(APR DEFAULT_MSG APR_INC)
