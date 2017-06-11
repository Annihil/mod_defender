find_path(APACHE_INC
        NAMES httpd.h
        HINTS
        /usr/include/apache2
        /usr/include
        /usr/local/include/apache2
        /usr/local/include/apache22
        /usr/local/include/apache24
        /usr/home/vlt-sys/Engine/include)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(APACHE DEFAULT_MSG APACHE_INC)
