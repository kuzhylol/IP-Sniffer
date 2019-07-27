AC_INIT([IP-Sniffer], [1.0])
AC_PROG_CC
AC_CHECK_LIB([glib-2.0], [g_free], [], [AC_MSG_ERROR([glib needed])])
AC_CHECK_LIB([pcap], [pcap_lookupnet], [], [AC_MSG_ERROR([libpcap-dev needed])])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT