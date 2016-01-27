dnl Configury specific to the libfabric udp provider

dnl Called to configure this provider
dnl
dnl Arguments:
dnl
dnl $1: action if configured successfully
dnl $2: action if not configured successfully
dnl
AC_DEFUN([FI_RDMX_CONFIGURE],[
	# Determine if we can support the rdmx provider
	rdmx_h_happy=0
	rdmx_shm_happy=0
	AS_IF([test x"$enable_sockets" != x"no"],
	      [AC_CHECK_HEADER([sys/socket.h], [rdmx_h_happy=1],
	                       [rdmx_h_happy=0])


	       # check if shm_open is already present
	       AC_CHECK_FUNC([shm_open],
			     [rdmx_shm_happy=1],
			     [rdmx_shm_happy=0])

	       # look for shm_open in librt if not already present
	       AS_IF([test $rdmx_shm_happy -eq 0],
		     [FI_CHECK_PACKAGE([rdmx_shm],
				[sys/mman.h],
				[rt],
				[shm_open],
				[],
				[],
				[],
				[rdmx_shm_happy=1],
				[rdmx_shm_happy=0])])
	      ])

	AS_IF([test $rdmx_h_happy -eq 1 && \
	       test $rdmx_shm_happy -eq 1], [$1], [$2])
])
