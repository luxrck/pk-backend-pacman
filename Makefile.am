AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"PackageKit-Pacman\"

helperdir = $(datadir)/PackageKit/helpers/pacman
dist_helper_DATA = 	\
	alpmBackend.py	\
	pacman.py		\
	groups.json

plugindir = $(PK_PLUGIN_DIR)
plugin_LTLIBRARIES = libpk_backend_pacman.la
libpk_backend_portage_la_SOURCES = pk-backend-pacman.c
libpk_backend_portage_la_LIBADD = $(PK_PLUGIN_LIBS)
libpk_backend_portage_la_LDFLAGS = -module -avoid-version
libpk_backend_portage_la_CFLAGS = $(PK_PLUGIN_CFLAGS) $(WARNINGFLAGS_C)

install-data-hook:
	chmod a+rx $(DESTDIR)$(helperdir)/*.py

clean-local :
	rm -f *~
	rm -f *.pyc

-include $(top_srcdir)/git.mk
