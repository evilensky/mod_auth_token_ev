## Define compiler debug flags
AM_CFLAGS = $(CXXDEBUGDEFINES)

## Define the source file for the module
noinst_SCRIPTS = mod_auth_token.so

mod_auth_token.so:
	$(APXS) $(APXS_CXX_OPTIONS) $(INCLUDES) -c mod_auth_token.c

## Define install targets
install: mod_auth_token.so
	$(APXS) -i -a mod_auth_token.la