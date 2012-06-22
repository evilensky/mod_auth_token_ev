/* Copyright 2002-2005 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Written by Mikael Johansson <mikael AT synd DOT info>
 * Some code by David Aves <david.alves AT gmx DOT fr>
 *
 * This module uses token based authentication to secure files and
 * prevent deep-linking.
 *
 * Implementation ideas were taken from mod_secdownload for LIGHTTPD
 *  - http://www.lighttpd.net/documentation/secdownload.html
 */

#include "apr_strings.h"
#include "apr_md5.h"
#include "apr_time.h"
#include "apr_lib.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

typedef struct {
	char *secret;
	char *prefix;
	unsigned int prefix_len;
	int timeout;
	int checkip;
        int globaltoken;
} auth_token_config_rec;

static void *create_auth_token_dir_config(apr_pool_t *p, char *d)
{
	auth_token_config_rec *conf = apr_palloc(p, sizeof(*conf));

	conf->secret = NULL;
	conf->prefix = NULL;
	conf->prefix_len = 0;
	conf->timeout = 60;		/* 60 second timeout per default */
    conf->checkip = 0;		/* Disabling IP check by default */
    conf->globaltoken = 0;          /* Disabled global token by default */ 
	return conf;
}

static const char *auth_token_set_prefix_slot(cmd_parms *cmd, void *config, const char *arg)
{
	int len = strlen(arg);
	auth_token_config_rec *conf = (auth_token_config_rec*)config;

	if (arg[len - 1] != '/') {
		ap_set_string_slot(cmd, config, apr_pstrcat(cmd->pool, arg, '/'));
		conf->prefix_len = len + 1;
	}
	else {
		ap_set_string_slot(cmd, config, arg);
		conf->prefix_len = len;
	}

	return NULL;
}

static const command_rec auth_token_cmds[] =
{
	AP_INIT_TAKE1("AuthTokenSecret", ap_set_string_slot,
	 (void *)APR_OFFSETOF(auth_token_config_rec, secret),
	 ACCESS_CONF, "secret key to authenticate against"),
	AP_INIT_TAKE1("AuthTokenPrefix", auth_token_set_prefix_slot,
	 (void *)APR_OFFSETOF(auth_token_config_rec, prefix),
	 ACCESS_CONF, "prefix uri to file storage directory"),
	AP_INIT_TAKE1("AuthTokenTimeout", ap_set_int_slot,
	 (void *)APR_OFFSETOF(auth_token_config_rec, timeout),
	 ACCESS_CONF, "time to live for tokens"),
	AP_INIT_FLAG("AuthTokenLimitByIp", ap_set_flag_slot,
	 (void *)APR_OFFSETOF(auth_token_config_rec, checkip), 
	 ACCESS_CONF, "enable or disable ip checking"),
        AP_INIT_FLAG("GlobalToken", ap_set_flag_slot,
         (void *)APR_OFFSETOF(auth_token_config_rec, globaltoken),
         ACCESS_CONF, "Tokens are global and good for any file in the location within the time window."),
	{NULL}
};

module AP_MODULE_DECLARE_DATA auth_token_module;

/*
 * Converts 8 hex digits to a timestamp
 */
static unsigned int auth_token_hex2sec(const char *x)
{
	int i, ch;
	unsigned int j;

	for (i = 0, j = 0; i < 8; i++) {
		ch = x[i];
		j <<= 4;

		if (apr_isdigit(ch))
			j |= ch - '0';
		else if (apr_isupper(ch))
			j |= ch - ('A' - 10);
		else
			j |= ch - ('a' - 10);
	}

	return j;
}

/*
 * Converts a binary string to hex
 */
static void auth_token_bin2hex(char *result, const char *x, int len)
{
	int i, ch;
	for (i = 0; i < len; i++) {
		ch = (x[i] & 0xF0) >> 4;
		if (ch < 10)
			result[i * 2] = '0' + ch;
		else
			result[i * 2] = 'A' + (ch - 10);

		ch = x[i] & 0x0F;
		if (ch < 10)
			result[i * 2 + 1] = '0' + ch;
		else
			result[i * 2 + 1] = 'A' + (ch - 10);
	}
}

static int authenticate_token(request_rec *r)
{
	const char *usertoken, *timestamp, *path, *remoteip;
	unsigned char digest[APR_MD5_DIGESTSIZE];
	char token[APR_MD5_DIGESTSIZE * 2];
	auth_token_config_rec *conf;
	apr_md5_ctx_t context;

	conf = ap_get_module_config(r->per_dir_config, &auth_token_module);
	
	/* Get the remote IP , forcing to get an IP instead DNS record*/
	if (conf->checkip) {
		remoteip = ap_get_remote_host(r->connection, NULL, REMOTE_NAME, NULL);
    	if(NULL == remoteip)
		{	
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_auth_token: request from ip FAILED." );
			return DECLINED;
		}		
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_auth_token: request from ip %s", remoteip );
	}


	/* check if the request uri is to be protected */
	if (conf->prefix == NULL || strncmp(r->uri, conf->prefix, conf->prefix_len)) {
		return DECLINED;
	}

	/* <prefix> <32-byte-token> "/" <8-byte-timestamp> "/" */
	if (strlen(r->uri) < conf->prefix_len + 32 + 1 + 8 + 1) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_auth_token: malformed or nonexistent token");
		return HTTP_UNAUTHORIZED;
	}

	/* mark token, timestamp and relative path components */
	usertoken = r->uri + conf->prefix_len;
	timestamp = r->uri + conf->prefix_len + 32 + 1;
	path = r->uri + conf->prefix_len + 32 + 1 + 8;

	/* check if token has expired */
	if ((unsigned int)apr_time_sec(apr_time_now()) > auth_token_hex2sec(timestamp) + conf->timeout) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_auth_token: token expired at %u, now is %u",
			auth_token_hex2sec(timestamp) + conf->timeout, (unsigned int)apr_time_sec(apr_time_now()));
		return HTTP_GONE;
	}

	/* create md5 token of secret + path + timestamp */
	apr_md5_init(&context);
	apr_md5_update(&context, (unsigned char *) conf->secret, strlen(conf->secret));
	if (conf->globaltoken == 0) {
	apr_md5_update(&context, (unsigned char *) path, strlen(path));
	}
	apr_md5_update(&context, (unsigned char *) timestamp, 8);

	if (conf->checkip)
		apr_md5_update(&context, (unsigned char *) remoteip, strlen(remoteip));
	apr_md5_final(digest, &context);

	/* compare hex encoded token and user provided token */
	auth_token_bin2hex(token, (const char *)digest, APR_MD5_DIGESTSIZE);

	if (strncasecmp(token, usertoken, APR_MD5_DIGESTSIZE * 2) == 0) {
		/* remove token and timestamp from uri */
		memmove(r->uri + conf->prefix_len - 1, path, strlen(path) + 1);
		r->filename = apr_pstrdup(r->pool, r->uri);

		/* allow other modules to run their hooks */
		return DECLINED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_auth_token: failed token auth (got '%s', expected '%s', uri '%s')",
		apr_pstrndup(r->pool, usertoken, 32), apr_pstrndup(r->pool, token, 32), r->uri);
	return HTTP_FORBIDDEN;
}

static void register_hooks(apr_pool_t *p)
{
	static const char * const aszPost[] = { "mod_alias.c", NULL };
	ap_hook_translate_name(authenticate_token, NULL, aszPost, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_token_module =
{
	STANDARD20_MODULE_STUFF,
	create_auth_token_dir_config,	/* dir config creater */
	NULL,							/* dir merger --- default is to override */
	NULL,							/* server config */
	NULL,							/* merge server config */
	auth_token_cmds,				/* command apr_table_t */
	register_hooks					/* register hooks */
};
