/*
 * pam_oath.c - a PAM module for OATH one-time passwords
 * Copyright (C) 2009-2015 Simon Josefsson
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include "oath.h"
#include "ShsmApiUtils.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

/* Libtool defines PIC for shared objects */
#ifndef PIC
#define PAM_STATIC
#endif

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#define D(x) do {							\
    printf ("[%s:%s(%d)] ", __FILE__, __FUNCTION__, __LINE__);		\
    printf x;								\
    printf ("\n");							\
  } while (0)
#define DBG(x) if (cfg.debug) { D(x); }

#ifndef PAM_EXTERN
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
#endif

#define MIN_OTP_LEN 6
#define MAX_OTP_LEN 8

#define PROTOCOL_ENIGMABRIDE 1

struct cfg
{
  int debug;
  int alwaysok;
  int try_first_pass;
  int use_first_pass;
  char *usersfile;
  unsigned digits;
  unsigned window;
  int protocol;
};

/* Declaration */
int eb_oath_authenticate(const char *usersfile, const char *username, const char *otp,
        size_t window, const char *passwd, time_t * last_otp);
int eb_verify_pass(const char* password, const char* handle);
int eb_parse_usersfile(const char *username, const char *otp, size_t window, const char *passwd, time_t * last_otp,
        FILE * infh, char **lineptr, size_t * n, uint64_t * new_moving_factor, size_t * skipped_users);




static void
parse_cfg (int flags, int argc, const char **argv, struct cfg *cfg)
{
  int i;

  cfg->debug = 0;
  cfg->alwaysok = 0;
  cfg->try_first_pass = 0;
  cfg->use_first_pass = 0;
  cfg->usersfile = NULL;
  cfg->digits = -1;
  cfg->window = 5;
  cfg->protocol = 0;

  for (i = 0; i < argc; i++)
    {
      if (strcmp (argv[i], "debug") == 0)
	cfg->debug = 1;
      if (strcmp (argv[i], "alwaysok") == 0)
	cfg->alwaysok = 1;
      if (strcmp (argv[i], "try_first_pass") == 0)
	cfg->try_first_pass = 1;
      if (strcmp (argv[i], "use_first_pass") == 0)
	cfg->use_first_pass = 1;
      if (strncmp (argv[i], "usersfile=", 10) == 0)
	cfg->usersfile = (char *) argv[i] + 10;
      if (strncmp (argv[i], "digits=", 7) == 0)
	cfg->digits = atoi (argv[i] + 7);
      if (strncmp (argv[i], "window=", 7) == 0)
	cfg->window = atoi (argv[i] + 7);
      if (strncmp(argv[i], "protocol=", 9) == 0){
          // only enigmabridge is valid protocol
          if (strcmp(argv[i]+9, "enigmabridge") == 0){
              cfg->protocol = PROTOCOL_ENIGMABRIDE;
          }         
      }         
          
    }

  if (cfg->digits != 6 && cfg->digits != 7 && cfg->digits != 8)
    {
      if (cfg->digits != -1)
	D (("only 6, 7, and 8 OTP lengths are supported: invalid value %d",
	    cfg->digits));
      cfg->digits = 0;
    }

  if (cfg->debug)
    {
      D (("called."));
      D (("flags %d argc %d", flags, argc));
      for (i = 0; i < argc; i++)
	D (("argv[%d]=%s", i, argv[i]));
      D (("debug=%d", cfg->debug));
      D (("alwaysok=%d", cfg->alwaysok));
      D (("try_first_pass=%d", cfg->try_first_pass));
      D (("use_first_pass=%d", cfg->use_first_pass));
      D (("usersfile=%s", cfg->usersfile ? cfg->usersfile : "(null)"));
      D (("digits=%d", cfg->digits));
      D (("window=%d", cfg->window));
      D (("protocol=%d", cfg->protocol));
    }
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
  int retval, rc;
  const char *user = NULL;
  const char *password = NULL;
  char otp[MAX_OTP_LEN + 1];
  int password_len = 0;
  struct pam_conv *conv;
  struct pam_message *pmsg[1], msg[1];
  struct pam_response *resp;
  int nargs = 1;
  struct cfg cfg;
  char *query_prompt = NULL;
  char *onlypasswd = strdup ("");	/* empty passwords never match */

  if (!onlypasswd)
    {
      retval = PAM_BUF_ERR;
      goto done;
    }

  parse_cfg (flags, argc, argv, &cfg);

  retval = pam_get_user (pamh, &user, NULL);
  if (retval != PAM_SUCCESS)
    {
      DBG (("get user returned error: %s", pam_strerror (pamh, retval)));
      goto done;
    }
  DBG (("get user returned: %s", user));

  if (cfg.try_first_pass || cfg.use_first_pass)
    {
      retval = pam_get_item (pamh, PAM_AUTHTOK, (const void **) &password);
      if (retval != PAM_SUCCESS)
	{
	  DBG (("get password returned error: %s",
		pam_strerror (pamh, retval)));
	  goto done;
	}
      DBG (("get password returned: %s", password));
    }

  if (cfg.use_first_pass && password == NULL)
    {
      DBG (("use_first_pass set and no password, giving up"));
      retval = PAM_AUTH_ERR;
      goto done;
    }

  rc = oath_init ();
  if (rc != OATH_OK)
    {
      DBG (("oath_init() failed (%d)", rc));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  if (password == NULL)
    {
      retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
      if (retval != PAM_SUCCESS)
	{
	  DBG (("get conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      pmsg[0] = &msg[0];
      {
	const char *query_template = "One-time password (OATH) for `%s': ";
	size_t len = strlen (query_template) + strlen (user);
	size_t wrote;

	query_prompt = (char*) malloc (len);
	if (!query_prompt)
	  {
	    retval = PAM_BUF_ERR;
	    goto done;
	  }

	wrote = snprintf (query_prompt, len, query_template, user);
	if (wrote < 0 || wrote >= len)
	  {
	    retval = PAM_BUF_ERR;
	    goto done;
	  }

	msg[0].msg = query_prompt;
      }
      msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
      resp = NULL;

      retval = conv->conv (nargs, (const struct pam_message **) pmsg,
			   &resp, conv->appdata_ptr);

      free (query_prompt);
      query_prompt = NULL;

      if (retval != PAM_SUCCESS)
	{
	  DBG (("conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      DBG (("conv returned: %s", resp->resp));

      password = resp->resp;
    }

  if (password)
    password_len = strlen (password);
  else
    {
      DBG (("Could not read password"));
      retval = PAM_AUTH_ERR;
      goto done;
    }

  if (password_len < MIN_OTP_LEN)
    {
      DBG (("OTP too short: %s", password));
      retval = PAM_AUTH_ERR;
      goto done;
    }
  else if (cfg.digits != 0 && password_len < cfg.digits)
    {
      DBG (("OTP shorter than digits=%d: %s", cfg.digits, password));
      retval = PAM_AUTH_ERR;
      goto done;
    }
  else if (cfg.digits == 0 && password_len > MAX_OTP_LEN)
    {
      DBG (("OTP too long (and no digits=): %s", password));
      retval = PAM_AUTH_ERR;
      goto done;
    }
  else if (cfg.digits != 0 && password_len > cfg.digits)
    {
      free (onlypasswd);
      onlypasswd = strdup (password);
      if (!onlypasswd)
        {
          retval = PAM_BUF_ERR;
          goto done;
        }

      /* user entered their system password followed by generated OTP? */

      onlypasswd[password_len - cfg.digits] = '\0';

      DBG (("Password: %s ", onlypasswd));

      memcpy (otp, password + password_len - cfg.digits, cfg.digits);
      otp[cfg.digits] = '\0';

      retval = pam_set_item (pamh, PAM_AUTHTOK, onlypasswd);
      if (retval != PAM_SUCCESS)
	{
	  DBG (("set_item returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}
    }
  else
    {
      strcpy (otp, password);
      password = NULL;
    }

  DBG (("OTP: %s", otp ? otp : "(null)"));

  {
    time_t last_otp;    
    if (cfg.protocol == PROTOCOL_ENIGMABRIDE){
        DBG(("Enigmabridge protocol in use!!"));
        rc = eb_oath_authenticate(cfg.usersfile,
                    user,
                    otp, cfg.window, onlypasswd, &last_otp);
    } else {
        rc = oath_authenticate_usersfile(cfg.usersfile,
                    user,
                    otp, cfg.window, onlypasswd, &last_otp);
    }
    
    DBG (("authenticate rc %d (%s: %s) last otp %s", rc,
	  oath_strerror_name (rc) ? oath_strerror_name (rc) : "UNKNOWN",
	  oath_strerror (rc), ctime (&last_otp)));
  }

  if (rc != OATH_OK)
    {
      DBG (("One-time password not authorized to login as user '%s'", user));
      retval = PAM_AUTH_ERR;
      goto done;
    }

  retval = PAM_SUCCESS;

done:
  oath_done ();
  free (query_prompt);
  free (onlypasswd);
  if (cfg.alwaysok && retval != PAM_SUCCESS)
    {
      DBG (("alwaysok needed (otherwise return with %d)", retval));
      retval = PAM_SUCCESS;
    }
  DBG (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_oath_modstruct = {
  "pam_oath",
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};

#endif


/* EnigmaBridge stuff */
static const char *whitespace = " \t\r\n";
#define TIME_FORMAT_STRING "%Y-%m-%dT%H:%M:%SL"

int
eb_oath_authenticate(const char *usersfile,
        const char *username,
        const char *otp,
        size_t window,
        const char *passwd, time_t * last_otp) {    

    D(("oath_authenticate_enigmabridge"));
    
    FILE *infh;
    char *line = NULL;
    size_t n = 0;
    uint64_t new_moving_factor;
    int rc;
    size_t skipped_users;

    infh = fopen(usersfile, "r");
    if (!infh)
        return OATH_NO_SUCH_FILE;

    rc = eb_parse_usersfile(username, otp, window, passwd, last_otp,
            infh, &line, &n, &new_moving_factor, &skipped_users);

//    if (rc == OATH_OK) {
//        char timestamp[30];
//        size_t max = sizeof (timestamp);
//        struct tm now;
//        time_t t;
//        size_t l;
//        mode_t old_umask;
//
//        if (time(&t) == (time_t) - 1)
//            return OATH_TIME_ERROR;
//
//        if (localtime_r(&t, &now) == NULL)
//            return OATH_TIME_ERROR;
//
//        l = strftime(timestamp, max, TIME_FORMAT_STRING, &now);
//        if (l != 20)
//            return OATH_TIME_ERROR;
//
//        old_umask = umask(~(S_IRUSR | S_IWUSR));
//
//        rc = eb_update_usersfile(usersfile, username, otp, infh,
//                &line, &n, timestamp, new_moving_factor,
//                skipped_users);
//
//        umask(old_umask);
//    }

    free(line);
    fclose(infh);

    return rc;
}

int eb_parse_usersfile(const char *username,
        const char *otp,
        size_t window,
        const char *passwd,
        time_t * last_otp,
        FILE * infh,
        char **lineptr, size_t * n, uint64_t * new_moving_factor,
        size_t * skipped_users) {
    int bad_password = 0;

    *skipped_users = 0;

    while (getline(lineptr, n, infh) != -1) {
        char *saveptr;
        char *p = strtok_r(*lineptr, whitespace, &saveptr);
        D(("p1=%s", p));
        unsigned digits, totpstepsize;
        char secret[32];
        size_t secret_length = sizeof (secret);
        uint64_t start_moving_factor = 0;
        int rc = 0;
        char *prev_otp = NULL;

        if (p == NULL)
            continue;

        /* Read token type */
        if (strcmp(p, "HOTP/T30") == 0 || strcmp(p, "HOTP/T30/6") == 0) {
            D(("p2=%s", p));
            // only HOTP with 6 digits and time step 30 seconds is supported
            digits = 6;
            totpstepsize = 30;
        } else {
            // otherwise try another line
            continue;
        }       
            

        /* Read username */
        p = strtok_r(NULL, whitespace, &saveptr);
        if (p == NULL || strcmp(p, username) != 0)
            continue;
        D(("p3=%s", p));

        /* Read password. */
        p = strtok_r(NULL, whitespace, &saveptr);
        D(("p4=%s", p));
        if (passwd) {
            if (p == NULL)
                continue;
            if (strcmp(p, "-") == 0) {
                if (*passwd != '\0') {
                    bad_password = 1;
                    rc = OATH_BAD_PASSWORD;
                }
            } else if (strcmp(p, "+") == 0) {
                /* Externally verified. */
            } else if (strcmp(p, passwd) != 0) {
                bad_password = 1;
                rc = OATH_BAD_PASSWORD;
            }
            if (rc == OATH_BAD_PASSWORD) {
                (*skipped_users)++;
                continue;
            }
            bad_password = 0;
        }

        /* Read handle - p contains string handle */
        p = strtok_r(NULL, whitespace, &saveptr);
        D(("p5=%s", p));
        if (p == NULL)
            continue;
        
        rc = eb_verify_pass(otp, p);
        
//        rc = oath_hex2bin(p, secret, &secret_length);
//        if (rc != OATH_OK)
//            return rc;        
        
//        if (prev_otp && strcmp(prev_otp, otp) == 0)
//            return OATH_REPLAYED_OTP;

//        if (totpstepsize == 0)
//            rc = oath_hotp_validate(secret, secret_length,
//                start_moving_factor, window, otp);
//        else if (prev_otp) {
//            int prev_otp_pos, this_otp_pos, tmprc;
//            rc = oath_totp_validate2(secret, secret_length,
//                    time(NULL), totpstepsize, 0, window,
//                    &this_otp_pos, otp);
//            if (rc == OATH_INVALID_OTP) {
//                (*skipped_users)++;
//                continue;
//            }
//            if (rc < 0)
//                return rc;
//            tmprc = oath_totp_validate2(secret, secret_length,
//                    time(NULL), totpstepsize, 0, window,
//                    &prev_otp_pos, prev_otp);
//            if (tmprc >= 0 && prev_otp_pos >= this_otp_pos)
//                return OATH_REPLAYED_OTP;
//        } else
//            rc = oath_totp_validate(secret, secret_length,
//                time(NULL), totpstepsize, 0, window, otp);
//        if (rc == OATH_INVALID_OTP) {
//            (*skipped_users)++;
//            continue;
//        }
        
        
        
        if (rc < 0)
            return rc;
//        *new_moving_factor = start_moving_factor + rc;
        return OATH_OK;
    }

    if (*skipped_users) {
        if (bad_password)
            return OATH_BAD_PASSWORD;
        else
            return OATH_INVALID_OTP;
    }

    return OATH_UNKNOWN_USER;
}

int eb_verify_pass(const char* password, const char* handle){    
//    return OATH_OK;
    
    char hostname[] = "127.0.0.1";
    int port = 11111;
    
    if (hostname == NULL) {
        fprintf(stderr, "Error: Hostname cannot be null for SHSM operation.\n");
        return OATH_CRYPTO_ERROR;
        //       TODO return OATH_NETWORK_INVALID_HOSTNAME; 
    }

    //
    // Do the request, process response.
    //
    int requestStatus = 0;
    std::string jsonRequest = ShsmApiUtils::getRequestForOtpVerification(password, handle);
    D(("requestForOtpVerification=%s", jsonRequest.c_str()));    

    std::string jsonResponse = ShsmApiUtils::request(hostname, port, jsonRequest, &requestStatus);
    if (requestStatus < 0) {
        fprintf(stderr, "Error: Request was not successful, error code: %d.\n", requestStatus);
        return OATH_CRYPTO_ERROR;
        //       TODO return OATH_NETWORK_ERROR;
    }

    // Parse response, extract result, return it.
    Json::Value root; // 'root' will contain the root value after parsing.
    Json::Reader reader;
    bool parsedSuccess = reader.parse(jsonResponse, root, false);
    D(("responseForOtpVerification=%s", jsonResponse.c_str()));    
    if (!parsedSuccess) {
        fprintf(stderr, "Could not read data from socket.\n");
        return OATH_CRYPTO_ERROR;
    }

    // Check status code.
    int resStatus = ShsmApiUtils::getStatus(root);
    if (resStatus != 9000) {
        fprintf(stderr, "Result code is not 9000, cannot decrypt. Code: %d\n", resStatus);
        return OATH_CRYPTO_ERROR;
    }
    
    // otherwise everything correct
    return OATH_OK;

//    // Write certificate to a given file.
//    std::string crt = root["result"].asString();
//    ssize_t crtLen = ShsmApiUtils::getJsonByteArraySize(crt);
//    if (crtLen <= 0) {
//        fprintf(stderr, "Certificate length is invalid: %ld.\n", (long) crtLen);
//        return 1;
//    }
//
//    Botan::byte * crtByteArray = (Botan::byte *) malloc(sizeof (Botan::byte) * crtLen);
//    if (crtByteArray == NULL) {
//        fprintf(stderr, "Unable to allocate memory for pubey.\n");
//        return 1;
//    }
//
//    int res = ShsmApiUtils::hexToBytes(crt, crtByteArray, (size_t) crtLen);
//    fprintf(stderr, "PublicKey size: %ld, res: %d \n", (long) crtLen, res);
//
//    std::ofstream crtFile(crtPath);
//    crtFile.write((char *) crtByteArray, crtLen);
//    crtFile.close();
//
//    return 0;
}