/*
 * hotptool.c - command line tool for HOTP one-time passwords
 * Copyright (C) 2009  Simon Josefsson
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

#include "hotp.h"

#include <stdlib.h>
#include <string.h>

/* Gnulib. */
#include "progname.h"
#include "error.h"
#include "version-etc.h"

#include "hotptool_cmd.h"

const char version_etc_copyright[] =
  /* Do *not* mark this string for translation.  %s is a copyright
     symbol suitable for this locale, and %d is the copyright
     year.  */
  "Copyright %s %d Simon Josefsson.";

/* This feature is available in gcc versions 2.5 and later.  */
#if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
# define HOTP_ATTR_NO_RETRUN
#else
# define HOTP_ATTR_NO_RETRUN __attribute__ ((__noreturn__))
#endif

static void
usage (int status) HOTP_ATTR_NO_RETRUN;

static void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    fprintf (stderr, "Try `%s --help' for more information.\n",
	     program_name);
  else
    {
      cmdline_parser_print_help ();
      emit_bug_reporting_address ();
    }
  exit (status);
}

#define generate_otp_p(n) ((n) == 1)
#define validate_otp_p(n) ((n) == 2)

int
main (int argc, char *argv[])
{
  struct gengetopt_args_info args_info;
  char *secret;
  size_t secretlen;
  int rc;
  size_t window;
  uint64_t moving_factor;
  unsigned digits;
  char otp[10];
  size_t iter = 0;

  set_program_name (argv[0]);

  if (cmdline_parser (argc, argv, &args_info) != 0)
    return EXIT_FAILURE;

  if (args_info.version_given)
    {
      const char *p = PACKAGE_NAME;
      if (strcmp (hotp_check_version (NULL), PACKAGE_VERSION) != 0)
	p = PACKAGE_STRING;
      version_etc (stdout, "hotptool", p, hotp_check_version (NULL),
		   "Simon Josefsson", (char *) NULL);
      return EXIT_SUCCESS;
    }

  if (args_info.help_given)
    usage (EXIT_SUCCESS);

  if (args_info.inputs_num == 0)
    {
      cmdline_parser_print_help ();
      emit_bug_reporting_address ();
      return EXIT_SUCCESS;
    }

  secretlen = 1 + strlen (args_info.inputs[0]) / 2;
  secret = malloc (secretlen);

  rc = hotp_hex2bin (args_info.inputs[0], secret, &secretlen);
  if (rc != HOTP_OK)
    error (EXIT_FAILURE, 0, "Hex decoding of secret key failed");

  if (args_info.counter_orig)
    moving_factor = args_info.counter_arg;
  else
    moving_factor = 0;

  if (args_info.digits_orig)
    digits = args_info.digits_arg;
  else
    digits = 6;

  if (args_info.window_orig)
    window = args_info.window_arg;
  else
    window = 0;

  if (digits != 6 && digits != 7 && digits != 8)
    error (EXIT_FAILURE, 0, "Only digits 6, 7 and 8 are supported");

  do
    {
      rc = hotp_generate_otp (secret,
			      secretlen,
			      moving_factor + iter,
			      digits,
			      false,
			      HOTP_DYNAMIC_TRUNCATION,
			      otp);
      if (rc != HOTP_OK)
	error (EXIT_FAILURE, 0, "Generating one-time password failed: %d", rc);

      if (generate_otp_p (args_info.inputs_num))
	{
	  printf ("%s\n", otp);
	}
      else if (validate_otp_p (args_info.inputs_num))
	{
	  if (strcmp (otp, args_info.inputs[1]) == 0)
	    {
	      printf ("%ld\n", (long) iter);
	      return EXIT_SUCCESS;
	    }
	}
    }
  while (window - iter++ > 0);

  if (validate_otp_p (args_info.inputs_num))
    error (2, 0, "Password \"%s\" not found in range %ld .. %ld",
	   otp, (long) moving_factor, (long) moving_factor + window);

  return EXIT_SUCCESS;
}
