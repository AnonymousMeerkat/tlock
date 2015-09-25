/*
  Copyright (c) 2015 Anonymous Meerkat

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <shadow.h>
#include <unistd.h>
#include <termios.h>
#include <term.h>
#include <math.h>
#include <crypt.h>
#include <signal.h>
#include <ctype.h>
#include <sys/ioctl.h>

int term_width, term_height;

void
tl_get_size()
{
  struct winsize w;
  ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

  term_height = w.ws_row;
  term_width = w.ws_col;
}

char*
tl_getenv(char* variable, char* value)
{
  char* ret = getenv(variable);
  if (ret && *ret)
    return ret;
  else
    return value;
}


int
tl_strlen(char* str)
{
  int ret;

  int in_escape = 0;

  for (ret = 0; (*str); str++)
    {
      if (*str == '\033')
        {
          in_escape = 1;
          continue;
        }

      if (in_escape)
        {
          if (isalpha(*str))
            {
              in_escape = 0;
            }

          continue;
        }

      /* Ugly(?) UTF-8 handling */
      if ((unsigned char)*str >= 0xc0)
        {
          if ((unsigned char)*str >= 0xe0)
            {
              if ((unsigned char)*str >= 0xf0)
                {
                  if ((unsigned char)*str >= 0xf8)
                    {
                      if ((unsigned char)*str >= 0xfc)
                        {
                          str++;
                        }
                      str++;
                    }
                  str++;
                }
              str++;
            }
          str++;
        }

      ret++;
    }

  return ret;
}


int
tl_hmiddle(int len)
{
  return (int)(ceil((term_width - len) / 2.));
}

void
tl_kill(void)
{
  printf("\033[K");
}

void
tl_pos(int x, int y)
{
  printf("\033[%d;%dH", y, x);
}


void
tl_showpassword(int num, char* passchar, int passchar_len)
{
  int size = num * passchar_len;
  int i;

  tl_pos(0, term_height / 2 + 1);
  tl_kill();
  tl_pos(tl_hmiddle(size), term_height / 2 + 1);

  for (i = 0; i < num; i++)
    {
      fputs(passchar, stdout);
    }

  fflush(stdout);
}

void
tl_getpassword(char* password, char* passchar)
{
  int c;

  struct termios old, new;

  int passchar_len = 0;

  int password_pos = 0;
  password[0] = 0;

  tcgetattr(STDIN_FILENO, &old);
  new = old;
  new.c_lflag &= ~(ICANON|ECHO);
  new.c_cc[VMIN] = 1;
  new.c_cc[VTIME] = 0;

  passchar_len = tl_strlen(passchar);

  tl_showpassword(0, "", 0);

  while (1)
    {
      tcsetattr(STDIN_FILENO, TCSANOW, &new);
      c = getchar();
      tcsetattr(STDIN_FILENO, TCSANOW, &old);

      /* Backspace */
      if ((c == 127 || c == 8))
        {
          if (password_pos > 0)
            {
              password[--password_pos] = 0;

              tl_showpassword(password_pos, passchar, passchar_len);
            }

          continue;
        }

      if (c == '\n')
        break;

      password[password_pos++] = c;
      password[password_pos] = 0;

      tl_showpassword(password_pos, passchar, passchar_len);
    }
}


int
tl_checkpassword(char* password, char* shadow)
{
  return !strcmp(crypt(password, shadow), shadow);
}


int
main(int argc, char** argv)
{
  uid_t uid = getuid();
  struct passwd* pw;
  struct spwd* spw;
  char password[256];

  char* display_username;
  char* passchar;

  /*** Ignore signals ***/

  signal(SIGQUIT, SIG_IGN);
  signal(SIGINT,  SIG_IGN);
  signal(SIGTSTP, SIG_IGN);
  signal(SIGHUP,  SIG_IGN);

  /*** Setup passwd-related things ***/

  pw = getpwuid(uid);
  if (!pw)
    {
      fprintf(stderr, "Unable to get passwd entry for uid %d\n", uid);
      return 1;
    }

  if (setreuid(0, 0))
    {
      perror("Unable to setuid(0)");
      return 3;
    }

  spw = getspnam(pw->pw_name);
  if (!spw)
    {
      fprintf(stderr, "Unable to get shadow entry for user '%s'\n",
              pw->pw_name);
      return 2;
    }

  if (setreuid(uid, uid))
    {
      perror("Unable to setuid back");
      return 4;
    }


  /*** Configuration ***/

  display_username = tl_getenv("TL_USERNAME", pw->pw_name);
  passchar = tl_getenv("TL_PASS_CHAR", " *");


  /*** Display ***/

  setupterm((char*)0, 1, (int*)0);

  putp(enter_ca_mode);
  putp(cursor_invisible);

  tl_get_size();

  tl_pos(tl_hmiddle(tl_strlen(display_username)), term_height / 2 - 1);
  fputs(display_username, stdout);


  /* Get password */

  while (1)
    {
      tl_getpassword(password, passchar);

      if (tl_checkpassword(password, spw->sp_pwdp))
        break;
    }

  putp(cursor_normal);
  putp(exit_ca_mode);

  return 0;
}
