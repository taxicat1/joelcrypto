#ifndef WIN_H
#define WIN_H

#if defined(_WIN32) || defined(_WIN64)
  #define strcasecmp _stricmp
  #define strncasecmp _strnicmp
#endif

#endif