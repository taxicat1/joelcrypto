#ifndef ALPH__UTIL_H
#define ALPH__UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

bool is_lower(const char);
inline bool is_lower(const char c) {
	return c <= 'z' && c >= 'a';
}

bool is_upper(const char);
inline bool is_upper(const char c) {
	return c <= 'Z' && c >= 'A';
}

bool is_alpha(const char);
inline bool is_alpha(const char c) {
	return is_upper(c) || is_lower(c);
}

char to_upper(const char);
inline char to_upper(const char c) {
	return is_lower(c) ? c - ('a' - 'A') : c;
}

char to_lower(const char);
inline char to_lower(const char c) {
	return is_upper(c) ? c + ('a' - 'A') : c;
}

#endif