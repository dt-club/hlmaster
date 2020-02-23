// info.c
#include "info.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>

#define MAX_KV_LEN 127
/*
===============
Info_ValueForKey

Searches the string for the given
key and returns the associated value, or an empty string.
===============
*/
const char *Info_ValueForKey(const char *s, const char *key)
{
	char pkey[128];
	static char value[4][128]; // use two buffers so compares
							   // work without stomping on each other
	static int valueindex;
	char *o;

	valueindex = (valueindex + 1) % 4;
	if (*s == '\\')
		s++;
	while (1)
	{
		int nCount;

		nCount = 0;
		o = pkey;
		while (nCount < MAX_KV_LEN && *s != '\\')
		{
			if (!*s)
				return "";
			*o++ = *s++;
			nCount++;
		}
		*o = 0;
		s++;

		nCount = 0;
		o = value[valueindex];

		while (nCount < MAX_KV_LEN && *s != '\\' && *s)
		{
			if (!*s)
				return "";
			*o++ = *s++;
			nCount++;
		}
		*o = 0;

		if (!strcmp(key, pkey))
			return value[valueindex];

		if (!*s)
			return "";
		s++;
	}
}
void Info_RemoveKey(char *s, const char *key)
{
	char *start;
	char pkey[128];
	char value[128];
	char *o;

	int cmpsize = strlen(key);

	if (cmpsize > MAX_KV_LEN)
		cmpsize = MAX_KV_LEN;

	if (strstr(key, "\\"))
	{
		return;
	}

	while (1)
	{
		int nCount;

		start = s;
		if (*s == '\\')
			s++;
		nCount = 0;
		o = pkey;
		while (nCount < MAX_KV_LEN && *s != '\\')
		{
			if (!*s)
				return;
			*o++ = *s++;
			nCount++;
		}
		*o = 0;
		s++;

		nCount = 0;
		o = value;
		while (nCount < MAX_KV_LEN && *s != '\\' && *s)
		{
			if (!*s)
				return;
			*o++ = *s++;
			nCount++;
		}
		*o = 0;

		if (!strncmp(key, pkey, cmpsize))
		{
			strcpy(start, s); // remove this part
			return;
		}

		if (!*s)
			return;
	}
}

void Info_RemovePrefixedKeys(char *start, char prefix)
{
	char *s;
	char pkey[128];
	char value[128];
	char *o;

	s = start;

	while (1)
	{
		int nCount;

		if (*s == '\\')
			s++;
		nCount = 0;
		o = pkey;
		while (nCount < MAX_KV_LEN && *s != '\\')
		{
			if (!*s)
				return;
			*o++ = *s++;
			nCount++;
		}
		*o = 0;
		s++;

		nCount = 0;
		o = value;
		while (nCount < MAX_KV_LEN && *s != '\\' && *s)
		{
			if (!*s)
				return;
			*o++ = *s++;
			nCount++;
		}
		*o = 0;

		if (pkey[0] == prefix)
		{
			Info_RemoveKey(start, pkey);
			s = start;
		}

		if (!*s)
			return;
	}
}

char *Info_FindLargestKey(char *s)
{
	char key[128];
	char value[128];
	char *o;
	int l;
	static char largest_key[128];
	int largest_size = 0;

	*largest_key = 0;

	if (*s == '\\')
		s++;
	while (*s)
	{
		int nCount;
		int size = 0;

		nCount = 0;
		o = key;
		while (nCount < MAX_KV_LEN && *s && *s != '\\')
		{
			*o++ = *s++;
			nCount++;
		}

		l = o - key;
		*o = 0;
		size = strlen(key);

		if (!*s)
		{
			return largest_key;
		}

		nCount = 0;
		o = value;
		s++;
		while (nCount < MAX_KV_LEN && *s && *s != '\\')
		{
			*o++ = *s++;
			nCount++;
		}
		*o = 0;

		if (*s)
			s++;

		size += strlen(value);

		if ((size > largest_size))
		{
			largest_size = size;
			strncpy(largest_key, key, sizeof(largest_key) - 1);
			largest_key[sizeof(largest_key) - 1] = 0;
		}
	}

	return largest_key;
}

void Info_SetValueForStarKey(char *s, const char *key, const char *value, int maxsize)
{
	char newVal[1024], *v;
	int c;
	char *largekey;

	if (strstr(key, "\\") || strstr(value, "\\"))
	{
		return;
	}

	if (strstr(key, "..") || strstr(value, ".."))
	{
		return;
	}

	if (strstr(key, "\"") || strstr(value, "\""))
	{
		return;
	}

	if (strlen(key) > MAX_KV_LEN || strlen(value) > MAX_KV_LEN)
	{
		return;
	}

	Info_RemoveKey(s, key);
	if (!value || !strlen(value))
		return;

	snprintf(newVal, sizeof(newVal), "\\%s\\%s", key, value);

	if ((int)(strlen(newVal) + strlen(s)) >= maxsize)
	{
		return;
	}

	// only copy ascii values
	s += strlen(s);
	v = newVal;
	while (*v)
	{
		c = (unsigned char)*v++;
		// client only allows highbits on name
		if (strcasecmp(key, "name") != 0)
		{
			c &= 127;
			if (c < 32 || c > 127)
				continue;
			// auto lowercase team
			if (strcasecmp(key, "team") == 0)
				c = tolower(c);
		}
		if (c > 13)
			*s++ = c;
	}
	*s = 0;
}

void Info_SetValueForKey(char *s, const char *key, const char *value, int maxsize)
{
	if (key[0] == '*')
	{
		return;
	}

	Info_SetValueForStarKey(s, key, value, maxsize);
}