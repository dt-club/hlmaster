#ifndef BASETYPES_H
#define BASETYPES_H
#ifdef _WIN32
#pragma once
#endif

#include "archtypes.h"

#ifndef NULL
#define NULL 0
#endif

#ifndef FALSE
#define FALSE 0
#define TRUE (!FALSE)
#endif

typedef int BOOL;
typedef int qboolean;
typedef unsigned long ULONG;
typedef unsigned char BYTE;
typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef unsigned int DWORD;

typedef float vec_t;

#ifndef __cplusplus
#define true TRUE
#define false FALSE
#endif

#endif