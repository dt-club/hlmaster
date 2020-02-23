#ifndef INC_HASHLIST_H
#define INC_HASHLIST_H

typedef struct hashlist_s
{
	unsigned char md5[16];
	char szFileName[MAX_PATH];
	int nFileSize;
	int nTrueFileSize;
	time_t hCreateTime;
	unsigned char *pCache; // Cached representation

	struct hashlist_s *next;
} hashlist_t;

#endif
