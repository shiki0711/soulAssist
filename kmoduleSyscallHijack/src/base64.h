
#ifndef __BASE64_H__
#define __BASE64_H__

extern int base64_encode(const char *in, int len, char *out);
extern int base64_decode(const char *in, int len, char *out);

#endif
