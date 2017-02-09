#ifndef __UTIL_H__
#define __UTIL_H__

#define EXPORT_SYMBOL(...)

#define container_of(ptr, type, member) ({                      \
      const typeof( ((type *)0)->member ) *__mptr = (ptr);              \
      (type *)( (char *)__mptr - offsetof(type,member) );})

#endif
