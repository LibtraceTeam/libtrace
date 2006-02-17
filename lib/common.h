#ifndef COMMON_H
#define COMMON_H 1

#include "config.h"

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else /* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif /* __cplusplus */

#if HAVE_ZLIB
#  include <zlib.h>
#  define LIBTRACE_READ(file,buf,len) gzread(file,buf,len)
#  define LIBTRACE_FDOPEN(fd,mode) gzdopen(fd,mode)
#  define LIBTRACE_OPEN(path,mode) gzopen(path,mode)
#  define LIBTRACE_CLOSE(file) gzclose(file)
#  define LIBTRACE_WRITE(file,buf,len) gzwrite(file,buf,len)
#  define LIBTRACE_FILE gzFile*
#else
#  define LIBTRACE_READ(file,buf,len) read(file,buf,len)
#  define LIBTRACE_FDOPEN(fd,mode) dup(fd) 
#  define LIBTRACE_OPEN(path,mode) open(path,mode)
#  define LIBTRACE_CLOSE(file) close(file)
#  define LIBTRACE_WRITE(file,buf,len) write(file,buf,len)
#  define LIBTRACE_FILE int
#endif

#endif /* COMMON_H */
