/*
 * Defines gettimeofday
 *
 * Based on timeval.h by Wu Yongwei
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "config.h"

/* AFAIK windows doesn't run on any Big Endian machines... If it does
 * winlibtrace will break! - MattB
 */
#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <time.h>

#ifndef _FILETIME_
#define _FILETIME_
typedef struct _FILETIME
{
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME;
#endif

#ifdef _MSC_VER
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

struct timezone {
	int tz_minuteswest; /* minutes W of Greenwich */
	int tz_dsttime;		/* type of dst correction */
};


int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    FILETIME        ft;
    LARGE_INTEGER   li;
    __int64         t;
    static int      tzflag;

    if (tv)
    {
        GetSystemTimeAsFileTime(&ft);
        li.LowPart  = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        t  = li.QuadPart;       /* In 100-nanosecond intervals */
        t -= EPOCHFILETIME;     /* Offset to the Epoch time */
        t /= 10;                /* In microseconds */
        tv->tv_sec  = (long)(t / 1000000);
        tv->tv_usec = (long)(t % 1000000);
    }

    if (tz)
    {
        if (!tzflag)
        {
            _tzset();
            tzflag++;
        }
        tz->tz_minuteswest = _timezone / 60;
        tz->tz_dsttime = _daylight;
    }

    return 0;
}
