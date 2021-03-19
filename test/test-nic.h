/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */
#ifndef __TRACELIVETESTER__H
#define __TRACELIVETESTER__H

#define WRAP_VALUE(min, max, value)                                            \
        ((value) > (max)                                                       \
             ? (value) - ((max) - (min) + 1)                                   \
             : ((value) < (min) ? (value) + ((max) - (min) + 1) : (value)))

/* IS_BETWEEN inclusive between and including min, max */
#define IS_BETWEEN_INC(min, max, value) ((min) <= (value) && (max) >= (value))

/* Operations on timespecs. */
#ifndef timespecclear
#define timespecclear(tsp) (tsp)->tv_sec = (tsp)->tv_nsec = 0
#endif

#ifndef timespecisset
#define timespecisset(tsp) ((tsp)->tv_sec || (tsp)->tv_nsec)
#endif

#ifndef timespecisvalid
#define timespecisvalid(tsp)                                                   \
        ((tsp)->tv_nsec >= 0 && (tsp)->tv_nsec < 1000000000L)
#endif

#ifndef timespeccmp
#define timespeccmp(tsp, usp, cmp)                                             \
        (((tsp)->tv_sec == (usp)->tv_sec) ? ((tsp)->tv_nsec cmp(usp)->tv_nsec) \
                                          : ((tsp)->tv_sec cmp(usp)->tv_sec))
#endif

#ifndef timespecadd
#define timespecadd(tsp, usp, vsp)                                             \
        do {                                                                   \
                (vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;                 \
                (vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;              \
                if ((vsp)->tv_nsec >= 1000000000L) {                           \
                        (vsp)->tv_sec++;                                       \
                        (vsp)->tv_nsec -= 1000000000L;                         \
                }                                                              \
        } while (0)
#endif

#ifndef timespecsub
#define timespecsub(tsp, usp, vsp)                                             \
        do {                                                                   \
                (vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;                 \
                (vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;              \
                if ((vsp)->tv_nsec < 0) {                                      \
                        (vsp)->tv_sec--;                                       \
                        (vsp)->tv_nsec += 1000000000L;                         \
                }                                                              \
        } while (0)
#endif

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#endif
