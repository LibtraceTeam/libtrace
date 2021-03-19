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
#ifndef LIBTRACE_PTHREAD_SPINLOCK_H
#define LIBTRACE_PTHREAD_SPINLOCK_H


/* Apple does not implement pthread_spinlock_t
 */

#ifndef __PTHREAD_SPINLOCK_H
#define __PTHREAD_SPINLOCK_H

#ifdef __APPLE__

/* Apple 10.12 deprecates spin locks as they cause issues with their scheduler
 * https://mjtsai.com/blog/2015/12/16/osspinlock-is-unsafe/
 */
#if defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 101200
	#include <os/lock.h>
	typedef os_unfair_lock pthread_spinlock_t;
#else
	#include <libkern/OSAtomic.h>
	typedef OSSpinLock pthread_spinlock_t;
#endif /* macOS 10.12 or newer */

#include <errno.h>


int pthread_spin_lock(pthread_spinlock_t *lock);
int pthread_spin_trylock(pthread_spinlock_t *lock);
int pthread_spin_unlock(pthread_spinlock_t *lock);
int pthread_spin_destroy(pthread_spinlock_t *lock);
int pthread_spin_init(pthread_spinlock_t *lock, int pshared);

#endif /* __APPLE__ */
#endif /* __PTHREAD_SPINLOCK_H */


#endif // LIBTRACE_PTHREAD_SPINLOCK_H
