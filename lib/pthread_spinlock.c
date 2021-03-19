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

#ifdef __APPLE__

#include "pthread_spinlock.h"

/* Apple 10.12 deprecates spin locks as they cause issues with their scheduler
 * https://mjtsai.com/blog/2015/12/16/osspinlock-is-unsafe/
 */
#if defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 101200

int pthread_spin_lock(pthread_spinlock_t *lock) {
	if (lock == NULL)
		return EINVAL;

	os_unfair_lock_lock(lock);
	return 0;
}

int pthread_spin_trylock(pthread_spinlock_t *lock) {
	if (lock == NULL)
		return EINVAL;

	if (os_unfair_lock_trylock(lock)) {
		return 0;
	} else {
		return EBUSY;
	}
}

int pthread_spin_unlock(pthread_spinlock_t *lock) {
	if (lock == NULL)
		return EINVAL;
	os_unfair_lock_unlock(lock);
	return 0;
}

int pthread_spin_destroy(pthread_spinlock_t *lock) {
	(void)lock;
	return 0;
}

int pthread_spin_init(pthread_spinlock_t *lock, int pshared) {
	if (lock == NULL)
		return EINVAL;
	*lock = OS_UNFAIR_LOCK_INIT;
	(void)pshared;
	return 0;
}

#else

int pthread_spin_lock(pthread_spinlock_t *lock) {
	if (lock == NULL)
		return EINVAL;

	OSSpinLockLock(lock);
	return 0;
}

int pthread_spin_trylock(pthread_spinlock_t *lock) {
	if (lock == NULL)
		return EINVAL;

	if (OSSpinLockTry(lock)) {
		return 0;
	} else {
		return EBUSY;
	}
}

int pthread_spin_unlock(pthread_spinlock_t *lock) {
	if (lock == NULL)
		return EINVAL;
	OSSpinLockUnlock(lock);
	return 0;
}

int pthread_spin_destroy(pthread_spinlock_t *lock) {
	if (*lock != 0)
		return EBUSY;
	return 0;
}

int pthread_spin_init(pthread_spinlock_t *lock, int pshared) {
	if (lock == NULL)
		return EINVAL;
	*lock = OS_SPINLOCK_INIT;
	(void)pshared;
	return 0;
}
#endif /* macOS 10.12 or newer */
#endif /* __APPLE__ */
