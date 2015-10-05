/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007-2015 The University of Waikato, Hamilton,
 * New Zealand.
 *
 * Authors: Richard Sanger
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */

/** Apple does not implement pthread_spinlock_t so we'll do it for them */

#ifndef LIBTRACE_PTHREAD_SPINLOCK_H
#define LIBTRACE_PTHREAD_SPINLOCK_H


/* Apple does not implement pthread_spinlock_t
 */

#ifndef __PTHREAD_SPINLOCK_H
#define __PTHREAD_SPINLOCK_H

#ifdef __APPLE__

#include <libkern/OSAtomic.h>
#include <errno.h>

typedef OSSpinLock pthread_spinlock_t;

int pthread_spin_lock(pthread_spinlock_t *lock);
int pthread_spin_trylock(pthread_spinlock_t *lock);
int pthread_spin_unlock(pthread_spinlock_t *lock);
int pthread_spin_destroy(pthread_spinlock_t *lock);
int pthread_spin_init(pthread_spinlock_t *lock, int pshared);

#endif /* __APPLE__ */
#endif /* __PTHREAD_SPINLOCK_H */


#endif // LIBTRACE_PTHREAD_SPINLOCK_H
