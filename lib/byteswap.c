/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Daniel Lawson 
 *          Perry Lorier
 *          Shane Alcock 
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
 * $Id: format_helper.c 1830 2013-05-14 05:17:57Z salcock $
 *
 */

#include "lt_bswap.h"

/* Byte swapping functions for various inttypes */
uint64_t byteswap64(uint64_t num)
{
	return (byteswap32((num&0xFFFFFFFF00000000ULL)>>32))
	      |((uint64_t)byteswap32(num&0x00000000FFFFFFFFULL)<<32);
}

uint32_t byteswap32(uint32_t num)
{
	return ((num&0x000000FFU)<<24)
		| ((num&0x0000FF00U)<<8)
		| ((num&0x00FF0000U)>>8)
		| ((num&0xFF000000U)>>24);
}

uint16_t byteswap16(uint16_t num)
{
	return ((num<<8)&0xFF00)|((num>>8)&0x00FF);
}

