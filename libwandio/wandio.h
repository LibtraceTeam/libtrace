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
 * $Id$
 *
 */

#ifndef IO_H 
#define IO_H 1 /**< Guard Define */
#include <sys/types.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>


#ifndef DLLEXPORT
        #if HAVE_VISIBILITY && LT_BUILDING_DLL
                #define DLLEXPORT __attribute__ ((visibility("default")))
                #define DLLLOCAL __attribute__ ((visibility("hidden")))
        #else
                #define DLLEXPORT
                #define DLLLOCAL
        #endif
#endif

// TODO: Use a proper check for these attribute rather than gcc version check

/** @file
 *
 * @brief Header file dealing with the Libtrace IO sub-system
 *
 * @author Perry Lorier
 * @author Shane Alcock
 *
 * @version $Id$
 */

typedef struct io_t io_t; /**< Opaque IO handle structure for reading */
typedef struct iow_t iow_t; /**< Opaque IO handle structure for writing */

/** Structure defining a supported compression method */
struct wandio_compression_type {
	/** Name of the compression method */
	const char *name;
	/** Extension to add to the filename of files written using this 
	 *  method */
	const char *ext;
	/** Internal type identifying the compression method */
	int compress_type;
};

/** The list of supported compression methods */
extern struct wandio_compression_type compression_type[];

/** Structure defining a libtrace IO reader module */
typedef struct {
	/** Module name */
	const char *name;

	/** Reads from the IO source into the provided buffer.
	 *
	 * @param io		The IO reader
	 * @param buffer	The buffer to read into
	 * @param len		The amount of space available in the buffer
	 * @return The amount of bytes read, 0 if end of file is reached, -1
	 * if an error occurs
	 */
	off_t (*read)(io_t *io, void *buffer, off_t len);

	/** Reads from the IO source into the provided buffer but does not
	 *  advance the read pointer.
	 *
	 * @param io		The IO reader
	 * @param buffer	The buffer to read into
	 * @param len		The amount of space available in the buffer
	 * @return The amount of bytes read, 0 if end of file is reached, -1
	 * if an error occurs
	 */
	off_t (*peek)(io_t *io, void *buffer, off_t len);

	/** Returns the current offset of the read pointer for an IO source.
	 *
	 * @param io		The IO reader to get the read offset for
	 * @return The offset of the read pointer, or -1 if an error occurs
	 */
	off_t (*tell)(io_t *io);
	
	/** Moves the read pointer for an IO source.
	 * 
	 * @param io		The IO reader to move the read pointer for
	 * @param offset	The new read pointer offset
	 * @param whence	Where to start counting the new offset from.
	 * 			whence can be one of three values: SEEK_SET,
	 * 			SEEK_CUR and SEEK_END. See the lseek(2) manpage
	 * 			for more details as to what these mean.
	 * @return The value of the new read pointer, or -1 if an error occurs
	 */
	off_t (*seek)(io_t *io, off_t offset, int whence);
	
	/** Closes an IO reader. This function should free the IO reader.
	 *
	 * @param io		The IO reader to close
	 */
	void (*close)(io_t *io);
} io_source_t;

/** Structure defining a libtrace IO writer module */
typedef struct {
	/** The name of the module */
	const char *name;
	
	/** Writes the contents of a buffer using an IO writer.
	 *
	 * @param iow		The IO writer to write the data with
	 * @param buffer	The buffer to be written
	 * @param len		The amount of writable data in the buffer
	 * @return The amount of data written, or -1 if an error occurs
	 */
	off_t (*write)(iow_t *iow, const char *buffer, off_t len);

	/** Closes an IO writer. This function should free the IO writer. 
	 *
	 * @param iow		The IO writer to close
	 */
	void (*close)(iow_t *iow);
} iow_source_t;

/** A libtrace IO reader */
struct io_t {
	/** The IO module that is used by the reader */
	io_source_t *source;
	/** Generic pointer to data required by the IO module */
	void *data;
};

/** A libtrace IO writer */
struct iow_t {
	/** The IO module that is used by the writer */
	iow_source_t *source;
	/** Generic pointer to data required by the IO module */
	void *data;
};

/** Enumeration of all supported compression methods */
enum {
	/** No compression */
	WANDIO_COMPRESS_NONE	= 0,
	/** Zlib compression */
	WANDIO_COMPRESS_ZLIB	= 1,
	/** Bzip compression */
	WANDIO_COMPRESS_BZ2	= 2,
	/** LZO compression */
	WANDIO_COMPRESS_LZO	= 3,
        /** LZMA compression */
        WANDIO_COMPRESS_LZMA    = 4,
	/** All supported methods - used as a bitmask */
	WANDIO_COMPRESS_MASK	= 7
};

/** @name IO open functions
 *
 * These functions deal with creating and initialising a new IO reader or 
 * writer.
 *
 * @{
 */

io_t *bz_open(io_t *parent);
io_t *zlib_open(io_t *parent);
io_t *thread_open(io_t *parent);
io_t *lzma_open(io_t *parent);
io_t *peek_open(io_t *parent);
io_t *stdio_open(const char *filename);

iow_t *zlib_wopen(iow_t *child, int compress_level);
iow_t *bz_wopen(iow_t *child, int compress_level);
iow_t *lzo_wopen(iow_t *child, int compress_level);
iow_t *lzma_wopen(iow_t *child, int compress_level);
iow_t *thread_wopen(iow_t *child);
iow_t *stdio_wopen(const char *filename, int fileflags);

/* @} */

/**
 * @name Libtrace IO API functions
 *
 * These are the functions that should be called by the format modules to open
 * and use files with the libtrace IO sub-system.
 *
 * @{ */

/** Given a string describing the compression method, finds the internal
  * data structure representing that method. This is mostly useful for
  * nicely mapping a method name to the internal libwandio compression
  * method enum when configuring an output file.
  *
  * @param name          The compression method name as a string, e.g. "gzip",
  *                      "bzip2", "lzo" or "lzma".
  * @return A pointer to the compression_type structure representing the
  * compression method or NULL if no match can be found.
  *
  */
struct wandio_compression_type *wandio_lookup_compression_type(const char *name);

/** Creates a new libtrace IO reader and opens the provided file for reading.
 *
 * @param filename	The name of the file to open
 * @return A pointer to a new libtrace IO reader, or NULL if an error occurs
 *
 * The compression format will be determined automatically by peeking at the 
 * first few bytes of the file and comparing them against known compression 
 * file header formats. If no formats match, the file will be assumed to be
 * uncompressed.
 */
io_t *wandio_create(const char *filename);

/** Creates a new libtrace IO reader and opens the provided file for reading.
 *
 * @param filename	The name of the file to open
 * @return A pointer to a new libtrace IO reader, or NULL if an error occurs
 *
 * Unlike wandio_create, this function will always assume the file is 
 * uncompressed and therefore not run the compression autodetection algorithm.
 *
 * Use this function if you are only working with uncompressed files and are
 * running into problems with the start of your files resembling compression
 * format headers. Otherwise, you should really be using wandio_create.
 */
io_t *wandio_create_uncompressed(const char *filename);

/** Returns the current offset of the read pointer for a libtrace IO reader. 
 *
 * @param io		The IO reader to get the read offset for
 * @return The offset of the read pointer, or -1 if an error occurs
 */
off_t wandio_tell(io_t *io);

/** Changes the read pointer offset to the specified value for a libtrace IO
 * reader.
 *
 * @param io		The IO reader to adjust the read pointer for
 * @param offset	The new offset for the read pointer
 * @param whence	Indicates where to set the read pointer from. Can be 
 * 			one of SEEK_SET, SEEK_CUR or SEEK_END.
 * @return The new value for the read pointer, or -1 if an error occurs
 *
 * The arguments for this function are the same as those for lseek(2). See the
 * lseek(2) manpage for more details.
 */
off_t wandio_seek(io_t *io, off_t offset, int whence);

/** Reads from a libtrace IO reader into the provided buffer.
 *
 * @param io		The IO reader to read from
 * @param buffer	The buffer to read into
 * @param len		The size of the buffer
 * @return The amount of bytes read, 0 if EOF is reached, -1 if an error occurs
 */
off_t wandio_read(io_t *io, void *buffer, off_t len);

/** Reads from a libtrace IO reader into the provided buffer, but does not
 * update the read pointer.
 *
 * @param io		The IO reader to read from
 * @param buffer 	The buffer to read into
 * @param len		The size of the buffer
 * @return The amount of bytes read, 0 if EOF is reached, -1 if an error occurs
 */
off_t wandio_peek(io_t *io, void *buffer, off_t len);

/** Destroys a libtrace IO reader, closing the file and freeing the reader
 * structure.
 *
 * @param io		The IO reader to destroy
 */
void wandio_destroy(io_t *io);

/** Creates a new libtrace IO writer and opens the provided file for writing.
 *
 * @param filename		The name of the file to open
 * @param compression_type	Compression type
 * @param compression_level	The compression level to use when writing
 * @param flags			Flags to apply when opening the file, e.g.
 * 				O_CREATE
 * @return A pointer to the new libtrace IO writer, or NULL if an error occurs
 */
iow_t *wandio_wcreate(const char *filename, int compression_type, int compression_level, int flags);

/** Writes the contents of a buffer using a libtrace IO writer.
 *
 * @param iow		The IO writer to write the data with
 * @param buffer	The buffer to write out
 * @param len		The amount of writable data in the buffer
 * @return The amount of data written, or -1 if an error occurs
 */
off_t wandio_wwrite(iow_t *iow, const void *buffer, off_t len);

/** Destroys a libtrace IO writer, closing the file and freeing the writer
 * structure.
 *
 * @param iow		The IO writer to destroy
 */
void wandio_wdestroy(iow_t *iow);

/** @} */

#endif
