/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton,
 * New Zealand.
 *
 * Authors: Daniel Lawson
 *          Perry Lorier
 *          Shane Alcock
 *          Richard Sanger
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

/* This format module deals with using the Linux ring capture format.
 *
 * Linux ring is a LIVE capture format.
 *
 * This format also supports writing which will write packets out to the
 * network as a form of packet replay. This should not be confused with the
 * RT protocol which is intended to transfer captured packet records between
 * RT-speaking programs.
 */

static int linuxring_init_input(libtrace_t *libtrace)
{
	init_input(libtrace);
	FORMAT(libtrace->format_data)->format = TRACE_RT_DATA_LINUX_RING;
	return 0;
}

static int linuxring_start_input(libtrace_t *libtrace)
{
	char error[2048];

	/* We set the socket up the same and then convert it to PACKET_MMAP */
	if(linuxnative_start_input(libtrace) != 0)
		return -1;

	strncpy(error, "No known error", 2048);

	/* Make it a packetmmap */
	if(socket_to_packetmmap(libtrace->uridata, PACKET_RX_RING,
			FORMAT(libtrace->format_data)->fd,
		 	&FORMAT(libtrace->format_data)->req,
			&FORMAT(libtrace->format_data)->rx_ring,
			&FORMAT(libtrace->format_data)->max_order,
			error) != 0){
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
			      "Initialisation of packet MMAP failed: %s",
			      error);
		close(DATAOUT(libtrace)->fd);
		free(libtrace->format_data);
		libtrace->format_data = NULL;
		return -1;
	}

	return 0;
}

static int linuxring_pause_input(libtrace_t *libtrace)
{
	munmap(FORMAT(libtrace->format_data)->rx_ring, 
		FORMAT(libtrace->format_data)->req.tp_block_size *
			FORMAT(libtrace->format_data)->req.tp_block_nr);
	FORMAT(libtrace->format_data)->rx_ring = NULL;
	return linuxnative_pause_input(libtrace);
}



#ifdef HAVE_NETPACKET_PACKET_H
/* TODO: Fix this revision number */
static void linuxring_help(void) {
	printf("linuxring format module: $Revision: 1793 $\n");
	printf("Supported input URIs:\n");
	printf("\tring:eth0\n");
	printf("\n");
	printf("Supported output URIs:\n");
	printf("\tring:eth0\n");
	printf("\n");
	return;
}

static struct libtrace_format_t linuxring = {
	"ring",
	"$Id$",
	TRACE_FORMAT_LINUX_RING,
	linuxnative_probe_filename,	/* probe filename */
	NULL,				/* probe magic */
	linuxring_init_input,	 	/* init_input */
	linuxnative_config_input,	/* config_input */
	linuxring_start_input,	/* start_input */
	linuxring_pause_input,	/* pause_input */
	linuxring_init_output,	/* init_output */
	NULL,				/* config_output */
	linuxring_start_output,	/* start_ouput */
	linuxnative_fin_input,		/* fin_input */
	linuxring_fin_output,		/* fin_output */
	linuxring_read_packet,	/* read_packet */
	linuxring_prepare_packet,	/* prepare_packet */
	linuxring_fin_packet,				/* fin_packet */
	linuxring_write_packet,	/* write_packet */
	linuxring_get_link_type,	/* get_link_type */
	linuxring_get_direction,	/* get_direction */
	linuxring_set_direction,	/* set_direction */
	NULL,				/* get_erf_timestamp */
	linuxring_get_timeval,	/* get_timeval */
	linuxring_get_timespec,	/* get_timespec */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	linuxring_get_capture_length,	/* get_capture_length */
	linuxring_get_wire_length,	/* get_wire_length */
	linuxring_get_framing_length,	/* get_framing_length */
	linuxring_set_capture_length,	/* set_capture_length */
	NULL,				/* get_received_packets */
	linuxnative_get_filtered_packets,/* get_filtered_packets */
	linuxnative_get_dropped_packets,/* get_dropped_packets */
	linuxnative_get_captured_packets,/* get_captured_packets */
	linuxnative_get_fd,		/* get_fd */
	linuxring_event,		/* trace_event */
	linuxring_help,		/* help */
	NULL,				/* next pointer */
	{true, -1},              /* Live, no thread limit */
	linuxnative_pstart_input,			/* pstart_input */
	linuxring_pread_packets,			/* pread_packets */
	linuxnative_ppause_input,			/* ppause */
	linuxnative_fin_input,				/* p_fin */
	linuxnative_pconfig_input,
	linux_pregister_thread,
	NULL
};
#else
static void linuxring_help(void) {
	printf("linuxring format module: $Revision: 1793 $\n");
	printf("Not supported on this host\n");
}

static struct libtrace_format_t linuxring = {
	"ring",
	"$Id$",
	TRACE_FORMAT_LINUX_RING,
	NULL,				/* probe filename */
	NULL,				/* probe magic */
	NULL,	 			/* init_input */
	NULL,				/* config_input */
	NULL,				/* start_input */
	NULL,				/* pause_input */
	NULL,				/* init_output */
	NULL,				/* config_output */
	NULL,				/* start_ouput */
	NULL,				/* fin_input */
	NULL,				/* fin_output */
	NULL,				/* read_packet */
	linuxring_prepare_packet,	/* prepare_packet */
	NULL,				/* fin_packet */
	NULL,				/* write_packet */
	linuxring_get_link_type,	/* get_link_type */
	linuxring_get_direction,	/* get_direction */
	linuxring_set_direction,	/* set_direction */
	NULL,				/* get_erf_timestamp */
	linuxring_get_timeval,		/* get_timeval */
	linuxring_get_timespec,		/* get_timespec */
	NULL,				/* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
	linuxring_get_capture_length,	/* get_capture_length */
	linuxring_get_wire_length,	/* get_wire_length */
	linuxring_get_framing_length,	/* get_framing_length */
	linuxring_set_capture_length,	/* set_capture_length */
	NULL,				/* get_received_packets */
	linuxnative_get_filtered_packets,/* get_filtered_packets */
	linuxnative_get_dropped_packets,/* get_dropped_packets */
	linuxnative_get_captured_packets,/* get_captured_packets */
	linuxnative_get_fd,		/* get_fd */
	NULL,				/* trace_event */
	linuxring_help,			/* help */
	NULL,			/* next pointer */
	NON_PARALLEL(true)
};
#endif

/* TODO: We should try to prefer the ring format over the native format
 * if the user only specifies the interface (eth0 etc). */
void linuxring_constructor(void)
{
	register_format(&linuxring);
}
