/*
 * Copyright (c) 2002 Endace Measurement Systems Ltd, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This source code is proprietary to Endace Measurement Systems and no part
 * of it may be redistributed, published or disclosed except as outlined in
 * the written contract supplied with this product.
 *
 * $Id$
 */

# include	<stdio.h>
# include	<fcntl.h>
# include	<stdlib.h>
# include	<unistd.h>
# include	<errno.h>
# include	<regex.h>
# include	<stdarg.h>
# include	<string.h>

# include	<sys/types.h>
# include	<sys/wait.h>
# include	<sys/mman.h>
# include	<sys/param.h>
# include	<sys/time.h>

# if 0
# include	<machine/cpufunc.h>
# endif

# include	<dagnew.h>
# include	<dagapi.h>
# include	<dagtoken.h>

extern void	dagopt_scan_string(const char *);
extern int	dagoptlex(void);
extern char	*dagopttext;
extern int	dagoptlval;

# define	ToHM2		(*(volatile unsigned *)(herd[dagfd].iom+0x08))
# define	ToHM4		(*(volatile unsigned *)(herd[dagfd].iom+0x10))
# define	ToAM2		(*(volatile unsigned *)(herd[dagfd].iom+0x48))
# define	ToAM3		(*(volatile unsigned *)(herd[dagfd].iom+0x4c))
# define	IOM(OFF)	(*(volatile unsigned *)(herd[dagfd].iom+(OFF)))
# define	ARMOFFSET(FD)	({ int _off = ToHM4 - dag_info(FD)->phy_addr; \
					(_off == dag_info(FD)->buf_size) ? 0 : _off; })

# define	CUROFFSET(FD)	({ int _off = pbm->curaddr - dag_info(FD)->phy_addr; \
					(_off == dag_info(FD)->buf_size) ? 0 : _off; })
# define	SEGOFFSET(FD)	({ int _off = pbm->segaddr - dag_info(FD)->phy_addr; \
					(_off == dag_info(FD)->buf_size) ? 0 : _off; })
# define	PBMOFFSET(FD)	(herd[FD].brokencuraddr ? \
					SEGOFFSET(FD) : CUROFFSET(FD))

/*
 * Long comment on why this is here and necessary:
 * There are a number of ambiguities with the wrsafe and curaddr pointers being
 * the same, in particular, understanding in any given situation whether the
 * buffer is empty/full from the PBM point of view, or meant to be emptied from
 * a users point of view. A number of fixes are possible, this one appears to be
 * the reliable path to address the problem, for the moment.
 */
# define	WRSAFE(FD,X)	(((X)<8) ? ((X)+dag_info(FD)->buf_size-8) : ((X)-8))

/*
 * Need to explain the file descriptor associative array.
 */
typedef struct sheep {
	char		dagname[32];	/* be generous */
	int		dagiom;		/* XXX cannot be 0 */
	u_char		*buf;		/* large buffer */
	u_char		*iom;		/* IO memory pointer */
	daginf_t	daginf;
	unsigned	brokencuraddr;	/* fix for ECMs and Dag4.1s */
	unsigned        byteswap;       /* endinness for 3.4/3.51ecm */
} sheep_t;

static sheep_t	*herd;			/* I was going to call this flock, initially */

static void	panic(char *fmt, ...) __attribute__((noreturn, format (printf, 1, 2)));

char *dagpath(char *path, char *temp, int tempsize) {
	
	if (!getenv("DAG"))
		return path;
	snprintf(temp, tempsize-1, "%s/%s", getenv("DAG"), path);
	return temp;
}

int
dag_open(char *dagname)
{
	int	dagfd, i;

	if((dagfd = open(dagname, O_RDWR)) < 0)
		return dagfd;
	if(herd == NULL) {
		int herdsize = sysconf(_SC_OPEN_MAX) * sizeof(sheep_t);
		herd = malloc(herdsize);
		if(herd == NULL)
			return -1;	/* errno is ENOMEM */
		memset(herd, 0, herdsize);
		for( i = 0 ; i < sysconf(_SC_OPEN_MAX) ; i++)
			herd[i].dagiom = -1;
	}
	if(dagfd >= sysconf(_SC_OPEN_MAX))
		panic("dagapi: internal error in %s line %u\n", __FILE__, __LINE__);
	/*
	 * Now fill in the herd structure
	 */
	strcpy(herd[dagfd].dagname, dagname);
	if(ioctl(dagfd, DAGIOCINFO, &herd[dagfd].daginf) < 0)
		return -1;		/* errno set appropriately */

	if((herd[dagfd].dagiom = dag_clone(dagfd, DAGMINOR_IOM)) < 0)
		panic("dag_open dag_clone dagfd for dagiom: %s\n", strerror(errno));

	if((herd[dagfd].iom = mmap(NULL, 2*PAGE_SIZE, PROT_READ | PROT_WRITE,
					MAP_SHARED, herd[dagfd].dagiom, 0)) == MAP_FAILED)
		return -1;	/* errno set appropriately */

	return dagfd;
}

int
dag_close(int dagfd)
{
	(void)close(herd[dagfd].dagiom);
	memset(&herd[dagfd], 0, sizeof(herd[dagfd]));
	herd[dagfd].dagiom = -1;
	return close(dagfd);
}

/*
 * This is tentative, could be made an inline function.
 * Problem is we don't want to make herd public.
 */
daginf_t *
dag_info(int dagfd)
{
	return &herd[dagfd].daginf;
}

u_char *
dag_iom(int dagfd)
{
	return herd[dagfd].iom;
}

u_char
dag_linktype(int dagfd)
{
	daggpp_t	*gpp = (daggpp_t *)(herd[dagfd].iom +
					dag_info(dagfd)->gpp_base);
	unsigned char   type;

	type = (gpp->control >> 16) & 0xff;
	if (type == 0xff)
		type = TYPE_ETH;

	return type;
}

static int	spawn(char *cmd, ...);

#define Int_Enables 0x8c
#define IW_Enable   0x10000
#define armcode(X) ( (*(int*)(herd[X].iom + Int_Enables) & IW_Enable) || dag_info(X)->soft_caps.code )

int
dag_configure(int dagfd, char *params)
{
	int	lock, tok, setatm;
	char    temp1[80], temp2[80];
	daggpp_t	*gpp = (daggpp_t *)(herd[dagfd].iom +
					dag_info(dagfd)->gpp_base);

	/*
	 * We better own this before changing configurations
	 * We might aquire the lock again when starting the
	 * card, which is no harm.
	 */
	lock = 1;
	if(ioctl(dagfd, DAGIOCLOCK, &lock) < 0)
		return -1;	/* errno set */

	/* 
	 * Parse input options
	 *
	 * Options are parsed before loading arm code since
	 * arm code loading depends on the options provided.
	 * The ncells options may enable armcode loading, and if so sets
	 * ToAM3 afterwards, since it is volatile on mailbox use.
	 *
	 * It is also possible auto-fpga loading may depend on options
	 * parsed here. If so, needs rearranging since reprogramming the
	 * pp fpga will void the gpp configurations set now.
	 */
	dagopt_scan_string(params);

	setatm=1; /* default to ncells=1 */
	while((tok = dagoptlex()) != 0)
		switch(tok) {
		  case T_ERROR:
			fprintf(stderr, "unknown option '%s'\n", dagopttext);
			break;
		  case T_POS:
			break;
		  case T_ATM:
			break;
		  case T_ATM_NCELLS:
			if (dagoptlval)
				*(int*)(herd[dagfd].iom + Int_Enables) |= IW_Enable;
			else
				*(int*)(herd[dagfd].iom + Int_Enables) &= ~IW_Enable;
			if (dagoptlval > 15)
				panic("ncells set too high (%d), max is 15\n",
				      dagoptlval);
			setatm &= ~0xffff;
			setatm |= dagoptlval;
			break;
		  case T_ATM_LCELL:
			if(dagoptlval)
				setatm |= 0x20000;
			break;
		  case T_GPP_SLEN:
			gpp->snaplen = dagoptlval;
			break;
		  case T_GPP_VARLEN:
			if(dagoptlval)
				gpp->control |= 1;
			else
				gpp->control &= ~1;
			break;
		  default:
			/* silently ignore unhandled tokens */
			if (tok < T_MAX)
				break;
			/* panic on illegal tokens */
			panic("unknown token %u in %s line %u\n", tok, __FILE__, __LINE__);
		}

	switch(dag_info(dagfd)->device_code) {
	  case 0x3200:
		if(armcode(dagfd)) {
			if(spawn(dagpath("tools/dagrun", temp1, 80), "-d",
					herd[dagfd].dagname,
					dagpath("arm/dag3atm-hash.b",
					temp2, 80), NULL) < 0)
				return -1;				
		}
		break;
	  case 0x3500:
		/*
		 * XXX might want to load recent images first
		 * XXX check if DUCK PPS present ?
		 */
		/*
		 * XXX we need to split params and implement an "ignore what
		 * you don't know" option in dagthree
		 */
# if notyet
		if(execlp(dagpath("tools/dagthree", temp1, 80), "-d", herd[dagfd].dagname, params, NULL) < 0)
			return -1;	/* errno set appropriately */
# endif
		if(armcode(dagfd)) {
# ifdef	__linux__
			if(spawn(dagpath("tools/dagrun", temp1, 80), "-d", herd[dagfd].dagname, dagpath("arm/dag3atm-erf.b", temp2, 80), NULL) < 0)
				return -1;				
			
# else /* FreeBSD */
			if(spawn(dagpath("dagld", temp1, 80), "-d", herd[dagfd].dagname, "-r", dagpath("arm/dag3atm-erf.b", temp2, 80), NULL) < 0)
				return -1;
# endif
		}
		break;
		/* normal */
	  case 0x350e:
	  case 0x360d:
		break;
		/* byteswapped */
	  case 0x351c:
		herd[dagfd].byteswap = DAGPBM_BYTESWAP;
		break;
		/* byteswapped and ipp */
	  case 0x3400:
	  case 0x340e:
	  case 0x341e:
		herd[dagfd].byteswap = DAGPBM_BYTESWAP;
		/* ipp */
	  case 0x4100:
	  case 0x4110:
		herd[dagfd].brokencuraddr++;
		break;
		/* normal */
	  case 0x3800:
	  case 0x4220:
	  case 0x422e:
	  case 0x423e:
	  case 0x4230:
	  case 0x6000:
	  case 0x6100:
		/*
		 * XXX might wish to load recent Xilinx image, then reload
		 */
		break;
	  default:
		errno = ENODEV;		/* need to say something */
		return -1;
	}

	/* Now we are finished with loading, it's safe to set ARM parameters */
	if(armcode(dagfd))
		ToAM3 = setatm;

	return 0;
}

static int
spawn(char *cmd, ...)
{
	va_list ap;
	int	i, pid, status;
	char	*args[16];	/* arbitrarily small */

	switch(pid = fork()) {
	  case -1:	/* error */
		return -1;	/* errno set appropriately */
	  case 0:	/* child */
		va_start(ap, cmd);
		args[0] = cmd;
		for( i = 1 ; i < 15 ; i++)
			if((args[i] = va_arg(ap, char *)) == NULL)
				break;
		args[i] = NULL;
		for( i = 0 ; i < 15 ; i++ ) {
			if(args[i] == NULL) {
				break;
			}
		}

		va_end(ap);
		execvp(cmd, args);
		panic("execvp %s failed: %s\n", cmd, strerror(errno));
	  default:	/* parent */
		if(wait(&status) != pid)
			return -1;
		if(!WIFEXITED(status))
			return -1;
		if(WEXITSTATUS(status) != 0)
			return -1;
		break;
	}
	return 0;
}

extern int	dag32start(int dagfd);
extern int	dag32stop(int dagfd);
extern int	dag35start(int dagfd);
extern int	dag35stop(int dagfd);
extern int	dag42start(int dagfd);
extern int	dag42stop(int dagfd);

int
dag_start(int dagfd)
{
	int	lock;

	lock = 1;
	if(ioctl(dagfd, DAGIOCLOCK, &lock) < 0)
		return -1;	/* errno set */

	memset(herd[dagfd].buf, 0, dag_info(dagfd)->buf_size);

	switch(dag_info(dagfd)->device_code) {
	  case 0x3200:
		return dag32start(dagfd);
	  case 0x3500:
	  case 0x360d:
		return dag35start(dagfd);
	  case 0x3400:
	  case 0x340e:
	  case 0x341e:
	  case 0x351c:
	  case 0x350e:
	  case 0x3800:
	  case 0x4100:
	  case 0x4110:
	  case 0x4220:
	  case 0x422e:
	  case 0x423e:
	  case 0x4230:
	  case 0x6000:
	  case 0x6100:
		return dag42start(dagfd);
	  default:
		errno = ENODEV;		/* need to say something */
		return -1;
	}
}

int
dag_stop(int dagfd)
{
	int	lock;
	int	error = 0;

	switch(dag_info(dagfd)->device_code) {
	  case 0x3200:
		error = dag32stop(dagfd);
		break;
	  case 0x3500:
	  case 0x360d:
		error = dag35stop(dagfd);
		break;
	  case 0x3400:
	  case 0x340e:
	  case 0x341e:
	  case 0x351c:
	  case 0x350e:
	  case 0x3800:
	  case 0x4100:
	  case 0x4110:
	  case 0x4220:
	  case 0x422e:
	  case 0x423e:
	  case 0x4230:
	  case 0x6000:
	  case 0x6100:
		error = dag42stop(dagfd);
		break;
	  default:
		errno = ENODEV;		/* need to say something */
		error = -1;
	}

	lock = 0; /* unlock */
	if(ioctl(dagfd, DAGIOCLOCK, &lock) < 0) 
		error = -1;		/* errno set accordingly */
	return error;
}

void *
dag_mmap(int dagfd)
{
	void		*sp, *p, *ep;
	daginf_t	*dip;

	dip = dag_info(dagfd);
	/*
	 * Start off with a fake mapping to allocate contiguous virtual
	 * address space in one lot for twice the size of the memory buffer,
	 * then map in the two copies via the dag device driver.
	 * This saves us (for the momemt) the costs of rewriting parts of
	 * the device driver, which would be an alternative solution to the
	 * problem.
	 */
	if((sp = mmap(NULL, 2*dip->buf_size, PROT_READ | PROT_WRITE,
			MAP_ANON|MAP_SHARED, -1, 0)) == MAP_FAILED)
		return MAP_FAILED;
	/*
	 * Now map the real buffer, 1st round.
	 */
	if((p = mmap(sp, dip->buf_size, PROT_READ | PROT_WRITE,
			MAP_FIXED|MAP_SHARED, dagfd, 0)) == MAP_FAILED)
		return MAP_FAILED;
	/*
	 * Map the buffer for a second time, this will turn out to be a neat
	 * feature for handling data records crossing the wrap around the
	 * top of the memory buffer.
	 */
	if((ep = mmap(sp+dip->buf_size, dip->buf_size, PROT_READ|PROT_WRITE,
			MAP_FIXED|MAP_SHARED, dagfd, 0)) == MAP_FAILED)
		return MAP_FAILED;
	herd[dagfd].buf = p;
	return p;
}

/*
 * XXX should probably made card or feature specific.
 * XXX should the next two be merged ? Blocking/non-blocking ?
 */
int
dag_offset(int dagfd, int *oldoffset, int flags)
{
	dagpbm_t	*pbm = (dagpbm_t *)(herd[dagfd].iom +
					dag_info(dagfd)->pbm_base);
	int		offset;

	/*
	 * The implementation implies that offsets within
	 * the buffer are now starting zero to top of the
	 * hole, exclusive the top address, which is considered
	 * zero.
	 */
	if(*oldoffset >= dag_info(dagfd)->buf_size)
		*oldoffset -= dag_info(dagfd)->buf_size;

	if(dag_info(dagfd)->soft_caps.pbm) {
		/*
		 * Advance acknowledgement pointer, this should be done in
		 * all cases, blocking or non-blocking.
		 * Reinit the burst manager, in case safety net was reached
		 * XXX we might consider reporting safety net status ?
		 */
		pbm->wrsafe = dag_info(dagfd)->phy_addr + WRSAFE(dagfd, *oldoffset);
		pbm->cs = (DAGPBM_AUTOWRAP|herd[dagfd].byteswap);
		/*
		 * With the WRSAFE() macro in place, if offset equals oldoffset,
		 * the buffer is guaranteed to be empty.
		 */
		offset = PBMOFFSET(dagfd);
		while(offset == *oldoffset) {
			if (flags & DAGF_NONBLOCK)
				return offset;
			usleep(1);
			offset = PBMOFFSET(dagfd);
		}
	} else {
		offset = ARMOFFSET(dagfd);
		while(offset == *oldoffset) {
			if (flags & DAGF_NONBLOCK)
				return offset;
			usleep(1);
			offset = ARMOFFSET(dagfd);
		}
	}

	if(offset > dag_info(dagfd)->buf_size)
		panic("dagapi: dag_offset internal error offset=0x%x\n", offset);

	if(offset < *oldoffset)
		offset += dag_info(dagfd)->buf_size;

	return offset;
}

void *
dag_nextpkt(void *curpkt, void *buf, int bufsize)
{

	return 0;
}

/*
 * XXX this shall be moved to a different file later
 */
int
dag32start(int dagfd)
{
	if(armcode(dagfd)) {
		ToAM2 = 0;			/* clear command register */

		while(ToHM2 != 1) {
			usleep(1);
			if(ToHM2 == 2)
				break;		/* protocol bug */
		}

		ToAM2 = 1;			/* command: run */

		while(ToHM2 != 2)
			usleep(1);
	}

	return 0;
}

int
dag32stop(int dagfd)
{
	int	loop = 100, retval=0;

	if(armcode(dagfd)) {
		ToAM2 = 2;			/* stop command */

		while(--loop > 0) {
			usleep(10*1000); /* give ARM a chance to settle */
			if(ToHM2 == 3)
				break;
		}
		retval = (ToHM2 == 3) ? 0 : -1;	/* XXX need to set errno */
	}
	return retval;
}

int
dag35start(int dagfd)
{
	dagpbm_t	*pbm = (dagpbm_t *)(herd[dagfd].iom +
					dag_info(dagfd)->pbm_base);

	/*
	 * XXX make sure the DUCK is in sync, if needed
	 */
	if(dag_info(dagfd)->soft_caps.pbm) {
		pbm->cs = (DAGPBM_PAUSED | DAGPBM_SAFETY);
		while (pbm->cs & DAGPBM_REQPEND)
			usleep(1);

		IOM(0x88)  |= (1<<31);		/* L2RESET, will auto deassert */

		pbm->bursttmo = 0xffff;
		pbm->memaddr = dag_info(dagfd)->phy_addr; /* XXX curaddr bugfix */
		pbm->memsize = dag_info(dagfd)->buf_size;
		pbm->segsize = (1024*1024);	/* paranoia, not that it matters */
		pbm->wrsafe = dag_info(dagfd)->phy_addr + WRSAFE(dagfd, dag_info(dagfd)->buf_size);
		pbm->cs = (DAGPBM_SYNCL2R|DAGPBM_AUTOWRAP|herd[dagfd].byteswap);

		IOM(0x88)  |= (1<<31);		/* L2RESET, will auto deassert */

	}

	if(armcode(dagfd)) {
	        usleep(1); /* seems necessary to let pbm settle? */
		IOM(0x404) |=  (1<<23);		/* framer now held in reset */
		IOM(0x88)  |= (1<<31);		/* L2RESET, will auto deassert */

		ToAM2 = 0;			/* clear command register */

		while(ToHM2 != 1) {
			usleep(1);
			if(ToHM2 == 2)
				break;		/* protocol bug */
		}

		ToAM2 = 1;			/* command: run */

		while(ToHM2 != 2)
			usleep(1);
		IOM(0x404) &= ~(1<<23);		/* deassert framer reset */
	}

	return 0;
}

int
dag35stop(int dagfd)
{
	dagpbm_t	*pbm = (dagpbm_t *)(herd[dagfd].iom +
					dag_info(dagfd)->pbm_base);
	int	loop = 100, retval=0;

	if(armcode(dagfd)) {
		ToAM2 = 2;			/* stop command */

		while(--loop > 0) {
			usleep(10*1000); /* give ARM a chance to settle */
			if(ToHM2 == 3)
				break;
		}
		retval = (ToHM2 == 3) ? 0 : -1;	/* XXX need to set errno */
	}
	if(dag_info(dagfd)->soft_caps.pbm) {
		pbm->cs = (DAGPBM_PAUSED);

		while(--loop > 0) {
			if(!(pbm->cs & DAGPBM_REQPEND))
				break;
			usleep(10*1000);
		}
		retval += (pbm->cs & DAGPBM_REQPEND) ? -1 : 0;
	}
	return retval;
}

int
dag42start(int dagfd)
{
	dagpbm_t	*pbm = (dagpbm_t *)(herd[dagfd].iom +
					dag_info(dagfd)->pbm_base);

	pbm->cs = (DAGPBM_PAUSED | DAGPBM_SAFETY);
	while (pbm->cs & DAGPBM_REQPEND)
		usleep(1);

	IOM(0x88)  |= (1<<31);		/* L2RESET, will auto deassert */

	pbm->bursttmo = 0xffff;
	pbm->memaddr = dag_info(dagfd)->phy_addr; /* XXX curaddr bugfix */
	pbm->memsize = dag_info(dagfd)->buf_size;
	pbm->segsize = (1024*1024);	/* paranoia, not that it matters */
	pbm->wrsafe = dag_info(dagfd)->phy_addr + WRSAFE(dagfd, dag_info(dagfd)->buf_size);
	pbm->cs = (DAGPBM_SYNCL2R|DAGPBM_AUTOWRAP|herd[dagfd].byteswap);

	IOM(0x88)  |= (1<<31);		/* L2RESET, will auto deassert */

	return 0;
}

int
dag42stop(int dagfd)
{
	dagpbm_t	*pbm = (dagpbm_t *)(herd[dagfd].iom +
					dag_info(dagfd)->pbm_base);
	int		loop = 100;

	pbm->cs = (DAGPBM_PAUSED);

	while(--loop > 0) {
		if(!(pbm->cs & DAGPBM_REQPEND))
			break;
		usleep(10*1000);
	}

	return 0;
}

/*
 * I wish there was a better way, by means of a clone ioctl() in the
 * kernel, but it appears to be more difficult and also OS specific,
 * so here is the second best and also portable version.
 */
int
dag_clone(int dagfd, int minor)
{
	regex_t		reg;
	regmatch_t	match;
	char		buf[16];
	char		*fmt[DAGMINOR_MAX] = {
				"/dev/dag%c",		/* DAGMINOR_DAG */
				"/dev/dagmem%c", 	/* DAGMINOR_MEM */
				"/dev/dagiom%c",	/* DAGMINOR_IOM */
				"/dev/dagarm%c",	/* DAGMINOR_ARM */
				"/dev/dagram%c",	/* DAGMINOR_RAM */
			};
	int		r;

	if(minor >= DAGMINOR_MAX) {
		errno = EDOM;
		return -1;
	}
	if(regcomp(&reg, "/dev/dag(iom|mem|arm|ram)*[0-9]", REG_EXTENDED) != 0) {
		errno = EDOM;	/* grrrk */
		return -1;
	}
	if((r = regexec(&reg, herd[dagfd].dagname, 1, &match, 0)) !=0) {
		errno = EDOM;  /* grrrk */
		return -1;
	}
	(void)sprintf(buf, fmt[minor], herd[dagfd].dagname[match.rm_eo-1]);
	regfree(&reg);

	return open(buf, O_RDWR);
}

static void
panic(char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "daglib: panic: ");
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

