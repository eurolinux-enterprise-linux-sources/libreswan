/* Support of X.509 certificates and CRLs
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef _X509_H
#define _X509_H
#include <libreswan.h>
#include "lswalloc.h"
#include <nss.h>
#include <cert.h>

/* Maximum length of ASN.1 distinquished name */
#define ASN1_BUF_LEN	512
/*
 * NSS can actually support a much larger path length
 */
#define MAX_CA_PATH_LEN 7

/* Definition of generalNames kinds */

typedef enum {
	GN_OTHER_NAME =		0,
	GN_RFC822_NAME =	1,
	GN_DNS_NAME =		2,
	GN_X400_ADDRESS =	3,
	GN_DIRECTORY_NAME =	4,
	GN_EDI_PARTY_NAME =	5,
	GN_URI =		6,
	GN_IP_ADDRESS =		7,
	GN_REGISTERED_ID =	8
} generalNames_t;

/* access structure for a GeneralName */

typedef struct generalName generalName_t;

struct generalName {
	generalName_t *next;
	generalNames_t kind;
	chunk_t name;
};

/* forward declaration */
struct id;
/*
 * check periodically for expired crls
 */
extern deltatime_t crl_check_interval;

extern bool same_dn(chunk_t a, chunk_t b);
extern bool match_dn(chunk_t a, chunk_t b, int *wildcards);
extern int dn_count_wildcards(chunk_t dn);
extern int dntoa(char *dst, size_t dstlen, chunk_t dn);
extern int dntoa_or_null(char *dst, size_t dstlen, chunk_t dn,
			 const char *null_dn);
extern err_t atodn(char *src, chunk_t *dn);
extern void free_generalNames(generalName_t *gn, bool free_name);
extern chunk_t get_directoryName(chunk_t blob, int level, bool implicit);
extern void load_crls(void);
extern void list_authcerts(void);
extern void list_crls(void);
extern void clear_ocsp_cache(void);

/*
 * New NSS x509 converted functions
 */
extern SECItem chunk_to_secitem(chunk_t chunk);
extern chunk_t secitem_to_chunk(SECItem si);
extern chunk_t dup_secitem_to_chunk(SECItem si);
extern chunk_t get_dercert_from_nss_cert(CERTCertificate *cert);
extern void convert_nss_gn_to_pluto_gn(CERTGeneralName *nss_gn,
				       generalName_t *pluto_gn);
extern void get_pluto_gn_from_nss_cert(CERTCertificate *cert,
					generalName_t **gn_out);
extern realtime_t get_nss_cert_notafter(CERTCertificate *cert);
extern struct pubkey *allocate_RSA_public_key_nss(CERTCertificate *cert);
extern generalName_t *gndp_from_nss_cert(CERTCertificate *cert);
extern bool cert_key_is_rsa(CERTCertificate *cert);
extern void select_nss_cert_id(CERTCertificate *cert, struct id *end_id);
extern void add_rsa_pubkey_from_cert(const struct id *keyid,
				    CERTCertificate *cert);
extern bool trusted_ca_nss(chunk_t a, chunk_t b, int *pathlen);
extern bool insert_crl_nss(chunk_t *blob, chunk_t *crl_uri, char *nss_uri);
extern char *find_dercrl_uri(chunk_t *dercrl);
extern char *make_crl_uri_str(chunk_t *uri);

#if defined(LIBCURL) || defined(LDAP_VER)
extern void check_crls(void);
extern void lock_crl_list(const char *who);	/* in fetch.c */
extern void unlock_crl_list(const char *who);	/* in fetch.c */
extern void lock_authcert_list(const char *who);	/* in secrets.c */
extern void unlock_authcert_list(const char *who);	/* in secrets.c */
#else
/* WARNING empty x509 locking functions defined bypassing real locking */
/* not fixing this hack, see issues #1390, #1391, #1392 */
#define check_crls(who)			/* nothing */
#define lock_crl_list(who)		/* nothing */
#define unlock_crl_list(who)		/* nothing */
#define lock_authcert_list(who)		/* nothing */
#define unlock_authcert_list(who)	/* nothing */
#endif

/* filter eliminating the directory entries '.' and '..' */
typedef struct dirent dirent_t;

#endif /* _X509_H */
