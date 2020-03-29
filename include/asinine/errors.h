/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#define RETURN_ON_ERROR(e) \
	do { \
		if (e != ASININE_OK) { \
			return e; \
		} \
	} while (0)

//#define ASN1_DEBUG
#if defined(ASN1_DEBUG)
#define ERR(e, d) (e ## _ ## d)
#else
#define ERR(e, d) (e)
#endif

#if defined(ASN1_DEBUG)
#define EMBEDDED_ASSERT(x) \
	if (!(x))     \
	panic("%s: %d: assert err: %s", __FILE__, __LINE__, #x)
#else
#define EMBEDDED_ASSERT(x) (0)
#endif

typedef enum asinine_errno {
	ASININE_OK = 0,
	ERR_MALFORMED,
	ERR_MEMORY,
	ERR_UNSUPPORTED,
	ERR_INVALID,
	ERR_EXPIRED,
	ERR_UNTRUSTED,
	ERR_DEPRECATED,
	ERR_NOT_FOUND,
} asinine_errno_t;
