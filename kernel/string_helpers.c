#include "string_helpers.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)

/* stolen from lib/string_helpers.c */

#include <linux/slab.h>
#include <linux/ctype.h>

#define ESCAPE_SPACE		0x01
#define ESCAPE_SPECIAL		0x02
#define ESCAPE_NULL		    0x04
#define ESCAPE_OCTAL		0x08
#define ESCAPE_ANY		    (ESCAPE_SPACE | ESCAPE_OCTAL | ESCAPE_SPECIAL | ESCAPE_NULL)
#define ESCAPE_NP		    0x10
#define ESCAPE_ANY_NP		(ESCAPE_ANY | ESCAPE_NP)
#define ESCAPE_HEX		    0x20

static bool escape_passthrough(unsigned char c, char **dst, char *end)
{
	char *out = *dst;

	if (out < end)
		*out = c;
	*dst = out + 1;
	return true;
}

static bool escape_space(unsigned char c, char **dst, char *end)
{
	char *out = *dst;
	unsigned char to;

	switch (c) {
	case '\n':
		to = 'n';
		break;
	case '\r':
		to = 'r';
		break;
	case '\t':
		to = 't';
		break;
	case '\v':
		to = 'v';
		break;
	case '\f':
		to = 'f';
		break;
	default:
		return false;
	}

	if (out < end)
		*out = '\\';
	++out;
	if (out < end)
		*out = to;
	++out;

	*dst = out;
	return true;
}

static bool escape_special(unsigned char c, char **dst, char *end)
{
	char *out = *dst;
	unsigned char to;

	switch (c) {
	case '\\':
		to = '\\';
		break;
	case '\a':
		to = 'a';
		break;
	case '\e':
		to = 'e';
		break;
	default:
		return false;
	}

	if (out < end)
		*out = '\\';
	++out;
	if (out < end)
		*out = to;
	++out;

	*dst = out;
	return true;
}

static bool escape_null(unsigned char c, char **dst, char *end)
{
	char *out = *dst;

	if (c)
		return false;

	if (out < end)
		*out = '\\';
	++out;
	if (out < end)
		*out = '0';
	++out;

	*dst = out;
	return true;
}

static bool escape_octal(unsigned char c, char **dst, char *end)
{
	char *out = *dst;

	if (out < end)
		*out = '\\';
	++out;
	if (out < end)
		*out = ((c >> 6) & 0x07) + '0';
	++out;
	if (out < end)
		*out = ((c >> 3) & 0x07) + '0';
	++out;
	if (out < end)
		*out = ((c >> 0) & 0x07) + '0';
	++out;

	*dst = out;
	return true;
}

static bool escape_hex(unsigned char c, char **dst, char *end)
{
	char *out = *dst;

	if (out < end)
		*out = '\\';
	++out;
	if (out < end)
		*out = 'x';
	++out;
	if (out < end)
		*out = hex_asc_hi(c);
	++out;
	if (out < end)
		*out = hex_asc_lo(c);
	++out;

	*dst = out;
	return true;
}

int string_escape_mem(const char *src, size_t isz, char *dst, size_t osz,
		      unsigned int flags, const char *only)
{
	char *p = dst;
	char *end = p + osz;
	bool is_dict = only && *only;

	while (isz--) {
		unsigned char c = *src++;

		/*
		 * Apply rules in the following sequence:
		 *	- the character is printable, when @flags has
		 *	  %ESCAPE_NP bit set
		 *	- the @only string is supplied and does not contain a
		 *	  character under question
		 *	- the character doesn't fall into a class of symbols
		 *	  defined by given @flags
		 * In these cases we just pass through a character to the
		 * output buffer.
		 */
		if ((flags & ESCAPE_NP && isprint(c)) ||
		    (is_dict && !strchr(only, c))) {
			/* do nothing */
		} else {
			if (flags & ESCAPE_SPACE && escape_space(c, &p, end))
				continue;

			if (flags & ESCAPE_SPECIAL && escape_special(c, &p, end))
				continue;

			if (flags & ESCAPE_NULL && escape_null(c, &p, end))
				continue;

			/* ESCAPE_OCTAL and ESCAPE_HEX always go last */
			if (flags & ESCAPE_OCTAL && escape_octal(c, &p, end))
				continue;

			if (flags & ESCAPE_HEX && escape_hex(c, &p, end))
				continue;
		}

		escape_passthrough(c, &p, end);
	}

	return p - dst;
}

char *kstrdup_quotable(const char *src, gfp_t gfp)
{
	size_t slen, dlen;
	char *dst;
	const int flags = ESCAPE_HEX;
	const char esc[] = "\f\n\r\t\v\a\e\\\"";

	if (!src)
		return NULL;
	slen = strlen(src);

	dlen = string_escape_mem(src, slen, NULL, 0, flags, esc);
	dst = kmalloc(dlen + 1, gfp);
	if (!dst)
		return NULL;

	WARN_ON(string_escape_mem(src, slen, dst, dlen, flags, esc) != dlen);
	dst[dlen] = '\0';

	return dst;
}

#include "util.h"

char *kstrdup_quotable_cmdline(struct task_struct *task, gfp_t gfp)
{
	char *buffer, *quoted;
	int i, res;

	buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buffer)
		return NULL;

	res = get_cmdline(task, buffer, PAGE_SIZE - 1);
	buffer[res] = '\0';

	/* Collapse trailing NULLs, leave res pointing to last non-NULL. */
	while (--res >= 0 && buffer[res] == '\0')
		;

	/* Replace inter-argument NULLs. */
	for (i = 0; i <= res; i++)
		if (buffer[i] == '\0')
			buffer[i] = ' ';

	/* Make sure result is printable. */
	quoted = kstrdup_quotable(buffer, gfp);
	kfree(buffer);
	return quoted;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
char *strreplace(char *s, char old, char new)
{
	for (; *s; ++s)
		if (*s == old)
			*s = new;
	return s;
}

#endif
#endif