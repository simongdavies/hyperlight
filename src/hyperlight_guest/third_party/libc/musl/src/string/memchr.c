#include <string.h>
#include <stdint.h>
#include <limits.h>

#define SS (sizeof(size_t))
#define ALIGN (sizeof(size_t)-1)
#define ONES ((size_t)-1/UCHAR_MAX)
#define HIGHS (ONES * (UCHAR_MAX/2+1))
#define HASZERO(x) ((x)-ONES & ~(x) & HIGHS)

// This is to allow the code to compile when /O2 (or /Oi which it implies) is specified with MSVC 
// /Oi causes the compiler to generate and use intrinsics for some C functions which then results in compile errors if those functions are included in source
// there does not appear to be a way to detect if this option is on so the use of #pragma function ensures that the instrinsi version is never used regadless of compiler settings
#if defined(_MSC_VER) 
#pragma function(memchr)
#endif

void *memchr(const void *src, int c, size_t n)
{
	const unsigned char *s = src;
	c = (unsigned char)c;
#ifdef __GNUC__
	for (; ((uintptr_t)s & ALIGN) && n && *s != c; s++, n--);
	if (n && *s != c) {
		typedef size_t __attribute__((__may_alias__)) word;
		const word *w;
		size_t k = ONES * c;
		for (w = (const void *)s; n>=SS && !HASZERO(*w^k); w++, n-=SS);
		s = (const void *)w;
	}
#endif
	for (; n && *s != c; s++, n--);
	return n ? (void *)s : 0;
}