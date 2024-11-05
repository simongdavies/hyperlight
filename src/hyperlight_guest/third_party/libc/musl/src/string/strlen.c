#include <string.h>
#include <stdint.h>
#include <limits.h>

#define ALIGN (sizeof(size_t))
#define ONES ((size_t)-1/UCHAR_MAX)
#define HIGHS (ONES * (UCHAR_MAX/2+1))
#define HASZERO(x) ((x)-ONES & ~(x) & HIGHS)

// This is to allow the code to compile when /O2 (or /Oi which it implies) is specified with MSVC 
// /Oi causes the compiler to generate and use intrinsics for some C functions which then results in compile errors if those functions are included in source
// there does not appear to be a way to detect if this option is on so the use of #pragma function ensures that the instrinsi version is never used regadless of compiler settings
#if defined(_MSC_VER) 
#pragma function(strlen)
#endif
size_t strlen(const char *s)
{
	const char *a = s;
#ifdef __GNUC__
	typedef size_t __attribute__((__may_alias__)) word;
	const word *w;
	for (; (uintptr_t)s % ALIGN; s++) if (!*s) return s-a;
	for (w = (const void *)s; !HASZERO(*w); w++);
	s = (const void *)w;
#endif
	for (; *s; s++);
	return s-a;
}