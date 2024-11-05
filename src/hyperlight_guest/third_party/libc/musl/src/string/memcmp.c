#include <string.h>
// This is to allow the code to compile when /O2 (or /Oi which it implies) is specified with MSVC 
// /Oi causes the compiler to generate and use intrinsics for some C functions which then results in compile errors if those functions are included in source
// there does not appear to be a way to detect if this option is on so the use of #pragma function ensures that the instrinsi version is never used regadless of compiler settings
#if defined(_MSC_VER) 
#pragma function(memcmp)
#endif

int memcmp(const void *vl, const void *vr, size_t n)
{
	const unsigned char *l=vl, *r=vr;
	for (; n && *l == *r; n--, l++, r++);
	return n ? *l-*r : 0;
}