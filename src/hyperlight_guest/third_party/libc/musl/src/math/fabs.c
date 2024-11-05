#include <math.h>
#include <stdint.h>

// This is to allow the code to compile when /O2 (or /Oi which it implies) is specified with MSVC 
// /Oi causes the compiler to generate and use intrinsics for some C functions which then results in compile errors if those functions are included in source
// there does not appear to be a way to detect if this option is on so the use of #pragma function ensures that the instrinsi version is never used regadless of compiler settings
#if defined(_MSC_VER) 
#pragma function(fabs)
// TODO: Check these suppressions to see if the warnings can be avoided
#pragma warning (push)
#pragma warning (disable:4146)
#endif
double fabs(double x)
{
	union {double f; uint64_t i;} u = {x};
	u.i &= -1ULL/2;
	return u.f;
}
#if defined(_MSC_VER) 
#pragma warning (pop)
#endif