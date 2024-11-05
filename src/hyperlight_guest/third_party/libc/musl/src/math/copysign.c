#include "libm.h"

#if defined(_MSC_VER) 
// TODO: Check these suppressions to see if the warnings can be avoided
#pragma warning (push)
#pragma warning (disable:4146)
#endif
double copysign(double x, double y) {
	union {double f; uint64_t i;} ux={x}, uy={y};
	ux.i &= -1ULL/2;
	ux.i |= uy.i & 1ULL<<63;
	return ux.f;
}
#if defined(_MSC_VER) 
#pragma warning (pop)
#endif