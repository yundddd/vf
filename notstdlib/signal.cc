#include "notstdlib/signal.h"
#include "notstdlib/arch.h"
#include "notstdlib/types.h"
#include "notstdlib/sys.h"

int raise(int signal)
{
	return sys_kill(sys_getpid(), signal);
}
