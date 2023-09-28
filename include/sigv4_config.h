/* Only used for debugging. This file isn't used in the normal mrbgem. */
#include <stdio.h>
#define LOGERR(fmt, a...) fprintf(stderr, fmt "\n", ##a)
#define LogError(a) LOGERR a
#define LogDebug(a) LOGERR a
#define LogWarn(a) LOGERR a
#define LogInfo(a) LOGERR a
