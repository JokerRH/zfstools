#include <libzfs_core.h>
#include <stdbool.h>

bool ImportPool( int fdZFS, const char *szzVDevs, const char *szPool, uint64_t idPool );
bool MountPool( int fdZFS, const char *szPool );
bool LoadPoolKey( const char *szEncryptionRoot, const char abKey[ 32 ] );

void print_nvlist( nvlist_t *nvl, int indent );