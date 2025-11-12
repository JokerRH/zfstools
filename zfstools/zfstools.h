#include <loadkey/loadkey.h>
#include <libzfs_core.h>

bool ImportPool( int fdZFS, const char *szzVDevs, const char *szPool, uint64_t idPool );
bool MountPool( int fdZFS, const char *szPool );
bool LoadPoolKey( const char *szEncryptionRoot, block256_t ymmKey );

void print_nvlist( nvlist_t *nvl, int indent );