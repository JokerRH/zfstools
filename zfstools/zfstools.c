#include "zfstools.h"
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <dirent.h>
#include <aio.h>
#include <assert.h>
#include <zfs_cmd.h>
#include <syslog.h>

#define	VDEV_LABELS			4
#define	VDEV_PHYS_SIZE		( 112 << 10 )
#define	VDEV_PAD_SIZE		( 8 << 10 )
#define	VDEV_UBERBLOCK_RING	( 128 << 10 )

#define	ZEC_MAGIC	0x210da7ab10c7a11ULL

#define	P2ALIGN_TYPED( x, align, type )	( (type) ( x ) & -(type) ( align ) )
#define	PAGESIZE						( spl_pagesize( ) )

#define	CONFIG_BUF_MINSIZE	262144
#define MNTTYPE_ZFS			"zfs"

#ifdef __FreeBSD__
#	define PROP_ZONED	"jailed"
#else
#	define PROP_ZONED	"zoned"
#endif

extern size_t spl_pagesize( void );

typedef struct zio_cksum
{
	uint64_t zc_word[ 4 ];
} zio_cksum_t;

typedef struct zio_eck
{
	uint64_t zec_magic;		//For validation, endianness
	zio_cksum_t zec_cksum;	//256-bit checksum
} zio_eck_t;

typedef struct vdev_phys
{
	char vp_nvlist[ VDEV_PHYS_SIZE - sizeof( zio_eck_t ) ];
	zio_eck_t vp_zbt;
} vdev_phys_t;

typedef struct vdev_boot_envblock
{
	uint64_t vbe_version;
	char vbe_bootenv[ VDEV_PAD_SIZE - sizeof( uint64_t ) - sizeof( zio_eck_t ) ];
	zio_eck_t vbe_zbt;
} vdev_boot_envblock_t;
static_assert( sizeof( vdev_boot_envblock_t ) == VDEV_PAD_SIZE );

typedef struct vdev_label
{
	char vl_pad1[ VDEV_PAD_SIZE ];				//8K
	vdev_boot_envblock_t vl_be;					//8K
	vdev_phys_t vl_vdev_phys;					//112K
	char vl_uberblock[ VDEV_UBERBLOCK_RING ];	//128K
} vdev_label_t;
static_assert( sizeof( vdev_label_t ) == 262144 );

static unsigned CountStrings( const char *szz )
{
	unsigned numStrings = 0;
	while( *szz )
	{
		szz += strlen( szz ) + 1;
		++numStrings;
	}
	return numStrings;
}


/*
	A ZFS pool consists of 1 or more top-level vdevs.
	Each disk contains VDEV_LABELS labels for redundancy - half at the beginning of the disk, half at the end. Part of this label is the top-level vdev config.
	This top-level config in each disk stores which pool it belongs to, how many children that pool has and which child index this vdev is.
	To import a pool, a config must be created that lists all children of the pool, even if they are "holes". If the children can not be found, they are replaced with a "MISSING" type.
*/

/*!
	\brief Tries to unpack the vdev config from an io operation.
*/
static nvlist_t *VDevUnpackConfig( const struct aiocb aiocb[ 2 ] )
{
	unsigned j = 0;
	for( unsigned u = 0; u < 2; ++u )
	{
		const size_t numLabels = aio_return( (struct aiocb *) &aiocb[ u ] ) / sizeof( vdev_label_t );
		const vdev_label_t *const aLabels = (const vdev_label_t *) aiocb[ u ].aio_buf;
		for( unsigned uLabel = 0; uLabel < numLabels; ++uLabel )
		{
			if( aLabels[ uLabel ].vl_vdev_phys.vp_zbt.zec_magic != ZEC_MAGIC )
				continue;

			//TODO: Verify checksum

			nvlist_t *nvl;
			if( nvlist_unpack( (char *) aLabels[ uLabel ].vl_vdev_phys.vp_nvlist, sizeof( aLabels[ uLabel ].vl_vdev_phys.vp_nvlist ), &nvl, 0 ) )
				continue;

			return nvl;
		}
	}

	return NULL;
}

static const char *GetVDevName( const char *const szzVDevs, unsigned uVDev )
{
	const char *szVDev = szzVDevs;
	for( unsigned u = 0; u < uVDev; ++u )
		szVDev += strlen( szVDev ) + 1;

	return szVDev;
}

/*!
	\brief Loads the configuration from the VDevs given in \p szzVDevs.
	\param szzVDevs A list of vdev paths. VDevs are separated with NULL-terminators, the list itself is finalized with a second NULL-terminators (i.e. doubly terminated at the end).
	\details	Aside from errors that may occur from i/o or kernel communication, the function will purposely fail if a vdev is SPARE, L2CACHE or doesn't belong to the pool \p szPool with id \p idPool.
*/
static bool LoadVDevConfigs( const char *const szzVDevs, const char *const szPool, const uint64_t idPool, const unsigned numVDevs, nvlist_t **const anvl )
{
	//Read all labels
	vdev_label_t *aLabels;
	struct aiocb *const aiocbs = alloca( numVDevs * ( VDEV_LABELS / 2 ) * sizeof( struct aiocb ) );
	{
		if( posix_memalign( (void **) &aLabels, PAGESIZE, numVDevs * VDEV_LABELS * sizeof( vdev_label_t ) ) )
		{
			syslog( LOG_ERR, "Failed to allocate memory for vdev labels." );
			return NULL;
		}

		int *const afd = alloca( numVDevs * sizeof( int ) );
		struct aiocb **const aiocbps = alloca( numVDevs * ( VDEV_LABELS / 2 ) * sizeof( struct aiocb * ) );
		memset( aiocbs, 0, numVDevs * ( VDEV_LABELS / 2 ) * sizeof( struct aiocb ) );

		//VDev labels are stored half at the beginning of the device, half at the end.
		//Initialize all aiocb structures. Per vdev, one for the first VDEV_LABELS / 2 labels, the consecutive one for the remaining ones.
		{
			const char *szVDev = szzVDevs;
			for( unsigned uVDev = 0; uVDev < numVDevs; ++uVDev, szVDev += strlen( szVDev ) + 1 )
			{
				//TODO: error = blkid_dev_set_search(iter, (char *)"TYPE", (char *)"zfs_member");

				struct stat64 statbuf;
				if( stat64( szVDev, &statbuf ) != 0 || ( !S_ISREG( statbuf.st_mode ) && !S_ISBLK( statbuf.st_mode ) ) || ( S_ISREG( statbuf.st_mode ) && statbuf.st_size < SPA_MINDEVSIZE ) )
				{
					syslog( LOG_ERR, "Invalid device \"%s\".", szVDev );
					goto ERROR_WHILE_OPENING;
				}

				//Open the file descriptor
				const int fd = open( szVDev, O_RDONLY | O_DIRECT | O_CLOEXEC );
				if( fd < 0 && errno == EINVAL )
					*(int *) &fd = open( szVDev, O_RDONLY | O_CLOEXEC );
				if( fd < 0 )
				{
					syslog( LOG_ERR, "Failed to open vdev \"%s\".", szVDev );

ERROR_WHILE_OPENING:
					//Close already opened file descriptors
					for( ; uVDev; --uVDev )
						close( aiocbs[ ( uVDev - 1 ) * 2 ].aio_fildes );

					free( aLabels );
					return NULL;
				}

				//Fetch the size of the vdev
				if( ioctl( fd, BLKGETSIZE64, &statbuf.st_size ) )
				{
					syslog( LOG_ERR, "Failed to get blocksize for device \"%s\".", szVDev );
					close( fd );
					goto ERROR_WHILE_OPENING;
				}

				const size_t size = P2ALIGN_TYPED( statbuf.st_size, sizeof( vdev_label_t ), uint64_t );

				struct aiocb *const p = &aiocbs[ uVDev * 2 ];
				aiocbps[ uVDev * 2 ] = p;
				aiocbps[ uVDev * 2 + 1 ] = p + 1;

				p[ 0 ].aio_fildes = fd;
				p[ 0 ].aio_offset = 0;
				p[ 0 ].aio_buf = &aLabels[ uVDev * VDEV_LABELS ];
				p[ 0 ].aio_nbytes = VDEV_LABELS / 2 * sizeof( vdev_label_t );
				p[ 0 ].aio_lio_opcode = LIO_READ;
				p[ 1 ].aio_fildes = fd;
				p[ 1 ].aio_nbytes = p[ 0 ].aio_nbytes;
				p[ 1 ].aio_offset = size - p[ 1 ].aio_nbytes;
				p[ 1 ].aio_buf = (char *) p[ 0 ].aio_buf + p[ 0 ].aio_nbytes;
				p[ 1 ].aio_lio_opcode = LIO_READ;
			}
		}

		//Perform the io operations
		if( lio_listio( LIO_WAIT, aiocbps, numVDevs * ( VDEV_LABELS / 2 ), NULL ) )
		{
			syslog( LOG_ERR, "Failed to fetch vdev labels." );
			if( errno == EAGAIN || errno == EINTR || errno == EIO )
			{
				//A portion of the requests may have been submitted. Clean them up.
				for( unsigned u = 0; u < VDEV_LABELS; ++u )
				{
					errno = 0;
					switch( aio_error( &aiocbs[ u ] ) )
					{
					case EINVAL:
						break;
					case EINPROGRESS:
						//This shouldn't be possible to encounter, die if we do.
						assert( false );
						//fallthrough
					case EREMOTEIO:
					case EAGAIN:
					case EOPNOTSUPP:
					case ENOSYS:
					case 0:
					default:
						(void) aio_return( &aiocbs[ u ] );
					}
				}
			}

			//Cleanup and exit
			for( unsigned uVDev = 0; uVDev < numVDevs; ++uVDev )
				close( aiocbs[ uVDev * 2 ].aio_fildes );
			free( aLabels );
			return NULL;
		}

		//Close vdev file descriptors
		for( unsigned uVDev = 0; uVDev < numVDevs; ++uVDev )
			close( aiocbs[ uVDev * 2 ].aio_fildes );
	}

	//At this point, we have VDEV_LABELS / 2 sucessfull aio operation results, with VDEV_LABELS labels

	for( unsigned uVDev = 0; uVDev < numVDevs; ++uVDev )
	{
		const nvlist_t *nvl = anvl[ uVDev ] = VDevUnpackConfig( &aiocbs[ uVDev * 2 ] );
		if( !nvl )
		{
			syslog( LOG_WARNING, "Failed to unpack vdev config for \"%s\".", GetVDevName( szzVDevs, uVDev ) );
			continue;
		}

		//Ensure state is neither SPARE nor L2CACHE
		{
			uint64_t eState;
			if( nvlist_lookup_uint64( nvl, "state", &eState ) )
			{
				syslog( LOG_ERR, "Failed to lookup vdev state for \"%s\".", GetVDevName( szzVDevs, uVDev ) );
				goto ERROR_WHILE_UNPACKING;
			}

			if( eState == POOL_STATE_SPARE || eState == POOL_STATE_L2CACHE )
			{
				syslog( LOG_ERR, "VDev state for \"%s\" indicates a Spare or L2Cache drive.", GetVDevName( szzVDevs, uVDev ) );
				goto ERROR_WHILE_UNPACKING;
			}
		}

		//Ensure the vdev belongs to the correct pool by name
		{
			const char *szVDevPool;
			if( nvlist_lookup_string( nvl, "name", &szVDevPool ) )
			{
				syslog( LOG_ERR, "Failed to lookup vdev name for \"%s\".", GetVDevName( szzVDevs, uVDev ) );
				goto ERROR_WHILE_UNPACKING;
			}

			if( strcmp( szPool, szVDevPool ) )
			{
				syslog( LOG_ERR, "VDev \"%s\" is a member of pool \"%s\", not \"%s\".", GetVDevName( szzVDevs, uVDev ), szVDevPool, szPool );
				goto ERROR_WHILE_UNPACKING;
			}
		}

		//Ensure the vdev belongs to the correct pool by id
		{
			uint64_t idVDevPool;
			if( nvlist_lookup_uint64( nvl, "pool_guid", &idVDevPool ) )
			{
				syslog( LOG_ERR, "Failed to lookup vdev pool_guid for \"%s\".", GetVDevName( szzVDevs, uVDev ) );
				goto ERROR_WHILE_UNPACKING;
			}

			if( idPool != idVDevPool )
			{
				syslog( LOG_ERR, "VDev \"%s\" is a member of pool with id %" PRIu64 ", not %" PRIu64 ".", GetVDevName( szzVDevs, uVDev ), idVDevPool, idPool );
				goto ERROR_WHILE_UNPACKING;
			}
		}

		continue;

ERROR_WHILE_UNPACKING:
		do
		{
			nvlist_free( anvl[ uVDev ] );
		} while( uVDev-- );
		free( aLabels );
		return false;
	}

	free( aLabels );
	return true;
}

/*!
	\brief	Loads all vdev configurations for the list \p szzVDevs, then creates the pool configuration associated with them.
	\param szzVDevs A list of vdev paths. VDevs are separated with NULL-terminators, the list itself is finalized with a second NULL-terminators (i.e. doubly terminated at the end).
*/
static nvlist_t *LoadPoolConfig( const char *const szzVDevs, const char *const szPool, const uint64_t idPool )
{
	unsigned numVDevs = CountStrings( szzVDevs );
	nvlist_t *anvlRedundant[ numVDevs ];
	if( !LoadVDevConfigs( szzVDevs, szPool, idPool, numVDevs, anvlRedundant ) )
		return NULL;

	//At this point, we have one vdev config per physical device. All of these belong to the same pool, but not necessarily describe the same top-level vdev.
	//The pool could for example consist of multiple raidz* vdevs, each with severel vdevs (one per disk).
	//Make a unique set of top-level vdevs

	unsigned uVDev = 0;	//Needed for cleanup
	size_t numAllocated = 32;
	struct tlvdev_s
	{
		uint64_t uTxg;
		nvlist_t *nvl;
	} *aTlVDev = calloc( numAllocated, sizeof( struct tlvdev_s ) );
	if( !aTlVDev )
	{
		syslog( LOG_ERR, "Failed to allocate memory for top-level vdev list." );
		goto ERROR_AFTER_VDEV;
	}

	//The array aTlVDev will contain the list of top-level vdevs (only the vdev_tree section of the disk's vdevs).
	//Since we have multiple entries per top-level vdev in anvlRedundant, we pick the one with the highest transaction group. This is to prevent old disks re-inserted from corrupting the pool config.
	//Further, we need the full disk vdev with highest overall transaction group to create the pool config. This is handled separately via uMaxTxg and nvlLatest.
	uint64_t uMaxTxg = 0;
	nvlist_t *nvlLatest = NULL;
	for( ; uVDev < numVDevs; ++uVDev )
	{
		if( !anvlRedundant[ uVDev ] )
			continue;

		//Fetch the vdev tree from the disk vdev
		nvlist_t *nvl;
		if( nvlist_lookup_nvlist( anvlRedundant[ uVDev ], ZPOOL_CONFIG_VDEV_TREE, &nvl ) )
		{
			syslog( LOG_ERR, "Failed to lookup vdev_tree for \"%s\".", GetVDevName( szzVDevs, uVDev ) );
			goto ERROR_AFTER_TLVDEV;
		}

		uint64_t idChild;
		if( nvlist_lookup_uint64( nvl, "id", &idChild ) )
		{
			syslog( LOG_ERR, "Failed to lookup vdev child id for \"%s\".", GetVDevName( szzVDevs, uVDev ) );
			goto ERROR_AFTER_TLVDEV;
		}

		//If the child id is larger than the array we currently have, reserve some more space
		if( idChild >= numAllocated )
		{
			const size_t numPrevious = numAllocated;
			do
			{
				numAllocated += 32;
			} while( idChild >= numAllocated );

			struct tlvdev_s *const p = realloc( aTlVDev, numAllocated * sizeof( struct tlvdev_s ) );
			if( !p )
			{
				syslog( LOG_ERR, "Failed to allocate memory for top-level vdev list." );
				goto ERROR_AFTER_TLVDEV;
			}

			aTlVDev = p;
			memset( aTlVDev + numPrevious, 0, ( numAllocated - numPrevious ) * sizeof( struct tlvdev_s ) );
		}

		//Check if this top-level vdev has a higher transaction group than what was previously found
		uint64_t uTxg;
		if( nvlist_lookup_uint64( anvlRedundant[ uVDev ], ZPOOL_CONFIG_POOL_TXG, &uTxg ) )
		{
			syslog( LOG_ERR, "Failed to lookup vdev txg for \"%s\".", GetVDevName( szzVDevs, uVDev ) );
			goto ERROR_AFTER_TLVDEV;
		}

		if( aTlVDev[ idChild ].uTxg >= uTxg )
		{
			//There is a vdev with same or larger transaction group already in the child slot. Therefore it also can't be the largest overall txg.
			nvlist_free( anvlRedundant[ uVDev ] );
			anvlRedundant[ uVDev-- ] = anvlRedundant[ --numVDevs ];	//Move the vdev from the back of the array into the current position, then shorten the array
			continue;
		}

		//Transaction group is the current largest for this child, save a reference (not a copy yet!) to it.
		aTlVDev[ idChild ].uTxg = uTxg;
		aTlVDev[ idChild ].nvl = nvl;

		//Check if is the largest transaction group overall
		if( uMaxTxg >= uTxg )
			continue;

		uMaxTxg = uTxg;
		nvlLatest = anvlRedundant[ uVDev ];
	}
	uVDev = 0;	//Needed for cleanup

	//At this point, we have
	//- nvlLatest as the latest overall disk vdev
	//- aTlVDev as an array of references into the vdev_tree below vdevs in anvlRedundant

	//Using nvlLatest, create the basic structure of the pool configuration
	nvlist_t *nvlPool;
	uint64_t numChildren;
	uint64_t *auHoles;
	uint_t numHoles = 0;
	{
		if( nvlist_alloc( &nvlPool, NV_UNIQUE_NAME, 0 ) )
		{
			syslog( LOG_ERR, "Failed to allocate pool nvlist." );
			goto ERROR_AFTER_TLVDEV;
		}
		
		//Copy version
		{
			uint64_t uVersion;
			if( nvlist_lookup_uint64( nvlLatest, ZPOOL_CONFIG_VERSION, &uVersion ) )
			{
				syslog( LOG_ERR, "Failed to retrieve pool version." );
				goto ERROR_AFTER_POOL;
			}

			if( nvlist_add_uint64( nvlPool, ZPOOL_CONFIG_VERSION, uVersion ) )
			{
				syslog( LOG_ERR, "Failed to copy pool version." );
				goto ERROR_AFTER_POOL;
			}
		}

		//Copy pool guid
		{
			if( nvlist_add_uint64( nvlPool, ZPOOL_CONFIG_POOL_GUID, idPool ) )
			{
				syslog( LOG_ERR, "Failed to copy pool pool_guid." );
				goto ERROR_AFTER_POOL;
			}
		}

		//Copy pool name
		{
			if( nvlist_add_string( nvlPool, ZPOOL_CONFIG_POOL_NAME, szPool ) )
			{
				syslog( LOG_ERR, "Failed to copy pool name." );
				goto ERROR_AFTER_POOL;
			}
		}

		//Copy comment
		{
			const char *szComment;
			if( !nvlist_lookup_string( nvlLatest, ZPOOL_CONFIG_COMMENT, &szComment ) )
				if( nvlist_add_string( nvlPool, ZPOOL_CONFIG_COMMENT, szComment ) )
					syslog( LOG_WARNING, "Failed to copy pool comment." );
		}

		//Copy compatibility
		{
			const char *szCompatibility;
			if( !nvlist_lookup_string( nvlLatest, ZPOOL_CONFIG_COMPATIBILITY, &szCompatibility ) )
				if( nvlist_add_string( nvlPool, ZPOOL_CONFIG_COMPATIBILITY, szCompatibility ) )
					syslog( LOG_WARNING, "Failed to copy pool compatibility." );
		}

		//Copy state
		{
			uint64_t eState;
			if( nvlist_lookup_uint64( nvlLatest, ZPOOL_CONFIG_POOL_STATE, &eState ) )
			{
				syslog( LOG_ERR, "Failed to retrieve pool state." );
				goto ERROR_AFTER_POOL;
			}

			if( nvlist_add_uint64( nvlPool, ZPOOL_CONFIG_POOL_STATE, eState ) )
			{
				syslog( LOG_ERR, "Failed to copy pool state." );
				goto ERROR_AFTER_POOL;
			}
		}

		//Copy hostid
		{
			uint64_t idHost;
			if( !nvlist_lookup_uint64( nvlLatest, ZPOOL_CONFIG_HOSTID, &idHost ) )
				if( nvlist_add_uint64( nvlPool, ZPOOL_CONFIG_HOSTID, idHost ) )
				{
					syslog( LOG_ERR, "Failed to copy pool hostid." );
					goto ERROR_AFTER_POOL;
				}
		}

		//Copy hostname
		{
			const char *szHostName;
			if( !nvlist_lookup_string( nvlLatest, ZPOOL_CONFIG_HOSTNAME, &szHostName ) )
				if( nvlist_add_string( nvlPool, ZPOOL_CONFIG_HOSTNAME, szHostName ) )
				{
					syslog( LOG_ERR, "Failed to copy pool hostname." );
					goto ERROR_AFTER_POOL;
				}
		}

		//Copy hole_array
		{
			if( !nvlist_lookup_uint64_array( nvlLatest, ZPOOL_CONFIG_HOLE_ARRAY, &auHoles, &numHoles ) )
				if( nvlist_add_uint64_array( nvlPool, ZPOOL_CONFIG_HOLE_ARRAY, auHoles, numHoles ) )
				{
					syslog( LOG_ERR, "Failed to copy pool hole_array." );
					goto ERROR_AFTER_POOL;
				}
		}

		//Copy vdev_children
		{
			if( nvlist_lookup_uint64( nvlLatest, ZPOOL_CONFIG_VDEV_CHILDREN, &numChildren ) )
			{
				syslog( LOG_ERR, "Failed to retrieve pool vdev_children." );
				goto ERROR_AFTER_POOL;
			}

			if( nvlist_add_uint64( nvlPool, ZPOOL_CONFIG_VDEV_CHILDREN, numChildren ) )
			{
				syslog( LOG_ERR, "Failed to copy pool vdev_children." );
				goto ERROR_AFTER_POOL;
			}
		}
	}

	{
		//Fill holes with dummy vdevs
		nvlist_t *anvlHoles[ numHoles ];
		if( numHoles )
		{
			//At least one hole is present. Create a "template" (assigned to the first hole) that is copied for remaining holes.
			nvlist_t *nvlHole;
			if( nvlist_alloc( &nvlHole, NV_UNIQUE_NAME, 0 ) )
			{
				syslog( LOG_ERR, "Failed to allocate nvlist for pool holes." );
				goto ERROR_AFTER_POOL;
			}

			if( nvlist_add_string( nvlHole, ZPOOL_CONFIG_TYPE, VDEV_TYPE_HOLE ) )
			{
				syslog( LOG_ERR, "Failed to set hole nvlist type." );
				numHoles = 1;	//Only one hole to clean up
				goto ERROR_AFTER_HOLES;
			}

			if( nvlist_add_uint64( nvlHole, ZPOOL_CONFIG_GUID, 0ULL ) )
			{
				syslog( LOG_ERR, "Failed to set hole nvlist guid." );
				numHoles = 1;	//Only one hole to clean up
				goto ERROR_AFTER_HOLES;
			}

			aTlVDev[ auHoles[ 0 ] ].nvl = nvlHole;

			for( unsigned uHole = 1; uHole < numHoles; ++uHole )
			{
				nvlist_t *nvl;
				if( nvlist_dup( nvlHole, &nvl, 0 ) )
				{
					syslog( LOG_ERR, "Failed to copy nvlist for pool holes." );
					numHoles = uHole;	//Only clean up what was created so far
					goto ERROR_AFTER_HOLES;
				}

				if( nvlist_add_uint64( nvlHole, ZPOOL_CONFIG_ID, auHoles[ uHole ] ) )
				{
					syslog( LOG_ERR, "Failed to set hole nvlist config id %" PRIu64 ".", auHoles[ uHole ] );
					numHoles = uHole;	//Only clean up what was created so far
					goto ERROR_AFTER_HOLES;
				}

				aTlVDev[ auHoles[ uHole ] ].nvl = nvlHole;
			}

			//The template did not have the config id set (needed to be added per copy). Complete it.
			if( nvlist_add_uint64( nvlHole, ZPOOL_CONFIG_ID, auHoles[ 0 ] ) )
			{
				syslog( LOG_ERR, "Failed to set hole nvlist config id %" PRIu64 ".", auHoles[ 0 ] );
				goto ERROR_AFTER_HOLES;
			}
		}

		//Compress the list of top-level vdevs in preparation for insertion into the pool config
		unsigned numMissing = 0;
		nvlist_t **const anvlChildren = (nvlist_t **) aTlVDev;
		for( uint64_t uChild = 0; uChild < numChildren; ++uChild )
			if( !( anvlChildren[ uChild ] = aTlVDev[ uChild ].nvl ) )
				++numMissing;

		{
			//Fill missing children with dummy vdevs. This entails data loss and should not happen normally.
			nvlist_t *anvlMissing[ numMissing ];
			if( numMissing )
			{
				syslog( LOG_WARNING, "%u top-level vdevs are missing!", numMissing );

				for( unsigned uMissing = 0; uMissing < numMissing; ++uMissing )
				{
					nvlist_t *nvlMissing;
					if( nvlist_alloc( &nvlMissing, NV_UNIQUE_NAME, 0 ) )
					{
						syslog( LOG_ERR, "Failed to allocate nvlist for missing top-level vdev." );
						numMissing = uMissing;	//Only clean up what was created so far
						goto ERROR_AFTER_MISSING;
					}
					anvlMissing[ uMissing ] = nvlMissing;	//Ensure cleanup will cover the config in case of error

					if( nvlist_add_string( nvlMissing, ZPOOL_CONFIG_TYPE, VDEV_TYPE_MISSING ) )
					{
						syslog( LOG_ERR, "Failed to set missing vdev type." );
						numMissing = uMissing + 1;	//Only clean up what was created so far
						goto ERROR_AFTER_MISSING;
					}

					if( nvlist_add_uint64( nvlMissing, ZPOOL_CONFIG_GUID, 0ULL ) )
					{
						syslog( LOG_ERR, "Failed to set missing vdev guid." );
						numMissing = uMissing + 1;	//Only clean up what was created so far
						goto ERROR_AFTER_MISSING;
					}
				}

				//Patch the missing vdevs
				unsigned uMissing = 0;
				for( uint64_t uChild = 0; uChild < numChildren; ++uChild )
				{
					if( anvlChildren[ uChild ] )
						continue;

					anvlChildren[ uChild ] = anvlMissing[ uMissing++ ];
				}
			}

			//At this point, anvlChildren is a complete array of numChildren children. Create the pool side of the vdev configuration

			//Create the root vdev
			nvlist_t *nvlRoot;
			if( nvlist_alloc( &nvlRoot, NV_UNIQUE_NAME, 0 ) )
			{
				syslog( LOG_ERR, "Failed to create root vdev." );
				goto ERROR_AFTER_MISSING;
			}

			//Add the array of children into the root vdev
			if( nvlist_add_nvlist_array( nvlRoot, ZPOOL_CONFIG_CHILDREN, (const nvlist_t **) anvlChildren, numChildren ) )
			{
				syslog( LOG_ERR, "Failed to add children to root vdev." );
				nvlist_free( nvlRoot );
				goto ERROR_AFTER_MISSING;
			}

			//Cleanup of all temporary data - everything is now contained in nvlRoot and nvlPool
			{
				for( unsigned uMissing = 0; uMissing < numMissing; ++uMissing )
					nvlist_free( anvlMissing[ uMissing ] );
				for( uint uHole = 0; uHole < numHoles; ++uHole )
					nvlist_free( anvlHoles[ uHole ] );
				free( aTlVDev );
				for( ; uVDev < numVDevs; ++uVDev )
					nvlist_free( anvlRedundant[ uVDev ] );
			}

			if( nvlist_add_string( nvlRoot, ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT ) )
			{
				syslog( LOG_ERR, "Failed to set type of root vdev." );
				goto ERROR_AFTER_ROOT;
			}
			
			if( nvlist_add_uint64( nvlRoot, ZPOOL_CONFIG_ID, 0ULL ) )
			{
				syslog( LOG_ERR, "Failed to set id of root vdev." );
				goto ERROR_AFTER_ROOT;
			}
			
			if( nvlist_add_uint64( nvlRoot, ZPOOL_CONFIG_GUID, idPool ) )
			{
				syslog( LOG_ERR, "Failed to set guid of root vdev." );
				goto ERROR_AFTER_ROOT;
			}

			if( nvlist_add_nvlist( nvlPool, ZPOOL_CONFIG_VDEV_TREE, nvlRoot ) )
			{
				syslog( LOG_ERR, "Failed to add root vdev to pool config." );
				nvlist_free( nvlRoot );
				nvlist_free( nvlPool );
			}

			nvlist_free( nvlRoot );
			return nvlPool;

ERROR_AFTER_ROOT:
			nvlist_free( nvlRoot );
			nvlist_free( nvlPool );
			return NULL;

ERROR_AFTER_MISSING:
			for( unsigned uMissing = 0; uMissing < numMissing; ++uMissing )
				nvlist_free( anvlMissing[ uMissing ] );
		}
ERROR_AFTER_HOLES:
		for( uint uHole = 0; uHole < numHoles; ++uHole )
			nvlist_free( anvlHoles[ uHole ] );
	}
ERROR_AFTER_POOL:
	nvlist_free( nvlPool );
ERROR_AFTER_TLVDEV:
	free( aTlVDev );
ERROR_AFTER_VDEV:
	for( ; uVDev < numVDevs; ++uVDev )
		nvlist_free( anvlRedundant[ uVDev ] );
	return NULL;
}

static unsigned long GetHostID( void )
{
	FILE *const f = fopen( "/proc/sys/kernel/spl/hostid", "re" );
	if( !f )
	{
		syslog( LOG_ERR, "Failed to open spl file for host id." );
		return 0;
	}

	unsigned long uHostID;
	if( fscanf( f, "%lx", &uHostID ) != 1 )
	{
		syslog( LOG_ERR, "Failed to retrieve host id." );
		uHostID = 0;
	}

	fclose( f );
	return uHostID;
}

/*!
	\param szzVDevs A list of vdev paths. VDevs are separated with NULL-terminators, the list itself is finalized with a second NULL-terminators (i.e. doubly terminated at the end).
*/
bool ImportPool( const int fdZFS, const char *const szzVDevs, const char *const szPool, const uint64_t idPool )
{
	//Load the configuration from the vdevs, then perform the first import step (TRYIMPORT)
	nvlist_t *nvlPool = LoadPoolConfig( szzVDevs, szPool, idPool );
	if( !nvlPool )
		return false;

	zfs_cmd_t zc = { 0 };

	//Pack proto config and free the source
	{
		static_assert( sizeof( size_t ) == sizeof( zc.zc_nvlist_conf_size ) );
		if( nvlist_size( nvlPool, &zc.zc_nvlist_conf_size, NV_ENCODE_NATIVE ) )
		{
			syslog( LOG_ERR, "Failed to get size of pool configuration." );
			goto ERROR_AFTER_POOL;	//zc_nvlist_conf and zc_nvlist_dst are both NULL, so free will just ignore them. 
		}

		if( !( zc.zc_nvlist_conf = (uint64_t) malloc( zc.zc_nvlist_conf_size ) ) )
		{
			syslog( LOG_ERR, "Failed to allocate memory for packed pool configuration." );
			goto ERROR_AFTER_POOL;	//zc_nvlist_conf and zc_nvlist_dst are both NULL, so free will just ignore them.
		}

		if( nvlist_pack( nvlPool, (char **) &zc.zc_nvlist_conf, &zc.zc_nvlist_conf_size, NV_ENCODE_NATIVE, 0 ) )
		{
			syslog( LOG_ERR, "Failed to pack pool configuration." );
			goto ERROR_AFTER_CONF;
		}

		nvlist_free( nvlPool );
	}

	//Allocate space for the nvlist returned by the kernel
	uint64_t uDstSize = zc.zc_nvlist_dst_size = MAX( CONFIG_BUF_MINSIZE, zc.zc_nvlist_conf_size * 32 );
	zc.zc_nvlist_dst = (uint64_t) calloc( 1, zc.zc_nvlist_dst_size );
	if( !zc.zc_nvlist_dst )
	{
		syslog( LOG_ERR, "Failed to allocate memory for imported pool configuration." );
		goto ERROR_AFTER_CONF;
	}

	//Perform the TRYIMPORT step
TRYIMPORT_CONFIG:
	if( lzc_ioctl_fd( fdZFS, ZFS_IOC_POOL_TRYIMPORT, &zc ) == -1 )
		switch( errno )
		{
		case ENOMEM:
			//If the destination buffer was too small, the kernel updated zc_nvlist_dst_size with the actual size needed
			free( (void *) zc.zc_nvlist_dst );
			zc.zc_nvlist_dst = (uint64_t) calloc( 1, zc.zc_nvlist_dst_size );
			if( !zc.zc_nvlist_dst )
			{
				syslog( LOG_ERR, "Failed to allocate memory for imported proto-pool configuration." );
				goto ERROR_AFTER_CONF;
			}
			uDstSize = zc.zc_nvlist_dst_size;
			goto TRYIMPORT_CONFIG;
		default:
			syslog( LOG_ERR, "Failed to import proto-pool. Error code %d.", errno );
			goto ERROR_AFTER_DST;
		}

	//Unpack the pool configuration
	if( nvlist_unpack( (void *) zc.zc_nvlist_dst, zc.zc_nvlist_dst_size, &nvlPool, 0 ) )
	{
		syslog( LOG_ERR, "Failed to unpack imported pool configuration." );
		goto ERROR_AFTER_DST;
	}
	
	//Check for supported version
	{
		uint64_t uVersion;
		if( nvlist_lookup_uint64( nvlPool, ZPOOL_CONFIG_VERSION, &uVersion ) )
		{
			syslog( LOG_ERR, "Failed to retrieve pool version." );
			goto ERROR_AFTER_POOL;
		}

		if( !SPA_VERSION_IS_SUPPORTED( uVersion ) )
		{
			syslog( LOG_ERR, "Cannot import '%s': pool is formatted using an unsupported ZFS version", szPool );
			goto ERROR_AFTER_POOL;
		}
	}

	//Check if the pool is importable
	{
		nvlist_t *nvlLoadInfo;
		if( nvlist_lookup_nvlist( nvlPool, ZPOOL_CONFIG_LOAD_INFO, &nvlLoadInfo ) )
		{
			syslog( LOG_ERR, "Failed to retrieve load info from pool." );
			goto ERROR_AFTER_POOL;
		}

		//Ensure that the pool belongs to the current system
		{
			uint64_t eState;
			if( nvlist_lookup_uint64( nvlPool, ZPOOL_CONFIG_POOL_STATE, &eState ) )
			{
				syslog( LOG_ERR, "Failed to retrieve pool state." );
				goto ERROR_AFTER_POOL;
			}

			if( eState == POOL_STATE_EXPORTED )
			{
				uint64_t uHostID;
				if( nvlist_lookup_uint64( nvlLoadInfo, ZPOOL_CONFIG_HOSTID, &uHostID ) )
				{
					//The hostid on LOAD_INFO comes from the MOS label via spa_tryimport().
					//If its not there then we're likely talking to an older kernel, so use the top one.
					if( nvlist_lookup_uint64( nvlPool, ZPOOL_CONFIG_HOSTID, &uHostID ) )
					{
						syslog( LOG_ERR, "Failed to retrieve hostid from pool." );
						goto ERROR_AFTER_POOL;
					}
				}

				const unsigned long uLocalHostID = GetHostID( );
				if( !uLocalHostID )
					goto ERROR_AFTER_POOL;

				if( uHostID != uLocalHostID )
				{
					syslog( LOG_ERR, "The pool \"%s\" was exported on a different system. Please use the zpool tool to import.", szPool );
					goto ERROR_AFTER_POOL;
				}
			}
		}

		//Check the Multi-Modifier Protection (MMP) state
		{
			uint64_t eMMP;
			if( !nvlist_lookup_uint64( nvlLoadInfo, ZPOOL_CONFIG_MMP_STATE, &eMMP ) )
			{
				if( eMMP != MMP_STATE_INACTIVE )
				{
					syslog( LOG_ERR, "The pool has Multi-Mode Protection (MMP) enabled. This is currently not supported by this importer." );
					goto ERROR_AFTER_POOL;
				}
			}
		}
	}

	//Pack pool config and free the source
	{
		static_assert( sizeof( size_t ) == sizeof( zc.zc_nvlist_conf_size ) );
		if( nvlist_size( nvlPool, &zc.zc_nvlist_conf_size, NV_ENCODE_NATIVE ) )
		{
			syslog( LOG_ERR, "Failed to get size of pool configuration." );
			goto ERROR_AFTER_POOL;
		}

		void *const p = realloc( (void *) zc.zc_nvlist_conf, zc.zc_nvlist_conf_size );
		if( !p )
		{
			syslog( LOG_ERR, "Failed to allocate memory for packed pool configuration." );
			goto ERROR_AFTER_POOL;
		}
		zc.zc_nvlist_conf = (uint64_t) p;

		if( nvlist_pack( nvlPool, (char **) &zc.zc_nvlist_conf, &zc.zc_nvlist_conf_size, NV_ENCODE_NATIVE, 0 ) )
		{
			syslog( LOG_ERR, "Failed to pack pool configuration." );
			goto ERROR_AFTER_CONF;
		}

		nvlist_free( nvlPool );
	}

	zc.zc_nvlist_dst_size = uDstSize;
	zc.zc_guid = idPool;
	(void) strlcpy( zc.zc_name, szPool, sizeof( zc.zc_name ) );

	//Perform the IMPORT step
IMPORT_CONFIG:
	if( lzc_ioctl_fd( fdZFS, ZFS_IOC_POOL_IMPORT, &zc ) == -1 )
		switch( errno )
		{
		case ENOMEM:
			//If the destination buffer was too small, the kernel updated zc_nvlist_dst_size with the actual size needed
			free( (void *) zc.zc_nvlist_dst );
			zc.zc_nvlist_dst = (uint64_t) calloc( 1, zc.zc_nvlist_dst_size );
			if( !zc.zc_nvlist_dst )
			{
				syslog( LOG_ERR, "Failed to allocate memory for imported pool configuration." );
				goto ERROR_AFTER_CONF;
			}
			goto IMPORT_CONFIG;
		default:
			syslog( LOG_ERR, "Failed to import pool. Error code %d.", errno );
			goto ERROR_AFTER_DST;
		}

	//Debug: Print imported configuration
#if 0
	{
		//Unpack the pool configuration
		if( nvlist_unpack( (void *) zc.zc_nvlist_dst, zc.zc_nvlist_dst_size, &nvlPool, 0 ) )
		{
			syslog( LOG_ERR, "Failed to unpack imported pool configuration." );
			goto ERROR_AFTER_DST;
		}

		puts( "Imported configuration:" );
		print_nvlist( nvlPool, 1 );
		fflush( stdout );
		nvlist_free( nvlPool );
	}
#endif

	free( (void *) zc.zc_nvlist_dst );
	free( (void *) zc.zc_nvlist_conf );
	return true;

ERROR_AFTER_POOL:
	nvlist_free( nvlPool );
ERROR_AFTER_DST:
	free( (void *) zc.zc_nvlist_dst );
ERROR_AFTER_CONF:
	free( (void *) zc.zc_nvlist_conf );
	return false;
}

/*!
	\param zc	Command structure with pre-filled \c zc_name field and \c NULL or pre-allocated (using calloc) \c zc_nvlist_dst with matching \c zc_nvlist_dst_size field. Further fields dependent on \p uCommand.
	\details	If the \p zc \c zc_nvlist_dst field is too small, it is re-allocated to a matching buffer (overriding \c zc_nvlist_dst_size).
				If an error occurs, the \c zc_nvlist_dst field is freed.
	\warning Manipulates and/or frees \p zc \c zc_nvlist_dst! See detailed function description for more info.
*/
static nvlist_t *LoadStats( const int fdZFS, const unsigned long uCommand, zfs_cmd_t *const zc, const size_t uNameLength )
{
	/*
		ZFS_IOC_DATASET_LIST_NEXT will use the member zc_name and return the next child dataset below.
		The member zc_cookie is used to identify the position within the children of the original zc_name.
		Starting at 0 for zc_cookie, the first child is returned. Re-inserting the same parent-name as zc_name but the cookie from a child will return the next child in list.
	*/
	const uint64_t uCurrentCookie = zc->zc_cookie;
	zc->zc_objset_stats.dds_creation_txg = 0;
	uint64_t uDstSize = zc->zc_nvlist_dst_size;

TRYIMPORT_CONFIG:
	if( lzc_ioctl_fd( fdZFS, uCommand, zc ) == -1 )
		switch( errno )
		{
		case ESRCH:
			return NULL;
		case ENOMEM:
			//If the destination buffer was too small, the kernel updated zc_nvlist_dst_size with the actual size needed
			free( (void *) zc->zc_nvlist_dst );
			zc->zc_nvlist_dst = (uint64_t) calloc( 1, zc->zc_nvlist_dst_size );
			if( !zc->zc_nvlist_dst )
			{
				syslog( LOG_ERR, "Failed to allocate memory for dataset listing." );
				return NULL;
			}

			//ZFS_IOC_DATASET_LIST_NEXT will have already loaded the name and cookie of the next child. Restore the parent's name and cookie of the previous sibling.
			zc->zc_cookie = uCurrentCookie;
			zc->zc_name[ uNameLength ] = '\0';	
			uDstSize = zc->zc_nvlist_dst_size;
			goto TRYIMPORT_CONFIG;
		case ENOENT:
			syslog( LOG_ERR, "Failed to list datasets: the underlying dataset has been removed." );
			free( (void *) zc->zc_nvlist_dst );
			return NULL;
		default:
			syslog( LOG_ERR, "Failed to list datasets. Error code %d.", errno );
			free( (void *) zc->zc_nvlist_dst );
			return NULL;
		}

	nvlist_t *nvl;
	if( nvlist_unpack( (void *) zc->zc_nvlist_dst, zc->zc_nvlist_dst_size, &nvl, 0 ) )
	{
		syslog( LOG_ERR, "Failed to unpack imported pool configuration." );
		free( (void *) zc->zc_nvlist_dst );
		return NULL;
	}

	zc->zc_nvlist_dst_size = uDstSize;
	return nvl;
}

/*!
	\param szPath	The path to create. On error, this string is shortened to the subpath that failed.
*/
static int mkdirp( char *szPath, mode_t mode )
{
	for( char *pSeparator = szPath[ 0 ] == '/' ? szPath + 1 : szPath; *pSeparator; ++pSeparator )
	{
		if( pSeparator[ 0 ] != '/' )
			continue;

		pSeparator[ 0 ] = '\0';
		if( mkdir( szPath, mode ) && errno != EEXIST )
			return -1;

		pSeparator[ 0 ] = '/';
	}

	return mkdir( szPath, mode );
}

static bool MountDataset( const char *const szDataset, nvlist_t *const nvl, const char *const szAlternateRoot, const size_t lenAlternateRoot, const bool fReadonly )
{
	//Ensure that the encryption key (if needed) is loaded
	{
		nvlist_t *nvlKeystatus;
		if( nvlist_lookup_nvlist( (nvlist_t *) nvl, "keystatus", &nvlKeystatus ) )
		{
			syslog( LOG_ERR, "Failed to find keystatus property for dataset \"%s\".", szDataset );
			return false;
		}

		uint64_t eKeyStatus;
		if( nvlist_lookup_uint64( nvlKeystatus, ZPROP_VALUE, &eKeyStatus ) )
		{
			syslog( LOG_ERR, "Failed to find keystatus value for dataset \"%s\".", szDataset );
			return false;
		}

		if( eKeyStatus == ZFS_KEYSTATUS_UNAVAILABLE )
		{
			syslog( LOG_ERR, "Dataset \"%s\" requires a key that isn't loaded.", szDataset );
			return false;
		}
	}

	//Ensure that the canmount is enabled
	{
		nvlist_t *nvlCanMount;
		if( !nvlist_lookup_nvlist( (nvlist_t *) nvl, "canmount", &nvlCanMount ) )
		{
			uint64_t eCanMount;
			if( nvlist_lookup_uint64( nvlCanMount, ZPROP_VALUE, &eCanMount ) )
			{
				syslog( LOG_ERR, "Failed to find canmount value for dataset \"%s\".", szDataset );
				return false;
			}

			if( eCanMount == ZFS_CANMOUNT_OFF )
				return true;	//Marked as not mountable, nothing to do
		}
	}

	//Ensure that the dataset is not redacted
	{
		nvlist_t *nvlRedacted;
		if( !nvlist_lookup_nvlist( (nvlist_t *) nvl, "redacted", &nvlRedacted ) )
		{
			syslog( LOG_ERR, "Dataset \"%s\" is redacted. This feature is currently not supported by this importer.", szDataset );
			return false;
		}
	}

	//Ensure that the dataset is not zoned
	{
		nvlist_t *nvlZoned;
		if( !nvlist_lookup_nvlist( (nvlist_t *) nvl, PROP_ZONED, &nvlZoned ) )
		{
			uint64_t fZoned;
			if( nvlist_lookup_uint64( nvlZoned, ZPROP_VALUE, &fZoned ) )
			{
				syslog( LOG_ERR, "Failed to find zoned value for dataset \"%s\".", szDataset );
				return false;
			}

			if( fZoned )
			{
				syslog( LOG_ERR, "Dataset \"%s\" is zoned. This feature is currently not supported by this importer.", szDataset );
				return false;
			}
		}
	}

	//Fetch mountpoint
	char *szMountPoint;
	{
		nvlist_t *nvlMountPoint;
		if( nvlist_lookup_nvlist( (nvlist_t *) nvl, "mountpoint", &nvlMountPoint ) )
		{
			syslog( LOG_ERR, "Failed to find mountpoint property for dataset \"%s\".", szDataset );
			return false;
		}

		const char *szValue;
		if( nvlist_lookup_string( nvlMountPoint, ZPROP_VALUE, &szValue ) )
		{
			syslog( LOG_ERR, "Failed to find mountpoint value for dataset \"%s\".", szDataset );
			return false;
		}

		if( !strcmp( szValue, "none" ) )
			return true;

		if( !strcmp( szValue, "legacy" ) )
		{
			syslog( LOG_ERR, "Dataset \"%s\" uses unsupported \"legacy\" mountpoint.", szDataset );
			return false;
		}

		const char *szSource;
		if( nvlist_lookup_string( nvlMountPoint, ZPROP_SOURCE, &szSource ) )
		{
			syslog( LOG_ERR, "Failed to find mountpoint source for dataset \"%s\".", szDataset );
			return false;
		}

		if( !strcmp( szSource, ZPROP_SOURCE_VAL_RECVD ) )
		{
			syslog( LOG_ERR, "Failed to find mountpoint source for dataset \"%s\": Received datasets are currently not supported by this importer.", szDataset );
			return false;
		}

		const char *const szRelativePath = szDataset + strlen( szSource );
		if( strncmp( szDataset, szSource, strlen( szSource ) ) || szRelativePath[ 0 ] != '\0' && szRelativePath[ 0 ] != '/' )
		{
			syslog( LOG_ERR, "Mountpoint source for dataset \"%s\" is corrupted.", szDataset );
			return false;
		}

		const size_t lenValue = strlen( szValue );
		const size_t lenRelativePath = strlen( szRelativePath );
		szMountPoint = alloca( lenAlternateRoot + lenValue + lenRelativePath + 1 );
		memcpy( szMountPoint, szAlternateRoot, lenAlternateRoot );
		memcpy( szMountPoint + lenAlternateRoot, szValue, lenValue );
		memcpy( szMountPoint + lenAlternateRoot + lenValue, szRelativePath, lenRelativePath );
		szMountPoint[ lenAlternateRoot + lenValue + lenRelativePath ] = '\0';
	}

	//Ensure the path exists
	if( mkdirp( szMountPoint, 0755 ) )
	{
		if( errno != EEXIST )
		{
			syslog( LOG_ERR, "Failed to create path for mountpoint: \"%s\".", szMountPoint );
			return false;
		}

		//The path existed, ensure the folder is emtpy
		{
			DIR *const dir = opendir( szMountPoint );
			if( !dir )
			{
				syslog( LOG_ERR, "Failed to check if directory \"%s\" is empty.", szMountPoint );
				return false;
			}

			int numEntries = 0;
			for( struct dirent *pDirEnt; pDirEnt = readdir( dir ); )
				if( ++numEntries > 2 )
				{
					syslog( LOG_ERR, "Mounting directory \"%s\" is not empty.", szMountPoint );
					closedir( dir );
					return false;
				}

			closedir(dir);
		}
	}

	if( mount( szDataset, szMountPoint, MNTTYPE_ZFS, 0, NULL ) )
	{
		syslog( LOG_ERR, "Failed to mount dataset \"%s\".", szDataset );
		return false;
	}

	syslog( LOG_INFO, "Dataset \"%s\" mounted at \"%s\".", szDataset, szMountPoint );

	//TODO: zfs_share_one

	return true;
}

/*!
	\param zc	Command structure with pre-filled \c zc_name field and \c NULL or pre-allocated (using calloc) \c zc_nvlist_dst with matching \c zc_nvlist_dst_size field.
	\details If the \p zc \c zc_nvlist_dst field is too small, it is re-allocated to a matching buffer (overriding \c zc_nvlist_dst_size).
		If an error occurs, the \c zc_nvlist_dst field is freed.
	\warning Manipulates and/or frees \p zc \c zc_nvlist_dst! See detailed function description for more info.
*/
static bool MountChildren( const int fdZFS, zfs_cmd_t *const zc, const uint16_t uNameLength )
{
	static_assert( UINT16_MAX >= sizeof( zc->zc_name ) );
	for( nvlist_t *nvl; nvl = LoadStats( fdZFS, ZFS_IOC_DATASET_LIST_NEXT, zc, uNameLength ); )
	{
		if( !MountDataset( zc->zc_name, nvl, NULL, 0, false ) )
			goto ERROR_AFTER_NVL;
		nvlist_free( nvl );

		//Mount all children of the current dataset
		const uint64_t uCookie = zc->zc_cookie;
		zc->zc_cookie = 0;	//Start with the first child
		if( !MountChildren( fdZFS, zc, (uint16_t) strlen( zc->zc_name ) ) )
			return false;

		//All children processed. Restore the command structure for this dataset to find the next sibling
		zc->zc_cookie = uCookie;
		zc->zc_name[ uNameLength ] = '\0';
		continue;

ERROR_AFTER_NVL:
		nvlist_free( nvl );
		free( (void *) zc->zc_nvlist_dst );
		return false;
	}

	return errno == ESRCH;	//ESRCH indicates no more children -> Success
}

bool MountPool( int fdZFS, const char *const szPool )
{
	zfs_cmd_t zc = { 0 };

	//Allocate space for the nvlist returned by the kernel
	zc.zc_nvlist_dst_size = MAX( CONFIG_BUF_MINSIZE, 256 * 1024 );
	zc.zc_nvlist_dst = (uint64_t) calloc( 1, zc.zc_nvlist_dst_size );
	if( !zc.zc_nvlist_dst )
	{
		syslog( LOG_ERR, "Failed to allocate memory for imported pool configuration." );
		return false;
	}

	//Mount the root dataset
	const size_t lenName = strlcpy( zc.zc_name, szPool, sizeof( zc.zc_name ) );
	{
		//Reload the dataset to ensure that the key is now loaded
		nvlist_t *const nvlDataset = LoadStats( fdZFS, ZFS_IOC_OBJSET_STATS, &zc, lenName );
		if( !nvlDataset )
			return false;	//LoadStats will clean up zc_nvlist_dst on error

		if( !MountDataset( szPool, nvlDataset, NULL, 0, false ) )
		{
			nvlist_free( nvlDataset );
			free( (void *) zc.zc_nvlist_dst );
			return false;
		}

		nvlist_free( nvlDataset );
	}

	if( !MountChildren( fdZFS, &zc, lenName ) )
		return false;	//MountChildren (or specifically, LoadStats) will clean up zc_nvlist_dst on error

	free( (void *) zc.zc_nvlist_dst );
	return true;
}

bool LoadPoolKey( const char *const szEncryptionRoot, const block256_t ymmKey )
{
	const int iRet = lzc_load_key( szEncryptionRoot, false, (char *) ymmKey.ab, sizeof( ymmKey ) );
	if( iRet )
	{
		const char *szError;
		switch( iRet )
		{
		case EPERM:
			szError = "Permission denied.";
			break;
		case EINVAL:
			szError = "Invalid parameters provided.";
			break;
		case EEXIST:
			szError = "Key already loaded.";
			break;
		case EBUSY:
			szError = "Dataset is busy.";
			break;
		case EACCES:
			szError = "Incorrect key provided.";
			break;
		case ZFS_ERR_CRYPTO_NOTSUP:
			szError = "Dataset uses an unsupported encryption suite.";
			break;
		default:
			syslog( LOG_ERR, "Failed to load key for encryption root \"%s\": Unknown error %d.", szEncryptionRoot, iRet );
			return false;
		}
		syslog( LOG_ERR, "Failed to load key for encryption root \"%s\": %s", szEncryptionRoot, szError );
		return false;
	}

	return true;
}

void print_nvlist( nvlist_t *nvl, int indent )
{
	nvpair_t *nvp = NULL;
	while( nvp = nvlist_next_nvpair( nvl, nvp ) )
	{
		for( int i = 0; i < indent; i++ )
			putchar( '\t' );
		const char *name = nvpair_name( nvp );

		switch( nvpair_type( nvp ) )
		{
		case DATA_TYPE_STRING:
			{
				const char *value;
				nvpair_value_string( nvp, &value );
				printf( "%s = \"%s\"\n", name, value );
				break;
			}
		case DATA_TYPE_UINT32:
			{
				uint32_t value;
				nvpair_value_uint32( nvp, &value );
				printf( "%s = %u (uint32)\n", name, (unsigned) value );
				break;
			}
		case DATA_TYPE_UINT64:
			{
				uint64_t value;
				nvpair_value_uint64( nvp, &value );
				printf( "%s = %llu (uint64)\n", name, (unsigned long long) value );
				break;
			}
		case DATA_TYPE_NVLIST:
			{
				nvlist_t *child;
				nvpair_value_nvlist( nvp, &child );
				printf( "%s = {\n", name );
				print_nvlist( child, indent + 1 );
				for( int i = 0; i < indent; i++ )
					putchar( '\t' );
				printf( "}\n" );
				break;
			}
		case DATA_TYPE_NVLIST_ARRAY:
			{
				nvlist_t **array;
				uint_t nelem;
				nvpair_value_nvlist_array( nvp, &array, &nelem );
				printf( "%s = [\n", name );
				for( uint_t i = 0; i < nelem; i++ )
				{
					for( int j = 0; j < indent + 1; j++ )
						putchar('\t');
					printf( "{\n" );
					print_nvlist( array[i], indent + 2 );
					for( int j = 0; j < indent + 1; j++ )
						putchar( '\t' );
					printf( "}%s\n", (i == nelem - 1) ? "" : "," );
				}
				for( int i = 0; i < indent; i++ )
					putchar( '\t' );
				printf( "]\n" );
				break;
			}
		default:
			printf( "%s = <unhandled type %d>\n", name, nvpair_type( nvp ) );
		}
	}
}