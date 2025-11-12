# zfstools

This repository contains a collection of tools indended for minimal server builds to load a key using a YubiKey, then import and mount ZFS pools with encrypted datasets.

## Library loadkey
This library allows deriving a Key Encryption Key (KEK) from a YubiKey certificate slot (9a, 9c, 9d or 9e). 
This KEK is then used to unpack a wrapped dataset encryption key. Note that this unpack operation is **not** a decryption, but rather an encryption using a 256bit Rijndael cipher (the algorithm chosen for AES). The operations are reversible, meaning there is no security difference to decryption first, then encryption to get the plaintext back. However, an encryption can be performed straight forward, while a decryption requires a reversed key schedule. As such, the wrapped key provided to a call to **LoadKey** must have been wrapped using a 256 bit Rijndael decryption operation.

The following options must be provided to cmake:
### ID_KEY
This is the id that identifies the certificate slot. It is **not** matching the labeling you'll find listed by Yubico applications. Instead, these are mapped as follows:
9a -> 01
9c -> 02
9d -> 03
9e -> 04
Example cmake option: -DID_KEY=03

### PEM
To derive the KEK, the public key from the Privacy-Enhanced Mail (PEM) file is needed.
Example cmake option: -DPEM=04164754C5DE45D1683D2AC40FDD8BFA80B0199D9719CD0B19DC051A83ABF101020AAB4F74F8C000B7231AC460526AA51FC9F9F47C294C811887AB29A2F1D88B5C

### DEBUG_KEY
This optional option allows providing a test key directly. If this option is set, no attempt will be made to query a YubiKey. Instead, the value of DEBUG_KEY is returned immediately.
Example cmake option: -DDEBUG_KEY=DEADBEEFADECAFC0FFEEDEFACEDECADE0001020305060708090A0B0C0D0E1011

## Library zfstools
This library provides functions to import a ZFS pool, load required keys and mount the contained datasets. It is purely based on libzfs_core.
## Executable zfsmount
This executable is intended to replace zpool on minimal systems. When run, it uses the loadkey library to fetch a dataset encryption key, then uses the library zfstools to import a given pool, load the root dataset key and mount all contained datasets.

The following options must be provided to cmake:
### POOL_NAME
The name of the pool to be imported
Example cmake option: -DPOOL_NAME=data
### POOL_ID
The ID of the pool to be imported
Example cmake option: -DPOOL_ID=12345
### POOL_VDEVS
The VDevs to be scanned for the pool. VDevs must be terminated using '\0'.
Example cmake option: -DPOOL_VDEVS=/dev/sda1\0/dev/sdb1\0/dev/sdc1\0/dev/sdd1\0
### KEY_WRAPPED
The wrapped key that will be decrypted using loadkey.
Example cmake option: -DKEY_WRAPPED=DEADBEEFADECAFC0FFEEDEFACEDECADE0001020305060708090A0B0C0D0E1011
## Executable writekey
This executable allows fetching the dataset encryption key using a YubiKey, then stores the key in file pointed to by the first argument passed to the executable. This is needed to use the standard zfs tools (e.g. zpool, among others when creating the pool in the first place).

The following options must be provided to cmake:
### KEY_WRAPPED
See zfsmount.