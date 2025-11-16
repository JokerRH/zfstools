
# zfstools

This repository contains a collection of tools indended for minimal server builds to load a key using a YubiKey, then import and mount ZFS pools with encrypted datasets.

## Library loadkey
This library allows deriving a Key Encryption Key (KEK) from a YubiKey certificate slot (9a, 9c, 9d or 9e). 
This KEK is then used to unpack a wrapped dataset encryption key. Note that this unpack operation is **not** a decryption, but rather an encryption using a 256bit Rijndael cipher (the algorithm chosen for AES). The operations are reversible, meaning there is no security difference to decryption first, then encryption to get the plaintext back. However, an encryption can be performed straight forward, while a decryption requires a reversed key schedule. As such, the wrapped key provided to a call to **LoadKey** must have been wrapped using a 256 bit Rijndael decryption operation.

Note that unfortunately, yubico-piv-tool does not expose the necessary headers for pkcs11. You will need to add
```
install(FILES pkcs11y.h DESTINATION ${YKPIV_INSTALL_INC_DIR}/ykpiv)
install(FILES pkcs11.h DESTINATION ${YKPIV_INSTALL_INC_DIR}/ykpiv)
install(FILES pkcs11t.h DESTINATION ${YKPIV_INSTALL_INC_DIR}/ykpiv)
install(FILES pkcs11f.h DESTINATION ${YKPIV_INSTALL_INC_DIR}/ykpiv)
```
In the ykcs11/CMakeLists.txt file (and make sure that ykcs11 is not disabled).
Then, in ykcs11/ykcs11.pc.in, add this line at the end:
```
Cflags: -I${includedir}
```


The following options must be provided to cmake:
### DEBUG_KEY
This optional option allows providing a test key directly. If this option is set, no attempt will be made to query a YubiKey. Instead, the value of DEBUG_KEY is returned immediately.
Example cmake option: -DDEBUG_KEY=DEADBEEFADECAFC0FFEEDEFACEDECADE0001020305060708090A0B0C0D0E1011

## Library zfstools
This library provides functions to import a ZFS pool, load required keys and mount the contained datasets. It is purely based on libzfs_core.
Note that libzfs_core does not normally provide the zfs_cmd_t struct needed for ioctl commands to /dev/zfs. zfstools expects this struct in a header file called zfs_cmd.h. You will need to create this manually by copying in the zfs_cmd_t struct from zfs/include/sys/zfs_ioctl.h (or find a way to include that header without messing up your build system).
## Executable keysetup
This is a helper executable that can provide you the public key in PEM format (65 byte), as well as wrap or unwrap keys. The output of this tool is needed for zfsmount and writekey.
Run it without arguments to get an argument overview. When running with arguments, you will need your YubiKey.
**Note that this expects a 256 bit ECC key!**
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
The VDevs to be scanned for the pool. VDevs must be separated using ':'.
Example cmake option: -DPOOL_VDEVS=/dev/sda1:/dev/sdb1:/dev/sdc1:/dev/sdd1
Note that internally, vdevs are terminated using individual '\0' characters, with a double '\0' terminating the string.
### ID_KEY
This is the id that identifies the certificate slot. It is **not** matching the labeling you'll find listed by Yubico applications. Instead, these are mapped as follows:
9a -> 01
9c -> 02
9d -> 03
9e -> 04
The value you type will be interpreted as hexadecimal.
Example cmake option: -DID_KEY=03

### PEM
To derive the KEK, the public key from the Privacy-Enhanced Mail (PEM) file is needed. You can generate it using the keysetup tool. It could be extracted automatically (as keysetup does), but is tied to the wrapped key anyways. As such, it was chosen to be hardcoded to simplify this essential tool.
Example cmake option: -DPEM=04164754C5DE45D1683D2AC40FDD8BFA80B0199D9719CD0B19DC051A83ABF101020AAB4F74F8C000B7231AC460526AA51FC9F9F47C294C811887AB29A2F1D88B5C
### KEY_WRAPPED
The wrapped key that will be decrypted using loadkey. You can wrap your own key using the keysetup tool.
Example cmake option: -DKEY_WRAPPED=DEADBEEFADECAFC0FFEEDEFACEDECADE0001020305060708090A0B0C0D0E1011
## Executable writekey
This executable allows fetching the dataset encryption key using a YubiKey, then stores the key in file pointed to by the first argument passed to the executable. This is needed to use the standard zfs tools (e.g. zpool, among others when creating the pool in the first place).

The following options must be provided to cmake:
### ID_KEY
See zfsmount.
### PEM
See zfsmount.
### KEY_WRAPPED
See zfsmount.