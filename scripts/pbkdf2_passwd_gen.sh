#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright 2024 NXP
#
# Generate test vectors for xtest's PBKDF2 suite.
# 	- HSE requires the salt to be at least 16 bytes in length
#
# This script depends on OpenSSL's 'openssl' tool


# Example for PBKDF2:
# openssl kdf -keylen 29 -kdfopt digest:SHA1 -kdfopt pass:"S32G_the_coolest_Automotive_SoC!" -kdfopt salt:"Linux_BSP_rulez!" -kdfopt iter:4096 PBKDF2

#Example for AES:
#echo "S32G_the_coolest_Automotive_SoC!" | openssl enc -e -aes-256-ecb -K 0000000000000000000000000000000000000000000000000000000000000000 -out /tmp/kkmak

# Other tools
# echo -n 'The_quick_brown_fox_jumped_over' | od -A n -t x1 | sed 's/ //g'


# Options for PBKDF2
passwd=( \
	'passwordPASSWORDpassword' \
	'passwordPASSWORDpassword' \
	'passwordPASSWORDpassword' \
	'passwordPASSWORDpassword' \
	'passwordPASSWORDpassword' \
	'passwordPASSWORDpassword' \
	'passwordPASSWORDpassword' \
)
salt=( \
	'saltSALTsaltSALTsaltSALTsaltSALTsalt' \
	'saltSALTsaltSALTsaltSALTsaltSALTsalt' \
	'saltSALTsaltSALTsaltSALTsaltSALTsalt' \
	'saltSALTsaltSALTsaltSALTsaltSALTsalt' \
	'saltSALTsaltSALTsaltSALTsaltSALTsalt' \
	'saltSALTsaltSALTsaltSALTsaltSALTsalt' \
	'saltSALTsaltSALTsaltSALTsaltSALTsalt' \
)
iter=( \
	8192 \
	8192 \
	8192 \
	8192 \
	8192 \
	8192 \
	8192 \
)
dklen=( \
	64 \
	64 \
	64 \
	64 \
	64 \
	64 \
	64 \
)
digest=( \
	SHA1 \
	SHA256 \
	SHA512 \
	SHA224 \
	SHA384 \
	SHA512-256 \
	SHA512-224 \
)

# Options for AES KEK
kek_cipher=-aes-256-ctr
kek_key=0000000000000000000000000000000000000000000000000000000000000000
kek_iv=00000000000000000000000000000000
kek_outfile=/tmp/dk.out
kek_infile=/tmp/dk.bin


# 'password' --> AB:CD:EF
function do_pbkdf2 {
	# !! no echo-ing inside this function; its output will be parsed as-is
	p=${1}
	s=${2}
	i=${3}
	l=${4}
	d=${5}
	echo

	openssl kdf -keylen ${l} -kdfopt digest:${d} -kdfopt pass:"${p}" -kdfopt salt:"${s}" -kdfopt iter:${i} PBKDF2
}

# ab:cd:ef --> 0xab,0xcd,0xef
function dk_to_c_array {
	dk=${1}

	dk=`echo $dk | tr -t ':' ','`
	echo $dk | sed s/\\\([0-9a-fA-F]\\{2\\}\\\)/0x\\1/g | sed s/,/,\ /g
}

# ab:cd:ef --> dk.bin
function dk_to_bin {
	dk=$1

	echo -n ${dk} | tr -d ':' | xxd -r -p > ${kek_infile}
}

#            +---------+
# dk.bin --->|dummy_kek|---> dk.out
#            | AES-256 |
#            +---------+
function dk_encrypt {
	openssl enc -e ${kek_cipher} -nosalt -K ${kek_key} -iv ${kek_iv} -in ${kek_infile} -out ${kek_outfile}
}

# dk.out --> 0xab, 0xcd, 0xef
function dump_encrypted_key {
	xxd -p -c 8 ${kek_outfile} | sed s/\\\([0-9a-fA-F]\\{2\\}\\\)/0x\\1,\ /g | tr -d ' ' | \
		sed s/^/\\t/ | sed s/,/,\ /g
}

for i in ${!passwd[@]}; do
	echo ">>> i = "${i}
	p=${passwd[${i}]}
	s=${salt[${i}]}
	iter=${iter[${i}]}
	l=${dklen[${i}]}
	d=${digest[${i}]}

	# PBKDF2-derive the key
	dk=`do_pbkdf2 "$p" "$s" "$iter" "$l" "$d"`
	# Derived key output by openssl is in double:digit:hex:format. Reformat
	# it a C array code. This is just to copy-paste in the xtest source file.
	echo "Derived Key:"; echo -n -e "\t"
	dk_to_c_array ${dk}

	# Write it to a binary file for easier encryption
	dk_to_bin ${dk}
	dk_encrypt
	echo "Encrypted key:"
	dump_encrypted_key

	echo
done
