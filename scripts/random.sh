#!/bin/bash

function random_gen_hex {
	RETVAL=$(cat /dev/urandom | head -c $1 | hexdump '-e"%x"')
}

# Will be used one day
function random_gen_dec {
	RETVAL=$(shuf -i 1-65535 -n 1)
}

random_gen_hex 4
AUTH=0x$RETVAL
random_gen_hex 4
HTUA=0x$RETVAL

cat >> $1 <<EOF

#
# Other configurtion
#
AUTH=$AUTH
HTUA=$HTUA
EOF
