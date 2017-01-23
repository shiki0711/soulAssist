#!/bin/sh

err_exit(){
    echo "Error exit. $1"
    exit 1
}

# -----------------------------------------------
# k5pp9f90NBFSt0nesS7tgUSi4pdaLhFGoqk9CTLgtJ4=
# -----------------------------------------------
SUPER_KEY="939a69f5ff74341152b749deb12eed8144a2e2975a2e1146a2a93d0932e0b49e"

# -----------------------------------------------
# brOjEMCP2MbjVfs7KT0UnQ==
# -----------------------------------------------
SUPER_IV="6eb3a310c08fd8c6e355fb3b293d149d"

if [ ! -f dump_packet.py ]; then
    err_exit "dump_packet.py missed."
fi

if [ -z $1 ]; then
    echo "Usage: "$0" packet_file"
    err_exit "no packet data file specified."
fi

python dump_packet.py $1

base64 -D -i key -o key.hex
base64 -D -i iv -o iv.hex
base64 -D -i data -o data.hex

openssl enc -d -aes-256-cbc -K $SUPER_KEY -iv $SUPER_IV -in key.hex -out real_key
openssl enc -d -aes-256-cbc -K $SUPER_KEY -iv $SUPER_IV -in iv.hex -out real_iv

base64 -D -i real_key -o real_key.hex
base64 -D -i real_iv -o real_iv.hex

REAL_KEY=`hexdump -e '16/1 "%02X" ' real_key.hex`
REAL_IV=`hexdump -e '16/1 "%02X" ' real_iv.hex`

openssl enc -d -aes-256-cbc -K $REAL_KEY -iv $REAL_IV -in data.hex

echo ""

