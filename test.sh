#!/usr/bin/env sh

# Test vector 1
echo -ne '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' | ./hd-wallet "m/0'/1/2'/2"


# Test Key Path
# ./hd-wallet < /dev/urandom ""
# ./hd-wallet < /dev/urandom "m"
./hd-wallet < /dev/urandom "m/0/0"
./hd-wallet < /dev/urandom "m/2/5"
./hd-wallet < /dev/urandom "m/0'/1/2'"
./hd-wallet < /dev/urandom "m/1'/0"
./hd-wallet < /dev/urandom "m/1'/0'"
