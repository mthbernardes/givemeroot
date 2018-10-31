#!/bin/bash
make
make -C sbin
mv sbin/bin/tcp_client /usr/local/bin/mkdir
