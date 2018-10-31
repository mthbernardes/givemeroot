#!/bin/bash
make
make -C sbin
mv sbin/bin/tcp_client /usr/bin/tcp
