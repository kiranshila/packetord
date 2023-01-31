#!/usr/bin/env bash
BINARY=packetord
if test -f "target/debug/$BINARY"; then
    sudo setcap cap_net_raw,cap_net_admin+ep target/debug/$BINARY
fi
if test -f "target/release/$BINARY"; then
    sudo setcap cap_net_raw,cap_net_admin+ep target/release/$BINARY
fi