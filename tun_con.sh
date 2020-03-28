#!/bin/sh

sysctl net.ipv4.ip_forward=1

ip addr add 10.0.4.1/24 dev tun0

ifconfig tun0 up

route add -net 10.0.5.0 netmask 255.255.255.0 dev tun0


