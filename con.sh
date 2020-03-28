#!bin/sh

gcc -o server server.c 
./server -i tun0 -s -d
 
