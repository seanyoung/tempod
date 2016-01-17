#!/bin/bash
gcc -o tempod tempod.c -O3 -Wall -lbluetooth -levent -lsystemd -DGIT_COMMIT=\"$(git log -1 --oneline | cut -f1 '-d ')\" -D_GNU_SOURCE
