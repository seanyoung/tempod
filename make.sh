#!/bin/bash
gcc -o tempod tempod.c -O3 -Wall -lbluetooth -levent -DGIT_COMMIT=\"$(git log -1 --oneline | cut -f1 '-d ')\"
