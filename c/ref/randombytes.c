/*
This code was taken from the SPHINCS reference implementation and is public domain.
*/

#ifndef CKB_VM
#include <fcntl.h>
#include <unistd.h>

#include "randombytes.h"

static int fd = -1;

void randombytes(unsigned char *x, unsigned long long xlen)
{
    int i;

    if (fd == -1) {
        for (;;) {
            fd = open("/dev/urandom", O_RDONLY);
            if (fd != -1) {
                break;
            }
            sleep(1);
        }
    }

    while (xlen > 0) {
        if (xlen < 1048576) {
            i = xlen;
        }
        else {
            i = 1048576;
        }

        i = read(fd, x, i);
        if (i < 1) {
            sleep(1);
            continue;
        }

        x += i;
        xlen -= i;
    }
}
#else // CKB_VM

void randombytes(unsigned char *x, unsigned long long xlen)
{
    // Random numbers cannot be generated in ckb-vm
}

#endif // CKB_VM

