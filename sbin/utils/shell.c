#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
int shell(char * cmd,char **comout){
    FILE *fd;
    fd = popen(cmd, "r");
    if (!fd) return 1;
 
    char   buffer[256];
    size_t chread;

    size_t comalloc = 256;
    size_t comlen   = 0;
    *comout = malloc(comalloc);
 
    while ((chread = fread(buffer, 1, 256, fd)) != 0) {
        if (comlen + chread >= comalloc) {
            comalloc *= 2;
            *comout = realloc(*comout, comalloc);
        }
        memmove(*comout + comlen, buffer, chread);
        comlen += chread;
    }
    pclose(fd);
    return 0;
}

