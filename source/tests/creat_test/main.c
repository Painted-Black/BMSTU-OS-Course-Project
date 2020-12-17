#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


#define FILE1 "test_file"
#define FILE2 "/home/lander/BMSTU-OS-Course-Project/source/tests/test_file"
#define FILE3 "../test_file2"

int main(void)
{

    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    int fd = creat(FILE2, mode);
    printf("creat() returned %d\n", fd);
    close(fd);
}