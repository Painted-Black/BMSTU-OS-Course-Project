#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define FILE2 "/home/lander/BMSTU-OS-Course-Project/source/tests/unlink_test_file"

int main(void)
{

    int fd = unlink(FILE2);
    printf("unlink() returned %d\n", fd);
}