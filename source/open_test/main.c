#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


#define FILE1 "test_file.txt"
#define FILE2 "/home/lander/Desktop/BMSTU-OS-Course-Project/source/"

int main(void)
{
    int fd = open(FILE2, O_RDONLY, 0);
    int fd2 = openat("Makefile", 0, 0);
    printf("Fd: %d\n", fd);
    printf("Fd2: %d\n", fd2);
    close(fd);
}