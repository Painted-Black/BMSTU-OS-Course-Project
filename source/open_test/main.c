#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


#define FILE1 "test_file"
#define FILE2 "/home/lander/Desktop/BMSTU-OS-Course-Project/source"

int main(void)
{
    int fd = openat(0, FILE2, O_RDONLY, 0);
    int fd2 = openat(fd, "Makefile", 0, 0);
    //int fd3 = mkdirat(fd, "TestDir", 0);
    int ret = unlinkat(fd, FILE1, 0);
    printf("Unlinkat returned %d\n", ret);
    // //int fd3 = openat(fd, "stop", 0, 0);
    // printf("Fd: %d\n", fd);
    // printf("Fd2: %d\n", fd2);
    // printf("Fd3: %d\n", fd3);
    close(fd);
    close(fd2);
    //close(fd3);
}