#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define FILE2 "/home/lander/BMSTU-OS-Course-Project/source/tests"
#define FILE1 "unlinkat_test_file"

int main(void)
{
    int fd = open(FILE2, 0);
    printf("open() returned %d\n", fd);
    if (fd > 0)
    {
	int fd2 = unlinkat(fd, FILE1, 0);
    	printf("unlinkat() returned %d\n", fd2);
    }
    return 0;
}