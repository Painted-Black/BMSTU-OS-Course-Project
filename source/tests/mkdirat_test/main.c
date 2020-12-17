#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define FILE2 "/home/lander/BMSTU-OS-Course-Project/source/tests"
#define FILE1 "mkdirat_test_dir"

int main(void)
{
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    int fd = open(FILE2, 0);
    printf("open() returned %d\n", fd);
    if (fd > 0)
    {
	int fd2 = mkdirat(fd, FILE1, mode);
    	printf("unlinkat() returned %d\n", fd2);
    }
    return 0;
}