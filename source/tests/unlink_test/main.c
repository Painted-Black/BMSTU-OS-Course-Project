#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define FILE2 "/home/lander/BMSTU-OS-Course-Project/source/tests/unlink_test_file"
#define FILE1 "/home/lander/BMSTU-OS-Course-Project/source/tests/unlink_test_dir"

int main(void)
{
    int fd = unlink(FILE2);
    printf("unlink() file returned %d\n", fd);

    int fd2 = unlink(FILE1);
    printf("unlink() dir returned %d\n", fd2);

    return 0;
}