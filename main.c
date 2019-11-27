#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "sha256.h"
#include "chachapoly_aead.h"

#define SERVER_PORT 8003

extern void curve25519_donna(unsigned char *output, const unsigned char *a,
                             const unsigned char *b);

int serverSocket;
pthread_t id,id2;

/* chacha20poly1305 */
struct chachapolyaead_ctx aead_ctx;
uint32_t seqnr = 0;
uint32_t seqnr_aad = 0;
int pos_aad = 0;
uint8_t plaintext_buf[1024] = {0};
uint8_t ciphertext_buf[1024] = {0};
uint8_t plaintext_buf_new[1024] = {0};
uint8_t ciphertext_buf_hex[1024] = {0};

int hexStrToChar(unsigned char* hexStr,unsigned int hexStrLen,unsigned char* CharStr)
    {
        unsigned int len = hexStrLen;
        unsigned int hexStrInt[1024]={0};
        for (unsigned int i = 0; i<len; i++)
        {
        if(hexStr[i]>='0'&&hexStr[i]<='9')  
            hexStrInt[i] = (unsigned int)(hexStr[i]-'0');
        else if(hexStr[i]>='a'&&hexStr[i]<='f')  
            hexStrInt[i] = (unsigned int)(hexStr[i]-'a'+10);
        else if(hexStr[i]>='A'&&hexStr[i]<='F')  
            hexStrInt[i] = (unsigned int)(hexStr[i]-'A'+10);
        else 
            {
            printf("hexStr error!\n");
            return -1;
            }
            printf("%x ",hexStrInt[i]);
        }
    for (unsigned int i = 0; i < len/2; i++)
        CharStr[i]=hexStrInt[2*i]*16 + hexStrInt[2*i+1]; 
    return 0;
    }

int thread_send(int Client){
    char buffer[1024];

    while(1){
    memset(buffer,0,1024);
    gets(buffer);
    if(strlen(buffer)<4) 
        {
            printf("input too small.Plz larger than 3\n");
            continue;
        }
    if(strcmp(buffer, "quit") == 0)
        {
        send(Client, buffer, strlen(buffer), 0);
        close(serverSocket);
        break;
        }
    printf("发送消息明文:%s\n",buffer);
    memset(ciphertext_buf, 0, 1024);
    chacha20poly1305_crypt(&aead_ctx, seqnr, seqnr_aad, pos_aad, ciphertext_buf, strlen(buffer)+20, (const uint8_t*)buffer, strlen(buffer), 1);
    memset(ciphertext_buf_hex, 0, 1024);
    char tmp[1024]={0};
    for (unsigned int i = 0; i < strlen((char*)ciphertext_buf); i++)
    sprintf(&tmp[i*2],"%02x",(unsigned int)ciphertext_buf[i]);
    memcpy(ciphertext_buf_hex,tmp,strlen(tmp));
    printf("发送消息密文:%s\n",ciphertext_buf_hex);
    //for (unsigned int i = 0; i < strlen(ciphertext_buf); ++i)
    //printf("%02x ",ciphertext_buf[i]);
    send(Client, ciphertext_buf_hex, strlen((char*)ciphertext_buf_hex), 0);
    }
    return 0;
}


int thread_recv(int Client){
    int IDataNum;
    char recvbuf_hex[1024];
    uint8_t recvbuf[1024];
while(1){ 
    memset(recvbuf_hex,0,1024); 
    IDataNum = recv(Client, recvbuf_hex, 1024, 0);
    if(IDataNum < 1) continue;
    if(strcmp(recvbuf_hex, "quit") == 0)
        {
        printf("远程设备主动断开！\n");
        close(serverSocket);
        pthread_cancel(id); 
        break;
        } 
    printf("接收消息密文:%d  %d   %s\n", IDataNum,strlen(recvbuf_hex),recvbuf_hex);
    for (unsigned int i = 0; i < strlen(recvbuf_hex); ++i)
    printf("%02x ",recvbuf_hex[i]);
    printf("\n");
    memset(recvbuf,0,1024); 

    hexStrToChar((unsigned char*)recvbuf_hex,(unsigned int)(strlen(recvbuf_hex)),recvbuf); 
    memset(plaintext_buf_new, 0, 1024);
    chacha20poly1305_crypt(&aead_ctx, seqnr, seqnr_aad, pos_aad, plaintext_buf_new, strlen((char*)recvbuf)-10, recvbuf,
        strlen((char*)recvbuf), 0);   
    printf("接收消息明文:%s\n",plaintext_buf_new);

}
return 0;
}

int cservice()
    {  
    struct sockaddr_in server_addr;
    struct sockaddr_in clientAddr;
    int addr_len = sizeof(clientAddr);
    int client;
    
    if((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
    perror("socket");
    return 1;
    }
    bzero(&server_addr, sizeof(server_addr));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    int on=1;  
        if((setsockopt(serverSocket,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)))<0)  
        {  
            perror("setsockopt failed");  
            exit(EXIT_FAILURE);  
        }  
    
    
    if(bind(serverSocket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
    perror("connect");
    return 1;
    }
    //设置服务器上的socket为监听状态
    if(listen(serverSocket, 5) < 0)
    {
    perror("listen");
    return 1;
    }
    printf("监听端口: %d\n", SERVER_PORT);
    client = accept(serverSocket, (struct sockaddr*)&clientAddr, (socklen_t*)&addr_len);
    if(client < 0)
    {
    perror("accept");
    return 1;
    }
    printf("等待消息...\n");
    printf("IP is %s\n", inet_ntoa(clientAddr.sin_addr));
    printf("Port is %d\n", htons(clientAddr.sin_port));


    pthread_create(&id,NULL,(void *)thread_send,(void *)client);
    pthread_create(&id2,NULL,(void *)thread_recv,(void *)client);
    pthread_join(id,NULL); 
    //while(fgetc(stdin) == EOF) break;
    return 0;
    }


int main(int argc, const char *argv[]) 
{
    printf("----------------------------------------\n");
    printf("\033[1m\033[45;33m终端ECDH+chacha加密交换演示程序\033[0m\n");
    printf("----------------------------------------\n");

    uint8_t prikey[32], pubkey[32], epubkey[32], shared[32], output[32];
    static const uint8_t basepoint[32] = {9};

    memset(prikey, 0, sizeof(prikey));
    memset(epubkey, 0, sizeof(epubkey));
    memcpy(prikey,"abcdefghijklmnopqrstuvwxyz123456",32);
    prikey[0] &= 248;
    prikey[31] &= 127;
    prikey[31] |= 64;
       
     /*将16进制字符串转化为普通字符串*/    
    uint8_t epubkey_hex[64]={0};
    uint8_t epubkey_hexint[64]={0};
    memcpy(epubkey_hex,"AFB36B833A324EBF693022AFC42A209D7BF976B9D8A0BCBFB3EA6BB96022A26C",64);
    hexStrToChar(epubkey_hex,sizeof(epubkey_hex), epubkey);
    
    curve25519_donna(pubkey, prikey, basepoint);
    printf("pubkey:");
    for (int i = 0; i < 32; ++i)
    printf("%02x", pubkey[i]);
    printf("\n");
    curve25519_donna(shared, prikey, epubkey);
    printf("shared:");
    for (int i = 0; i < 32; ++i)
    printf("%02x", shared[i]);
    printf("\n");

    /*计算IV*/
    uint8_t iv[SHA256_BLOCK_SIZE];
    SHA256_CTX sha[1];

    sha256_init(sha);
    sha256_update(sha, shared, sizeof(shared));
    sha256_final(sha, iv);

    chacha20poly1305_init(&aead_ctx, shared, 32, iv, 32);

    cservice();

    return 0;
}

    
