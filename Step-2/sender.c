#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include "net_type.h"
#include "cksum.c"
// #include "crc32.h"

#define max_frame_size 1500 + 14 //无fcs的最大帧长, MTU+帧首部长度

//sockaddr_ll结构体
struct sockaddr_ll sll;
// 绑定的网卡接口（本地环路）
char *interface = "lo";
// 目标地址、源地址、协议类型（数据链路层）
char da[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
char sa[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
char protocol_type[2] = {0x08, 0x00};

char ether_buffer[max_frame_size]; //Ethernet帧(无fcs)
char ip_buffer[max_frame_size];    //IP数据报
char udp_buffer[max_frame_size];   //UDP包
char payload[max_frame_size];      //udp净载荷

// IP地址及协议类型(网络层)
char *my_ip = "127.0.0.1";
char *dst_ip = "127.0.0.1";
unsigned char proto_udp = 17;

// UDP端口号(传输层)
unsigned short my_port = 1234;
unsigned short dst_port = 4321;

// 辅助函数，16bytes一行打印数据
void printHexData(const char *name, unsigned char *buffer, int size)
{
    printf("%s", name);
    printf(": \n");
    for (int i = 0; i < size; i++)
    {
        printf("%02x ", buffer[i] & 0xff);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("\n");
}

// 打包成帧（数据链路层）
int pack_frame(char *da, char *sa, char *protocol_type, char *buffer, char *payload, int payload_len)
{
    // 使用Raw Socket, MAC层中会自动补0到最小帧长, 故注释
    // if (payload_len < 46)
    // {
    //     payload_len = 46; //填充0x00至最小长度
    // }
    struct frame_header header;
    int header_len = sizeof(header);
    memcpy(header.destination_address, da, 6);
    memcpy(header.source_address, sa, 6);
    memcpy(header.protocol_type, protocol_type, 2);
    // 复制header
    memcpy(buffer, &header, header_len);
    // 复制payload
    memcpy(buffer + header_len, payload, payload_len);
    // 使用Raw Socket不需要fcs, 故注释
    // 计算并复制fcs
    // uint32_t fcs = crc32(buffer, payload_len + header_len);
    // memcpy(buffer + payload_len + header_len, &fcs, 4);
    // int frame_len = payload_len + header_len + 4;
    int frame_len = payload_len + header_len;
    // printHexData("frame", ether_buffer, frame_len);
    return frame_len;
}

// 打包成packet（网络层）
int pack_packet(in_addr_t sipaddr, in_addr_t dipaddr, char *buffer, char *payload, int packet_payload_len)
{
    //设置header
    struct ip_header header;
    int header_len = sizeof(header);
    header.ihl_version = 0x45;//version:4, IPv4 header length:5
    header.tos = 0;
    header.total_len = htons(packet_payload_len + header_len);
    header.ident = rand() % 0xffff;
    header.ident = 0x61a0;
    header.frag_and_flags = 0x0040; //不分片
    header.ttl = 64;
    header.proto = proto_udp;
    header.checksum = 0;
    header.srcIP = sipaddr;
    header.dstIP = dipaddr;
    //计算校验和
    header.checksum = ip_cksum((u_short *)&header, header_len);
    //计算总长度
    int frame_payload_len = packet_payload_len + header_len;
    // 复制header
    memcpy(buffer, &header, header_len);
    // 复制payload
    memcpy(buffer + header_len, payload, packet_payload_len);
    // printHexData("ip packet", buffer, frame_payload_len);
    //打包成帧, buffer作为下一层的payload
    return pack_frame(da, sa, protocol_type, ether_buffer, buffer, frame_payload_len);
}

// 打包成segment（传输层）, 只计算伪首部的校验和
int pack_segment(unsigned short sport, unsigned short dport, char *buffer, char *payload, int payload_len)
{
    //设置header
    struct udp_header header;
    int header_len = sizeof(header);
    header.uh_sport = htons(sport);
    header.uh_dport = htons(dport);
    header.uh_len = htons(header_len + payload_len);
    header.uh_sum = 0;
    //IP地址转换
    struct in_addr src_addr, dst_addr;
    inet_aton(my_ip, &src_addr);
    inet_aton(dst_ip, &dst_addr);
    in_addr_t sipaddr = src_addr.s_addr;
    in_addr_t dipaddr = dst_addr.s_addr;
    //UDP伪首部, 用以计算校验和
    struct pseudo_header udp_pseudo_header;
    udp_pseudo_header.source_address = sipaddr;
    udp_pseudo_header.dest_address = dipaddr;
    udp_pseudo_header.placeholder = 0;
    udp_pseudo_header.protocol = proto_udp;
    udp_pseudo_header.length = header.uh_len;
    // printHexData("udp_pseudo_header", (unsigned char *)&udp_pseudo_header, sizeof(udp_pseudo_header));
    memcpy(buffer, &header, header_len);
    int packet_payload_len = payload_len + header_len;
    memcpy(buffer + header_len, payload, payload_len);
    // 只计算伪首部的校验和
    header.uh_sum = udp_ph_cksum((u_short *)&udp_pseudo_header, sizeof(udp_pseudo_header));
    // printf("header.uh_sum %x\n", header.uh_sum);
    // printHexData("udp", buffer, packet_payload_len);
    //打包成IP数据报, buffer作为下一层的payload
    return pack_packet(sipaddr, dipaddr, ip_buffer, buffer, packet_payload_len);
}

int main()
{
    //设置随机数seed
    srand((unsigned)time(NULL));
    int sd, frame_len;
    //创建socket, 设置为IP协议
    if ((sd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("[×]socket() error");
        exit(1);
    }
    //获取网卡index
    struct ifreq ifstruct;
    strcpy(ifstruct.ifr_name, interface);
    if (ioctl(sd, SIOCGIFINDEX, &ifstruct) == -1)
    {
        perror("[×]get interface index error");
        exit(1);
    }
    //设置sockaddr_ll结构体信息
    sll.sll_family = AF_PACKET;             //填写AF_PACKET,不经过协议栈处理
    sll.sll_ifindex = ifstruct.ifr_ifindex; //设置网卡index
    sll.sll_protocol = IPPROTO_RAW;         //IP协议
    sll.sll_pkttype = PACKET_OUTGOING;      //标识包的类型为发出去的包
    sll.sll_halen = 6;                      //目标MAC地址长度为6
    memcpy(sll.sll_addr, da, 6);            //填写目标MAC地址

    //udp包payload最大长度
    const int max_udp_size = max_frame_size - sizeof(struct frame_header) - sizeof(struct ip_header) - sizeof(struct udp_header);
    while (1)
    {
        // 读取用户输入
        printf(">");
        scanf("%[^\n]", payload);
        int payload_len = strlen(payload);
        //判断长度
        if (payload_len > max_udp_size)
        {
            printf("[×]input is too long!");
        }
        else
        {
            // 层层打包
            frame_len = pack_segment(my_port, dst_port, udp_buffer, payload, payload_len);
            sendto(sd, ether_buffer, frame_len, 0, (const struct sockaddr *)&sll, sizeof(sll));
        }
        //清空缓存区
        getchar();
    }
    return 0;
}