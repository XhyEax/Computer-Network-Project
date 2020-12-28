#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include "net_type.h"
#include "cksum.c"

#define max_frame_size 1500 + 14 //无fcs的最大帧长, MTU+帧首部长度

//监听本地环路的IP数据报文(数据链路层)
char my_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
char source_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
char protocol_type[2] = {0x08, 0x00};

// IP地址及协议类型(网络层)
char *my_ip = "127.0.0.1";
char *src_ip = "127.0.0.1";
unsigned char proto_udp = 17;

// UDP端口号(传输层)
unsigned short my_port = 4321;
unsigned short src_port = 1234;

// 辅助函数，16bytes一行打印数据
void printHexData(const char *name, char *buffer, int size)
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

//解包udp
void unpack_segment(in_addr_t saddr, in_addr_t daddr, unsigned char *segment, int segment_len)
{
    struct udp_header header;
    int header_len = sizeof(header);
    memcpy(&header, segment, header_len);
    unsigned short uh_sport = ntohs(header.uh_sport);
    unsigned short uh_dport = ntohs(header.uh_dport);
    // printf("src port: %d\n", uh_sport);
    // printf("dst port: %d\n", uh_dport);
    //判断端口
    if (uh_sport == src_port && uh_dport == my_port)
    {
        //保存接收到的checksum
        u_short recv_sum = header.uh_sum;
        //判断checksum是否存在, ref: <RFC 768>, "for debugging or for higher level protocols that don't care"
        if (recv_sum != 0)
        {
            //UDP伪首部, 用以计算校验和
            struct pseudo_header udp_pseudo_header;
            udp_pseudo_header.source_address = saddr;
            udp_pseudo_header.dest_address = daddr;
            udp_pseudo_header.placeholder = 0;
            udp_pseudo_header.protocol = proto_udp;
            udp_pseudo_header.length = header.uh_len;
            // printHexData("udp_pseudo_header", (char *)&udp_pseudo_header, sizeof(udp_pseudo_header));
            //伪首部校验和
            u_short udp_pheader_cksum = udp_ph_cksum((u_short *)&udp_pseudo_header, sizeof(udp_pseudo_header));
            //判断校验和是否一致
            if (recv_sum != udp_pheader_cksum)
            {
                printf("[×]udp_pseudo_header checksum check failed.\n");
                // return;
            }
        }

        printf("receive data:\n");
        unsigned char *payload = segment + header_len;
        for (int i = 0; i < segment_len - header_len; i++)
            printf("%c", payload[i]);
        printf("\n");
    }
}

//解包ip
void unpack_packet(unsigned char *packet, int packet_len)
{
    struct ip_header header;
    int header_len = sizeof(header);
    memcpy(&header, packet, header_len);
    struct in_addr saddr, daddr;
    memcpy(&saddr, &header.srcIP, sizeof(saddr));
    memcpy(&daddr, &header.dstIP, sizeof(saddr));
    char *src_ip_str = inet_ntoa(saddr);
    char *dst_ip_str = inet_ntoa(daddr);

    // printf("proto: %d\n", header.proto);
    // printf("srcIP: %s\n", src_ip_str);
    // printf("dstIP: %s\n", dst_ip_str);

    //检查IP地址及协议类型
    if (!strcmp(src_ip, src_ip_str) && !strcmp(my_ip, dst_ip_str) && header.proto == proto_udp)
    {
        //校验checksum
        if (ip_cksum((u_short *)&header, sizeof(header)) != 0)
        {
            printf("[×]ip checksum check failed.\n");
            return;
        }
        //解包segment
        unpack_segment(header.srcIP, header.dstIP, packet + header_len, packet_len - header_len);
    }
}

//解包帧
void unpack_frame(unsigned char *frame, int frame_len)
{
    struct frame_header header;
    int header_len = sizeof(header);
    memcpy(&header, frame, header_len);
    // printHexData("destination_address", header.destination_address, 6);
    // printHexData("source_address", header.source_address, 6);
    // printHexData("protocol_type", header.protocol_type, 2);

    //检查目标地址、源地址、协议类型
    if (!memcmp(header.destination_address, my_address, 6) &&
        !memcmp(header.source_address, source_address, 6) &&
        (!memcmp(header.protocol_type, protocol_type, 2)))
    {
        //解包packet
        unpack_packet(frame + header_len, frame_len - header_len);
    }
}

int main()
{
    int sockfd;
    char frame[max_frame_size];
    //创建socket, 设置只接受IP报文
    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
    {
        perror("[×]socket() error");
        exit(1);
    }
    else
    {
        printf("[√]socket create success. Start listening...\n");
    }

    //监听
    int frame_len;
    while ((frame_len = recvfrom(sockfd, frame, max_frame_size, 0, NULL, NULL)) > 0)
    {
        unpack_frame(frame, frame_len);
    }

    return 0;
}