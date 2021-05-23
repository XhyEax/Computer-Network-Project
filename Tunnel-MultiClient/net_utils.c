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

#define max_frame_size 1500 + 14 //无fcs的最大帧长, MTU+帧首部长度

//Socket
int sd;
//sockaddr_ll结构体
struct sockaddr_ll sll;
// 绑定的网卡接口（本地环路）
char interface[10];
// mac地址、协议类型(ip)（数据链路层）
char tun_mac_address[6];
char dst_mac_address[6];
char listen_mac_address[6];
char protocol_type[2] = {0x08, 0x00};

char frame[max_frame_size]; //Ethernet帧(无fcs), 解包用
//以下数组作为打包缓存区
char ether_buffer[max_frame_size]; //Ethernet帧(无fcs)
char ip_buffer[max_frame_size];    //IP数据报
char udp_buffer[max_frame_size];   //UDP包
char payload[max_frame_size];      //udp净载荷

// IP地址及协议类型(udp) (网络层)
char tun_ip[20];
char dst_ip[20];
char listen_ip[20];
unsigned char proto_udp = 17;

// UDP端口号(传输层)
unsigned short tun_port;
unsigned short dst_port;
unsigned short listen_port;

// 辅助函数，16bytes一行打印数据
void printHexData(const char *name, unsigned char *buffer, int size)
{
    printf("%s [%d]", name, size);
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

// 打印mac地址
void printMacAddress(const char *name, char *buffer, int size)
{
    printf("%s", name);
    printf(": 0x");
    for (int i = 0; i < size; i++)
    {
        printf("%.2x", buffer[i] & 0xff);
    }
    printf("\n");
}

//解包udp
int unpack_segment(in_addr_t saddr_t, in_addr_t daddr_t, unsigned char *segment, int segment_len, int bypass_check)
{
    struct udp_header header;
    int header_len = sizeof(header);
    memcpy(&header, segment, header_len);
    unsigned short uh_sport = ntohs(header.uh_sport);
    unsigned short uh_dport = ntohs(header.uh_dport);
    // printf("src port: %d\n", uh_sport);
    // printf("dst port: %d\n", uh_dport);
    //判断端口
    int check = uh_dport == listen_port;
    if (bypass_check || check)
    {
        //保存接收到的checksum
        u_short recv_sum = header.uh_sum;
        //判断checksum是否存在, ref: <RFC 768>, "for debugging or for higher level protocols that don't care"
        if (recv_sum != 0)
        {
            //UDP伪首部, 用以计算校验和
            struct pseudo_header udp_pseudo_header;
            udp_pseudo_header.source_address = saddr_t;
            udp_pseudo_header.dest_address = daddr_t;
            udp_pseudo_header.placeholder = 0;
            udp_pseudo_header.protocol = proto_udp;
            udp_pseudo_header.length = header.uh_len;
            // printHexData("udp_pseudo_header", (char *)&udp_pseudo_header, sizeof(udp_pseudo_header));
            //伪首部校验和
            u_short udp_pheader_cksum = udp_ph_cksum((u_short *)&udp_pseudo_header, sizeof(udp_pseudo_header));
            //判断校验和是否一致
            if (!bypass_check && recv_sum != udp_pheader_cksum)
            {
                // printf("[×]udp_pseudo_header checksum check failed.\n");
                // return;
            }
        }
        //打印ip和端口
        struct in_addr saddr;
        memcpy(&saddr, &saddr_t, sizeof(saddr));
        char *src_ip_str = inet_ntoa(saddr);

        int payload_len = segment_len - header_len;
        printf("\nreceive %d bytes data from [%s:%d]\n", payload_len, src_ip_str, uh_sport);
        memcpy(&payload, segment + header_len, payload_len);
        return payload_len;
    }
    return -1;
}

//解包ip
int unpack_packet(unsigned char *packet, int packet_len, int bypass_check)
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

    //检查IP和协议类型
    int check = !strcmp(dst_ip_str, listen_ip) && header.proto == proto_udp;
    if (bypass_check || check)
    {
        //校验checksum
        if (!bypass_check && ip_cksum((u_short *)&header, sizeof(header)) != 0)
        {
            printf("[×]ip checksum check failed.\n");
            return -1;
        }
        //解包segment
        return unpack_segment(header.srcIP, header.dstIP, packet + header_len, packet_len - header_len, bypass_check);
    }
    return -1;
}

//解包帧
int unpack_frame(char *frame, int frame_len, int bypass_check)
{
    struct frame_header header;
    int frame_header_len = sizeof(header);
    memcpy(&header, frame, frame_header_len);

    // printHexData("destination_address", header.destination_address, 6);
    // printHexData("source_address", header.source_address, 6);
    // printHexData("protocol_type", header.protocol_type, 2);

    //检查地址、协议类型
    int check = (!memcmp(header.destination_address, listen_mac_address, 6) &&
                 (!memcmp(header.protocol_type, protocol_type, 2)));
    if (bypass_check || check)
    {
        //解包packet
        return unpack_packet(frame + frame_header_len, frame_len - frame_header_len, bypass_check);
    }
    return -1;
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
int pack_packet(char *src_mac_address, char *dst_mac_address, in_addr_t sipaddr, in_addr_t dipaddr, char *buffer, char *payload, int packet_payload_len, int is_pack_ether)
{
    //设置header
    struct ip_header header;
    int header_len = sizeof(header);
    header.ihl_version = 0x45; //version:4, IPv4 header length:5
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
    if (is_pack_ether == 0)
    {
        return frame_payload_len;
    }
    //打包成帧, buffer作为下一层的payload
    return pack_frame(dst_mac_address, src_mac_address, protocol_type, ether_buffer, buffer, frame_payload_len);
}

// 打包成segment（传输层）, 只计算伪首部的校验和
int pack_segment(char *src_mac_address, char *dst_mac_address, char *src_ip, char *dst_ip, unsigned short sport, unsigned short dport, char *buffer, char *payload, int payload_len, int is_pack_ether)
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
    inet_aton(src_ip, &src_addr);
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
    return pack_packet(src_mac_address, dst_mac_address, sipaddr, dipaddr, ip_buffer, buffer, packet_payload_len, is_pack_ether);
}

//发送udp包
void sender()
{
    //udp包 header总长度 payload最大长度
    const int headers_size = sizeof(struct frame_header) + sizeof(struct ip_header) + sizeof(struct udp_header);
    const int max_udp_size = max_frame_size - headers_size;
    //循环读取用户输入
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
            int frame_len = pack_segment(listen_mac_address, dst_mac_address, listen_ip, dst_ip, listen_port, dst_port, udp_buffer, payload, payload_len, 1);
            sendto(sd, ether_buffer, frame_len, 0, (const struct sockaddr *)&sll, sizeof(sll));
        }
        //清空缓存区
        getchar();
    }
}

//隧道路由，打包成ip_in_ip后转发至unpacker
void packer()
{
    int frame_len, payload_len;
    while ((frame_len = recvfrom(sd, frame, max_frame_size, 0, NULL, NULL)) > 0)
    {
        // 解包得到净载荷
        payload_len = unpack_frame(frame, frame_len, 0);
        if (payload_len > 0)
        {
            // 打包成IP报文
            int packet_len = pack_segment(listen_mac_address, dst_mac_address, listen_ip, dst_ip, listen_port, dst_port, udp_buffer, payload, payload_len, 0);
            // printHexData("send ip_buffer", ip_buffer, packet_len);
            // 生成以太网帧, IP in IP
            frame_len = pack_segment(listen_mac_address, dst_mac_address, listen_ip, dst_ip, listen_port, dst_port, udp_buffer, ip_buffer, packet_len, 1);

            sendto(sd, ether_buffer, frame_len, 0, (const struct sockaddr *)&sll, sizeof(sll));
        }
    }
}

//隧道路由，解包ip_in_ip后转发至receiver
void unpacker()
{
    int frame_len, payload_len;
    while ((frame_len = recvfrom(sd, frame, max_frame_size, 0, NULL, NULL)) > 0)
    {
        // 解包得到内部的IP报文
        payload_len = unpack_frame(frame, frame_len, 0);
        if (payload_len > 0)
        {
            // printHexData("recv ip_buffer", payload, payload_len);
            //解包ip in ip得到净载荷
            payload_len = unpack_packet(payload, payload_len, 1);
            // 重新打包发给tun_receiver
            frame_len = pack_segment(listen_mac_address, dst_mac_address, listen_ip, dst_ip, listen_port, dst_port, udp_buffer, payload, payload_len, 1);
            sendto(sd, ether_buffer, frame_len, 0, (const struct sockaddr *)&sll, sizeof(sll));
        }
    }
}

//接收udp包，解包净载荷并输出
void receiver()
{
    int frame_len;
    while ((frame_len = recvfrom(sd, frame, max_frame_size, 0, NULL, NULL)) > 0)
    {
        int payload_len = unpack_frame(frame, frame_len, 0);
        for (int i = 0; i < payload_len; i++)
            printf("%c", payload[i]);
        if (payload_len > 0)
            printf("\n");
    }
}

//发送udp包 (隧道) sender + packer
void tun_sender()
{
    //udp包 header总长度 payload最大长度
    const int headers_size = sizeof(struct frame_header) + sizeof(struct ip_header) + sizeof(struct udp_header);
    //IP in IP 相当于header存在两次
    const int max_udp_size = max_frame_size - 2 * headers_size;
    //循环读取用户输入
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
            // 打包成IP报文
            int packet_len = pack_segment(listen_mac_address, dst_mac_address, listen_ip, dst_ip, listen_port, dst_port, udp_buffer, payload, payload_len, 0);
            // printHexData("send ip_buffer", ip_buffer, packet_len);
            // 生成以太网帧, IP in IP (packer)
            int frame_len = pack_segment(listen_mac_address, tun_mac_address, listen_ip, tun_ip, listen_port, tun_port, udp_buffer, ip_buffer, packet_len, 1);
            sendto(sd, ether_buffer, frame_len, 0, (const struct sockaddr *)&sll, sizeof(sll));
        }
        //清空缓存区
        getchar();
    }
}

//隧道路由，将请求转发给tun_receiver
void tun_router()
{
    int frame_len, payload_len;
    while ((frame_len = recvfrom(sd, frame, max_frame_size, 0, NULL, NULL)) > 0)
    {
        // 解包得到内部的IP报文
        payload_len = unpack_frame(frame, frame_len, 0);
        if (payload_len > 0)
        {
            // printHexData("recv ip_buffer", payload, payload_len);
            // 重新打包转发给tun_receiver
            frame_len = pack_segment(listen_mac_address, dst_mac_address, listen_ip, dst_ip, listen_port, dst_port, udp_buffer, payload, payload_len, 1);
            sendto(sd, ether_buffer, frame_len, 0, (const struct sockaddr *)&sll, sizeof(sll));
        }
    }
}

//接收udp包，解包净载荷并输出 (隧道) unpacker + receiver
void tun_receiver()
{
    int frame_len, payload_len;
    while ((frame_len = recvfrom(sd, frame, max_frame_size, 0, NULL, NULL)) > 0)
    {
        // unpacker
        payload_len = unpack_frame(frame, frame_len, 0);
        if (payload_len > 0)
        {
            // printf("recv ip_in_ip");
            // receiver
            payload_len = unpack_packet(payload, payload_len, 1);
            if (payload_len > 0)
            {
                for (int i = 0; i < payload_len; i++)
                    printf("%c", payload[i]);
                if (payload_len > 0)
                    printf("\n");
            }
        }
    }
}

// 设置监听信息 绑定socket
void bind_socket(char *my_interface, char *my_src_mac_address, const char *my_src_ip, int my_src_port)
{
    strcpy(interface, my_interface);
    //mac地址 (数据链路层)
    memcpy(listen_mac_address, my_src_mac_address, 6);
    // IP地址 (网络层)
    strcpy(listen_ip, my_src_ip);
    // UDP端口号 (传输层)
    listen_port = my_src_port;
    //设置随机数seed
    srand((unsigned)time(NULL));
    //创建socket, 设置为IP协议
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
    {
        perror("[×]socket() error");
        exit(1);
    }
    else
    {
        printf("[√]socket create success. Start listening...\n");
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
    sll.sll_family = AF_PACKET;                  //填写AF_PACKET,不经过协议栈处理
    sll.sll_ifindex = ifstruct.ifr_ifindex;      //设置网卡index
    sll.sll_protocol = IPPROTO_RAW;              //IP协议
    sll.sll_pkttype = PACKET_OUTGOING;           //包类型标志
    sll.sll_halen = 6;                           //目标MAC地址长度为6
    memcpy(sll.sll_addr, listen_mac_address, 6); //监听MAC地址
    //打印地址
    printMacAddress("listen mac address", listen_mac_address, 6);
    printf("listen on: [%s:%d]\n", listen_ip, listen_port);
}

void set_dstinfo(char *my_dst_mac_address, char *my_dst_ip, int my_dst_port)
{
    //mac地址 (数据链路层)
    memcpy(dst_mac_address, my_dst_mac_address, 6);
    // IP地址 (网络层)
    strcpy(dst_ip, my_dst_ip);
    // UDP端口号 (传输层)
    dst_port = my_dst_port;
    printMacAddress("dst mac address", dst_mac_address, 6);
    printf("dst ip address: [%s:%d]\n", dst_ip, dst_port);
}

void set_tuninfo(char *my_dst_mac_address, char *my_dst_ip, int my_dst_port)
{
    //mac地址 (数据链路层)
    memcpy(tun_mac_address, my_dst_mac_address, 6);
    // IP地址 (网络层)
    strcpy(tun_ip, my_dst_ip);
    // UDP端口号 (传输层)
    tun_port = my_dst_port;
    printMacAddress("tun mac address", tun_mac_address, 6);
    printf("tun ip address: [%s:%d]\n", tun_ip, tun_port);
}