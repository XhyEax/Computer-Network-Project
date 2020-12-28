#ifndef _NET_TYPE_H
#define _NET_TYPE_H	1

struct frame_header //Ethernet帧首部
{
    unsigned char destination_address[6]; //源地址
    unsigned char source_address[6];      //目标地址
    unsigned char protocol_type[2];       //协议类型
};

struct ip_header //IP首部
{
    unsigned char ihl_version;     //4位首部长度+4位IP版本号
    unsigned char tos;             //8位服务类型TOS
    unsigned short total_len;      //16位总长度（字节）
    unsigned short ident;          //16位标识
    unsigned short frag_and_flags; //3位标志位
    unsigned char ttl;             //8位生存时间 TTL
    unsigned char proto;           //8位协议 (TCP, UDP 或其他)
    unsigned short checksum;       //16位IP首部校验和
    unsigned int srcIP;            //32位源IP地址
    unsigned int dstIP;            //32位目的IP地址
};

struct pseudo_header //伪首部
{
    u_int32_t source_address; //源IP地址
    u_int32_t dest_address;   //目的IP地址
    u_int8_t placeholder;     //必须置0,用于填充对齐
    u_int8_t protocol;        //8为协议号(IPPROTO_TCP=6,IPPROTO_UDP=17)
    u_int16_t length;         //UDP/TCP头长度(不包含数据部分)
};

struct udp_header //UDP首部
{
    unsigned short uh_sport; //16位源端口
    unsigned short uh_dport; //16位目的端口
    unsigned short uh_len;   //16位UDP包长度
    unsigned short uh_sum;   //16位校验和
};

#endif