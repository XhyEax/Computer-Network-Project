#include "net_utils.c"

int main()
{
    char my_dst_mac_address[6] = {0xfa, 0x16, 0x3e, 0xdd, 0x77, 0xe9};
    char my_src_mac_address[6] = {0x00, 0x0c, 0x29, 0x75, 0x26, 0x19};
    //填写网关mac (arp -a 第一行)
    char tun_dst_mac_address[6] = {0x00, 0x50, 0x56, 0xe2, 0x6f, 0xaf};
    bind_socket("ens33", my_src_mac_address, "10.0.0.1", 1234);
    set_dstinfo(my_dst_mac_address, "10.0.0.2", 4321);
    //填写tun_router的ip地址
    set_tuninfo(tun_dst_mac_address, "", 2333);
    //打包后发给隧道路由
    tun_sender();
    return 0;
}