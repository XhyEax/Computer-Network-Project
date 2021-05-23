#include "net_utils.c"

int main()
{
    char my_src_mac_address[6] = {0x00, 0x0c, 0x29, 0x75, 0x26, 0x19};
    //填写网关mac (arp -a 第一行)
    char tun_dst_mac_address[6] = {0x00, 0x50, 0x56, 0xe2, 0x6f, 0xaf};
    bind_socket("ens33", my_src_mac_address, "192.168.233.131", 2333);
    //填写unpacker的ip地址
    set_dstinfo(tun_dst_mac_address, "", 2333);
    packer();
    return 0;
}