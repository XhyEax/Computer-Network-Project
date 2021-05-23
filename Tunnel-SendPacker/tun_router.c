#include "net_utils.c"

int main()
{
    char my_dst_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char my_src_mac_address[6] = {0xfa, 0x16, 0x3e, 0xdd, 0x77, 0xe9};
    bind_socket("lo", my_src_mac_address, "192.168.1.67", 2333);
    set_dstinfo(my_dst_mac_address, "127.0.0.1", 4321);
    //隧道路由转发给tun_receiver
    tun_router();
    return 0;
}