#include "net_utils.c"

int main()
{
    char my_dst_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char my_src_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char tun_dst_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    bind_socket(my_src_mac_address, "127.0.0.1", 4321);
    //打包后发给隧道路由
    tun_receiver();
    return 0;
}