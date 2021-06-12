#include "net_utils.c"

int main()
{
    char my_src_mac_address[6] = {0x00, 0x0c, 0x29, 0x75, 0x26, 0x19};
    char my_dst_mac_address[6] = {0x00, 0x50, 0x56, 0xe2, 0x6f, 0xaf};
    bind_socket("ens33", my_src_mac_address, "192.168.233.131", 1234);
    set_dstinfo(my_dst_mac_address, "123.45.6.7", 2333);
    sender();
    return 0;
}