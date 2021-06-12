#include "net_utils.c"

int main()
{
    char my_dst_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char my_src_mac_address[6] = {0xfa, 0x16, 0x3e, 0xdd, 0x77, 0xe9};
    char left_mac_address[6] = {0x00, 0x0c, 0x29, 0x75, 0x26, 0x19};
    bind_socket("lo", my_src_mac_address, "192.168.1.67", 2333);
    set_dstinfo(my_dst_mac_address, "192.168.233.132", 4321);
    set_leftinfo(left_mac_address, "192.168.233.131", 1234);
    //解包后转发给receiver
    unpacker();
    return 0;
}