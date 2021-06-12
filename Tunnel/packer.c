#include "net_utils.c"

int main()
{
    char my_src_mac_address[6] = {0xfa, 0x16, 0x3e, 0x6e, 0xff, 0x5d};
    char my_dst_mac_address[6] = {0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0x01};
    char left_mac_address[6] = {0x00, 0x0c, 0x29, 0x75, 0x26, 0x19};
    char right_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    bind_socket("eth0", my_src_mac_address, "123.45.6.7", 2333);
    set_dstinfo(my_dst_mac_address, "124.71.185.211", 2333);
    set_leftinfo(left_mac_address, "192.168.233.131", 1234);
    set_rightinfo(right_mac_address, "192.168.233.132", 4321);
    packer();
    return 0;
}