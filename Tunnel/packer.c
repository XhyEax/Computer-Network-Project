#include "net_utils.c"

int main()
{
    char my_src_mac_address[6] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
    char my_dst_mac_address[6] = {0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb};
    bind_socket("eth0", my_src_mac_address, "", 2333);
    set_dstinfo(my_dst_mac_address, "", 2333);
    packer();
    return 0;
}