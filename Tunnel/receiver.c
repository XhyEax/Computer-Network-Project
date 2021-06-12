#include "net_utils.c"

int main()
{
    char my_src_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    bind_socket("lo", my_src_mac_address, "192.168.233.132", 4321);
    receiver();
    return 0;
}