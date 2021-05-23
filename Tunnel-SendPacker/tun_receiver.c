#include "net_utils.c"

int main()
{
    char my_src_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    bind_socket("lo", my_src_mac_address, "127.0.0.1", 4321);
    //解包ip_in_ip
    tun_receiver();
    return 0;
}