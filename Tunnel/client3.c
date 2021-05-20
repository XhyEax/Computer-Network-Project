#include <pthread.h>
#include "net_utils.c"

void receiver_thd(void *ptr)
{
    receiver();
}

int main()
{
    char my_dst_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char my_src_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    bind_socket(my_src_mac_address, "127.0.0.1", 4321);
    set_dstinfo(my_dst_mac_address, "127.0.0.1", 1234);
    //子线程监听收到的消息
    pthread_t recv_thread;
    int recv_thrd = pthread_create(&recv_thread, NULL, (void *)&receiver_thd, NULL);
    sender();
    return 0;
}