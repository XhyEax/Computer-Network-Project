#include <stdio.h>
#include <string.h>
#include "frame_type.h"
#include "crc32.h"

//初始化变量
char da[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
char sa[6] = {0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
char protocol_type[2] = {0x08, 0x00};

char frame_data[1518]; //Ethernet帧
char payload[1500];

int pack_frame(char *da, char *sa, char *protocol_type, char *frame_data, char *payload, int payload_len)
{
    struct frame_header header;
    memcpy(header.destination_address, da, 6);
    memcpy(header.source_address, sa, 6);
    memcpy(header.protocol_type, protocol_type, 2);
    //复制header
    memcpy(frame_data, &header, 14);
    //复制payload
    memcpy(frame_data + 14, payload, payload_len);
    //计算并复制fcs
    uint32_t fcs = crc32(frame_data, payload_len + 14);
    memcpy(frame_data + payload_len + 14, &fcs, 4);
    int frame_len = payload_len + 18;
    return frame_len;
}

int main()
{
    //读取用户输入
    printf("Please input payload:\n");
    scanf("%[^\n]", payload);
    int payload_len = strlen(payload);
    if (payload_len < 46)
    {
        payload_len = 46;//填充0x00至最小长度
    }
    //打包成帧
    int frame_len = pack_frame(da, sa, protocol_type, frame_data, payload, payload_len);
    //写入文件
    FILE *pFile = fopen("frame.bin", "w");
    fwrite(frame_data, sizeof(char), frame_len, pFile);
    fclose(pFile);
    return 0;
}