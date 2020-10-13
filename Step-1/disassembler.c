#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "frame_type.h"
#include "crc32.h"

char my_address[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

int get_file_size(FILE *pFile)
{
    fseek(pFile, 0, SEEK_END);
    int size = ftell(pFile);
    rewind(pFile);
    return size;
}

void prinfHexData(const char *name, char *buffer, int size)
{
    printf(name);
    printf(": 0x");
    for (int i = 0; i < size; i++)
    {
        printf("%.2x", buffer[i]);
    }
    printf("\n");
}

int unpack_frame(char *frame_data, int frame_len)
{
    //初始化变量
    char payload[1500];
    memset(payload, 0, 1500);
    uint32_t fcs;
    uint32_t fcs_excepted;
    //判断帧长度
    if (frame_len < 64 || frame_len > 1518)
    {
        printf("[×]frame length error!\n");
        return -1;
    }
    //解析 header
    struct frame_header header;
    memcpy(header.destination_address, frame_data, 6);
    memcpy(header.source_address, frame_data + 6, 6);
    memcpy(header.protocol_type, frame_data + 12, 2);
    //拷贝payload
    int payload_len = frame_len - 18;
    memcpy(payload, frame_data + 14, payload_len);
    memcpy(&fcs, frame_data + 14 + payload_len, 4);
    //检查地址
    if (!memcmp(header.destination_address, my_address, 6))
    {
        printf("[√]address check success\n");
    }
    else
    {
        printf("[√]address check failed\n");
        //return -1;
    }
    //检查校验码
    fcs_excepted = crc32(frame_data, payload_len + 14);
    if (fcs_excepted == fcs)
    {
        printf("[√]fcs check success\n");
    }
    else
    {
        printf("[×]fcs check failed!\n");
    }
    //打印结果
    printf("frame length: %d\n", frame_len);
    //header
    prinfHexData("destination address", header.destination_address, 6);
    prinfHexData("source address", header.source_address, 6);
    prinfHexData("protocol type", header.protocol_type, 2);
    //payload
    printf("payload length: %d\n", payload_len);
    printf("payload content: %s\n", payload);
    int payload_content_length = strlen(payload);
    printf("payload content length: %d\n", payload_content_length);
    //fcs
    printf("fcs: %x\n", fcs);
    printf("fcs excepted: %x\n", fcs_excepted);
}

int main()
{
    printf("Frame data Disassembler\n");
    prinfHexData("my address", my_address, 6);
    //读取文件
    FILE *pFile = fopen("frame.bin", "rb");
    int frame_len = get_file_size(pFile);
    char *frame_data = (char *)malloc(frame_len);
    fread(frame_data, sizeof(char), frame_len, pFile);
    fclose(pFile);
    //解析帧
    unpack_frame(frame_data, frame_len);

    return 0;
}