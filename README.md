# 计网Project
## Step 1
以中间文件形式实现以太网帧的打包和解包

## Step 2
使用`Linux`的`Raw Socket`实现`数据链路层(以太网帧)-网络层(IP)-传输层(UDP)`的打包和解包
PS:由于以太网帧的fcs已被内核处理，故接收端获取不到（所以打包时也没写fcs）
### 函数调用
#### sender
打包：`pack_segment`-`pack_packet`-`pack_frame`
#### receiver
解包：`unpack_frame`-`unpack_packet`-`unpack_segment`

### 实现过程
为方便测试，程序通过本地回环网卡`lo`发送数据
#### sender
首先根据资料进行代码编写，然后使用python发送正常的udp包, 并使用`wireshark`抓包进行比对。将抓包结果与生成的数据逐一对比，校验修改(其中udp层的checksum仅计算了伪首部)
#### receiver
在`step 1`的基础上，将其改为监听网卡的IP数据报。层层解包，同时检查MAC地址、IP地址、IP校验和、端口及udp校验和，最终输出payload

### 结果截图
sender receiver：
![sender&receiver](img/sr.png)
wireshark抓包：
![wireshark](img/ws.png)