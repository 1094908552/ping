//
// Created by 机械革命 on 2020/12/19.
//

#include "iping.h"
#include <iostream>

using namespace std;
iping::iping(const char *ip) {


    /*1.启动网络库*/
    if(WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
        //如果返回值为0，说明网络库启动失败,将返回错误码
        cerr<<"Failed to initialize the WinSock2 DLL"<<endl;
        cerr<<"Error code = "<<WSAGetLastError()<<endl;
    }


    /*2.解析参数ip，将它封装成一个in_addr结构体的数据*/
    unsigned long destIp = inet_addr(ip);   //inet_addr()函数将一个点分十进制的IP地址装换为unsigned long类型的IP地址
    if(destIp == INADDR_NONE) {
        //如果解析失败，说明是个域名
        hostent *destHostent = gethostbyname(ip);//调用失败会返回一个空指针
        if(destHostent == nullptr) {
            cerr << "gethostbyname function err:"<<WSAGetLastError()<<endl;
        }
        destIp = (*(in_addr*)destHostent -> h_addr).S_un.S_addr;
        printf("ping to %s[%s] with %d bytes size of data :\n",
               ip, inet_ntoa(*(in_addr*)&destIp), DEF_ICMP_DATA_SIZE);
    } else {
        printf("ping to [%s] with %d bytes size of data :\n",
               inet_ntoa(*(in_addr*)&destIp), DEF_ICMP_DATA_SIZE);
    }


    /*2.创建原始套接字用来发送icmp报文*/
    //socket和WSASocket函数都可以创建套接字，但是WSASocket支持异步操作，socket只能同步阻塞操作
    //SOCKET socketRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    SOCKET socketRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(socketRaw == INVALID_SOCKET) {
        cerr<<"socket init err, error code"<<WSAGetLastError()<<endl;
    }
    int timeOut = DEF_ICMP_TIMEOUT;
    //设置接收与发送的超时时间
    if(setsockopt(socketRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeOut, sizeof(timeOut)) == SOCKET_ERROR ||
            setsockopt(socketRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeOut, sizeof(timeOut)) == SOCKET_ERROR) {
        cerr << "Fail to set recv or send time out, error code:" << WSAGetLastError() << endl;
        closesocket(socketRaw);
        WSACleanup();
        return;
    }


    sockaddr_in destSocket;
    memset(&destSocket, 0, sizeof(destSocket));
    destSocket.sin_family = AF_INET;
    destSocket.sin_addr.S_un.S_addr = destIp;


    //2.封装icmp数据报
    char icmpSendBuf[sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE];
    memset(&icmpSendBuf, 0, sizeof(icmpSendBuf));
    ICMP_HEADER* icmpHeader = (ICMP_HEADER*) icmpSendBuf;
    icmpHeader -> type = ICMP_ECHO_REQUEST;    //类型字段置为8，代表一个icmp询问报文
    icmpHeader -> code = 0;    //代码字段置为0，在询问与回答报文中，它的值都为0
    icmpHeader -> id = GetCurrentProcessId();  //ping程序的icmp报文首部其余部分为进程id与发送数据的序号，类型为unsigned short
    memset(icmpSendBuf + sizeof(ICMP_HEADER), 'E', DEF_ICMP_DATA_SIZE);  //将icmp报文数据部分都置为E



    //3.创建一片接收缓冲区接收到一个IP数据报
    unsigned char recvBuf[MAX_ICMP_PACKET_SIZE];
    memset(recvBuf,0,sizeof(recvBuf));
    DECODE_RESULT stDecodeResult;
    for(int i = 0; i < PING_MSG_NUM; i++) {
        //设置序列号，时间戳，以及检验和
        icmpHeader -> seq = htons(i);
        icmpHeader -> cksum = 0;
        icmpHeader -> cksum = setCheckSum((unsigned short*)&icmpSendBuf, sizeof(icmpSendBuf));
        //记录时间与序号与目的IP地址
        stDecodeResult.dwRoundTripTime = GetTickCount();
        stDecodeResult.usSeqNo = i;
        stDecodeResult.dwIPaddr = *(in_addr*)&destIp;
        //发送icmp数据报
        if(sendto(socketRaw, icmpSendBuf, sizeof(icmpSendBuf), 0, (sockaddr*)&destSocket, sizeof(sockaddr)) == SOCKET_ERROR) {
            //如果目的主机不可达则直接退出
            if (WSAGetLastError() == WSAEHOSTUNREACH) {
                cout << '\t' << "Destination host unreachable.\n"
                     << "\nPinging complete.\n" << endl;
            }
                cout<<"error code:"<<WSAGetLastError()<<endl;
            closesocket(socketRaw);
            WSACleanup();
            return;
        }
        //阻塞模型，循环访问原始套接字是否接收到数据
        sockaddr_in from;
        int fromLen = sizeof(from);
        int iRecvLen;
        while(true) {
            iRecvLen = recvfrom(socketRaw, (char*)recvBuf, sizeof(recvBuf), 0, (sockaddr*)&from, &fromLen);
            if(iRecvLen != SOCKET_ERROR) {
                if(DecodeIcmpResponse((char*)recvBuf, iRecvLen, &stDecodeResult)) {
                    printf("reply from %s :bytes = %d, RRT = %d, TTL = %d\n",
                           inet_ntoa(stDecodeResult.dwIPaddr), DEF_ICMP_DATA_SIZE, stDecodeResult.dwRoundTripTime, (int)stDecodeResult.iTTL);
                    break;
                }
            } else if(WSAGetLastError() == WSAETIMEDOUT) {
                cout<<"Request timeout"<<endl;
                break;
            } else {//其他错误
                cerr << "\nFailed to call recvfrom\n"
                     << "error code: " << WSAGetLastError() << endl;
                closesocket(socketRaw);
                WSACleanup();
                return;
            }
        }
    }
    cout<<"ping complete!"<<endl;
    closesocket(socketRaw);
    WSACleanup();
}

/**
 * （1）把IP数据包的校验和字段置为0；
 * （2）把首部看成以16位为单位的数字组成，依次进行二进制求和（注意：求和时应将最高位的进位保存，所以加法应采用32位加法）；
 * （2.5）如果最后不足16位，则将余下的8位前补8位0再求和
 * （3）将上述加法过程中产生的进位（最高位的进位）加到低16位（采用32位加法时，即为将高16位与低16位相加，之后还要把该次加法最高位产生的进位加到低16位）
 * （4）将上述的和取反，即得到校验和。
 * @param sendBuf
 * @param sendBufSize
 */
unsigned short iping::setCheckSum(unsigned short *pBuf, int iSize) {
    unsigned long cksum = 0;
    while (iSize>1)
    {
        cksum += *pBuf++;
        iSize -= sizeof(USHORT);
    }
    if (iSize)
        cksum += *(UCHAR*)pBuf;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    return (USHORT)(~cksum);
}

/**
 * 解析接icmp响应数据报
 * 从ip首部获取TTl，对方IP地址，封装的协议类型，
 * 从icmp首部获取时间戳，进程id
 *
 * 先查看协议类型，如果是ICMP数据报则进行下一步
 * 查看ICMP数据报类型，如果是响应数据报则进行下一步
 * 查看进程号与序列号
 * @param pBuf 传入要解析的IP数据报
 * @param packetSize 接收到的IP数据报的大小
 * @param stDecodeResult 解析结果
 * @return
 */
bool iping::DecodeIcmpResponse(const char *pBuf, int packetSize, DECODE_RESULT *stDecodeResult) {
    IP_HEADER* ipHeader = (IP_HEADER*) pBuf;
    //判断此IP数据报内部是不是一个ICMP数据报
    if(ipHeader -> protocol != 1) {
        return false;
    }
    int ipHeaderLen = (ipHeader -> hdr_len) * 4;
    ICMP_HEADER* icmpHeader = (ICMP_HEADER *)(pBuf + ipHeaderLen);
    //判断这个ip报的源ip地址，icmp首部的进程id与序列号
    unsigned short pid = GetCurrentProcessId();
    if(stDecodeResult -> dwIPaddr.S_un.S_addr == ipHeader -> sourceIP
        && stDecodeResult -> usSeqNo == ntohs(icmpHeader -> seq)
        && icmpHeader -> id == pid) {
        //计算TTL
        stDecodeResult -> iTTL = ipHeader -> ttl;
        stDecodeResult -> dwRoundTripTime = GetTickCount() - stDecodeResult -> dwRoundTripTime;
        return true;
    }
    return false;
}