//
// Created by 机械革命 on 2020/12/19.
//

#ifndef PING_IPING_H
#define PING_IPING_H


#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

typedef struct
{
    unsigned char	hdr_len	:4;		// length of the header
    unsigned char	version	:4;		// version of IP
    unsigned char	tos;			// type of service
    unsigned short	total_len;		// total length of the packet
    unsigned short	identifier;		// unique identifier
    unsigned short	frag_and_flags;	// flags
    unsigned char	ttl;			// time to live
    unsigned char	protocol;		// protocol (TCP, UDP etc)
    unsigned short	checksum;		// IP checksum

    unsigned long	sourceIP;		// source IP address
    unsigned long	destIP;			// destination IP address

} IP_HEADER;

typedef struct
{
    unsigned char	type;		//8位类型
    unsigned char	code;		//8位代码
    unsigned short	cksum;		//16位校验和
    unsigned short	id;			//16位标识符
    unsigned short	seq;		//16位序列号

} ICMP_HEADER;

//解码结果
typedef struct
{
    USHORT usSeqNo;			//包序列号
    DWORD dwRoundTripTime;	//往返时间
    in_addr dwIPaddr;		//对端IP地址
    BYTE iTTL;      //跳数
} DECODE_RESULT;

const unsigned char ICMP_ECHO_REQUEST	= 8;	//请求回显
const unsigned char ICMP_ECHO_REPLY		= 0;	//回显应答

const DWORD DEF_ICMP_TIMEOUT	= 3000;	//默认超时时间，单位ms
const int DEF_ICMP_DATA_SIZE	= 32;	//默认ICMP数据部分长度
const int MAX_ICMP_PACKET_SIZE	= 1024;	//最大ICMP数据报的大小
const int PING_MSG_NUM = 4; //默认ping程序发送4个数据报


/**
 * 1.传入目标地址，
 * 2.封装icmp报文
 * 3.向目标地址发送icmp报文
 */
class iping {
private:
    sockaddr_in destSocket;
    sockaddr_in srcSocket;

    WSADATA wsadata;
public:
    /**
     * 构造函数，先查看传入参数域名还是ip地址，如果是域名，则将它解析为一个IP地址
     * @param ip 传入目标地址
     */
    explicit iping(const char* ip);
    unsigned short setCheckSum(unsigned short *pBuf, int iSize);
    bool DecodeIcmpResponse(const char* pBuf, int packetSize, DECODE_RESULT* stDecodeResult);
};



#endif //PING_IPING_H
