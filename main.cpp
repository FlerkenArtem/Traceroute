#include <chrono>
#include <combaseapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>

using namespace std;
using namespace std::chrono;

#pragma pack(push, 1)

/// Заголовок IP
struct ipHeader
{
    unsigned char len : 4;
    unsigned char version : 4;
    unsigned char tos;
    unsigned short totalLen;
    unsigned short id;
    unsigned short flags;
    unsigned char ttl;
    unsigned char proto;
    unsigned short checkSum;

    unsigned int srcIp;
    unsigned int destIp;
};

/// Заголовок ICMP
struct icmpHeader
{
    unsigned char type;
    unsigned char code;
    unsigned short checkSum;
};

/// Заголовок UDP
struct udpHeader
{
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned short len;
    unsigned short checksum;
};

/// Структура пакета ICMP с ошибкой
struct icmpErrorPacket
{
    icmpHeader icmpHdr;
    unsigned int unused;
    ipHeader origIpHdr;
    udpHeader origUdpHdr;
    GUID data;
};

#pragma pack(pop)

/// Определение маршрута
void traceroute(string addr, int maxHops = 30);

/// Вычисление контрольной суммы
unsigned short calculateChecksum(unsigned short *buffer, int size);

/// Обработка ошибок ICMP
void errors(unsigned char charType, unsigned char charCode);

/// Точка входа в программу
int main(int argc, char *argv[])
{
    system("chcp 65001 > nul");
    setlocale(LC_ALL, ".UTF8");

    if (argc == 2) {
        string addr = argv[1];
        traceroute(addr);
    } else if (argc == 4 && string(argv[2]) == "-h") {
        string addr = argv[1];
        int hops = stoi(string(argv[3]));
        traceroute(addr, hops);
    } else {
        cerr << "Использование: "
                "имя_узла_или_IP [-h количество_шагов]";
        return 1;
    }

    return 0;
}

void traceroute(string addr, int maxHops)
{
    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;

    int err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        return;
    }

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        WSACleanup();
        return;
    }

    SOCKET sendSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET recvSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    for (int ttl = 1, port = 33434; ttl <= maxHops; ttl++, port++) {
    }

    WSACleanup();
}

unsigned short calculateChecksum(unsigned short *buffer, int size)
{
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= 2;
    }
    if (size) {
        cksum += *(static_cast<unsigned char *>(static_cast<void *>(buffer)));
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return static_cast<unsigned short>(~cksum);
}

void errors(unsigned char charType, unsigned char charCode)
{
    int type = (int) charType;
    int code = (int) charCode;

    if ((type == 0 && code == 0) || (type == 11))
        return;
    if (type == 3) {
        cerr << "Ошибка: Адресат недостижим.\t";
        if (code == 0) {
            cerr << "Сеть недоступна.";
        } else if (code == 1) {
            cerr << "Узел недоступен.";
        } else if (code == 2) {
            cerr << "Протокол недоступен.";
        } else if (code == 3) {
            cerr << "Порт недоступен.";
        } else if (code == 4) {
            cerr << "Необходима фрагментация, но не задан бит ее запрета.";
        } else if (code == 5) {
            cerr << "Ошибка на исходном маршруте.";
        } else if (code == 6) {
            cerr << "Сеть адресата неизвестна.";
        } else if (code == 7) {
            cerr << "Узел адресата неизвестен.";
        } else if (code == 8) {
            cerr << "Исходный узел изолирован.";
        } else if (code == 9) {
            cerr << "Сеть адресата административно изолирована.";
        } else if (code == 10) {
            cerr << "Узел адресата административно изолирован.";
        } else if (code == 11) {
            cerr << "Сеть недоступна для TOS.";
        } else if (code == 12) {
            cerr << "Узел недоступен для TOS.";
        } else if (code == 13) {
            cerr << "Связь административно запрещена фильтрацией.";
        } else if (code == 14) {
            cerr << "Нарушение приоритета узлов.";
        } else if (code == 15) {
            cerr << "Пренебрежение приоритетом узлов.";
        } else {
            cerr << "Ошибка. Код: " << code;
        }
    } else if (type == 4 && code == 0) {
        cerr << "Ошибка.\tПодавление отправителя.";
    } else if (type == 5) {
        cerr << "Ошибка: Перенаправление.\t";
        if (code == 0) {
            cerr << "Перенаправление для сети.";
        } else if (code == 1) {
            cerr << "Перенаправление на узел.";
        } else if (code == 2) {
            cerr << "Перенаправление на TOS и сеть.";
        } else if (code == 3) {
            cerr << "Перенаправление на TOS и узел.";
        } else {
            cerr << "Ошибка. Код: " << code;
        }
    } else if (type == 12) {
        cerr << "Ошибка: Проблема параметра.\t";
        if (code == 0) {
            cerr << "Неверный заголовок IP.";
        } else if (code == 1) {
            cerr << "Отсутствует требуемый параметр.";
        } else {
            cerr << "Ошибка. Код: " << code;
        }
    } else {
        cerr << "Ошибка. Тип: " << type << ", код: " << code;
    }
    cerr << endl;
}
