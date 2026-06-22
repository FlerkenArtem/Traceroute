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
    unsigned short destPort;
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

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    addrinfo *result = nullptr;

    if (getaddrinfo(addr.c_str(), nullptr, &hints, &result) != 0) {
        cerr << "Ошибка разрешения имени" << endl;
        return;
    }

    sockaddr_in destAddr = *(sockaddr_in *) result->ai_addr;
    freeaddrinfo(result);

    char hostBuf[NI_MAXHOST];
    char ipBuf[INET_ADDRSTRLEN];

    getnameinfo((sockaddr *) &destAddr,
                sizeof(destAddr),
                hostBuf,
                sizeof(hostBuf),
                nullptr,
                0,
                NI_NUMERICSERV);

    cout << "Трассировка маршрута к " << hostBuf << " ["
         << inet_ntop(AF_INET, &destAddr.sin_addr, ipBuf, sizeof(ipBuf)) << "] " << endl
         << "с максимальным числом прыжков " << maxHops << ":" << endl;

    // Создание сокетов
    SOCKET recvSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // ICMP-сокет для получения

    // Перевод сокета в неблокирующий режим
    unsigned long mode = 1;
    int unblock = ioctlsocket(recvSock, FIONBIO, &mode);

    SOCKET sendSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // UDP-сокет для отправки

    if (sendSock == INVALID_SOCKET || recvSock == INVALID_SOCKET) {
        cerr << "Ошибка создания сокетов" << endl;
        return;
    }

    if (unblock == SOCKET_ERROR) {
        cerr << "Ошибка перевода принимающего сокета в неблокирующий режим: " << WSAGetLastError()
             << endl;
        return;
    }

    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    struct hostent *host = gethostbyname(hostname);

    sockaddr_in localAddr;
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(0);
    localAddr.sin_addr.s_addr = ((struct in_addr *) (host->h_addr_list[0]))->s_addr;

    int bindRes = bind(recvSock, (sockaddr *) &localAddr, sizeof(localAddr));
    if (bindRes == SOCKET_ERROR) {
        cerr << "Ошибка bind принимающего сокета: " << WSAGetLastError() << endl;
        return;
    }

    DWORD optval = 1;
    DWORD bytesReturned = 0;
    if (WSAIoctl(recvSock,
                 SIO_RCVALL,
                 &optval,
                 sizeof(optval),
                 nullptr,
                 0,
                 &bytesReturned,
                 nullptr,
                 nullptr)
        == SOCKET_ERROR) {
        cerr << "Ошибка SIO_RCVALL: " << WSAGetLastError() << endl;
    }

    // Размер буфера для приема данных в байтах
    const int bufferSize = 1024;

    // Буфер приема данных
    vector<char> recvBuffer(bufferSize);

    // Каждая итерация цикла - увеличение TTL на 1
    // По 3 попытки на каждый TTL
    for (int ttl = 1; ttl <= maxHops; ttl++) {
        cout << endl << ttl << "\t";

        // Порт на текущей итерации
        int sendPort = 33434 + ttl;

        // Установка порта
        destAddr.sin_port = htons(sendPort);

        // Установка TLL
        setsockopt(sendSock, IPPROTO_IP, IP_TTL, (char *) &ttl, sizeof(ttl));

        bool addrGetted = false;
        string addrInfo;

        // 3 попытки на TTL
        for (int attempt = 0; attempt < 3; attempt++) {
            GUID origGuid{};

            // Обработка ошибки при создании GUID
            if (CoCreateGuid(&origGuid) != S_OK) {
                cout << "*\t";
                continue;
            }

            auto start = steady_clock::now();

            int sendRes = sendto(sendSock,
                                 (char *) &origGuid,
                                 sizeof(origGuid),
                                 0,
                                 (sockaddr *) &destAddr,
                                 sizeof(destAddr));

            if (sendRes == SOCKET_ERROR) {
                cout << "*\t";
                continue;
            }

            fd_set fdSet{};
            FD_ZERO(&fdSet);
            FD_SET(recvSock, &fdSet);

            timeval timeout{};
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            int selectRes = select(0, &fdSet, nullptr, nullptr, &timeout);

            if (selectRes <= 0) {
                cout << "*\t";
                continue;
            }

            if (FD_ISSET(recvSock, &fdSet)) {
                sockaddr_in fromAddr{};
                int fromSize = sizeof(fromAddr);
                int error = 0;
                steady_clock::time_point end{};

                do {
                    int bytesRecved = recvfrom(recvSock,
                                               recvBuffer.data(),
                                               recvBuffer.size(),
                                               0,
                                               (sockaddr *) &fromAddr,
                                               &fromSize);

                    if (end - start > 1s) {
                        cout << "*\t";
                        break;
                    }

                    if (bytesRecved <= 0) {
                        continue;
                    } else if (bytesRecved == SOCKET_ERROR) {
                        error = WSAGetLastError();
                        if (error != WSAEWOULDBLOCK) {
                            cerr << "Ошибка приема: " << error;
                            return;
                        }
                    } else {
                        end = steady_clock::now();
                        duration<double, milli> diff = end - start;

                        ipHeader *ipHdr = (ipHeader *) recvBuffer.data();

                        int ipLen = ipHdr->len * 4;

                        if ((unsigned long long) bytesRecved < ipLen + sizeof(icmpErrorPacket)) {
                            continue;
                        }

                        icmpErrorPacket *errPack = (icmpErrorPacket *) recvBuffer.data() + ipLen;

                        if ((errPack->icmpHdr.type == 11 && errPack->icmpHdr.code == 0)
                            || (errPack->icmpHdr.type == 0 && errPack->icmpHdr.code == 0)
                            || (errPack->icmpHdr.type == 3 && errPack->icmpHdr.code == 3)) {
                            int recvPort = ntohs(errPack->origUdpHdr.destPort);

                            GUID recvedGuid = errPack->data;

                            if (recvPort != sendPort) {
                                continue;
                            }

                            if (!IsEqualGUID(origGuid, recvedGuid)) {
                                attempt--;
                                continue;
                            }

                            char ipStr[INET_ADDRSTRLEN];

                            inet_ntop(AF_INET, &fromAddr.sin_addr, ipStr, sizeof(ipStr));

                            if (!addrGetted) {
                                char hostName[NI_MAXHOST];

                                int dnsRes = getnameinfo((sockaddr *) &fromAddr,
                                                         sizeof(fromAddr),
                                                         hostName,
                                                         NI_MAXHOST,
                                                         nullptr,
                                                         0,
                                                         0);

                                if (dnsRes == 0 && strcmp(hostName, ipStr) != 0) {
                                    addrInfo = string(hostName) + " (" + ipStr + ")";
                                } else {
                                    addrInfo = ipStr;
                                }

                                addrGetted = true;

                                if (diff.count() < 1)
                                    cout << "<1\t";
                                else
                                    cout << (int) diff.count() << "\t";

                                if (errPack->icmpHdr.type == 3 && errPack->icmpHdr.code == 3) {
                                    cout << addrInfo << endl;

                                    closesocket(sendSock);
                                    closesocket(recvSock);

                                    cout << "Достигнут целевой узел" << endl;
                                    return;
                                }
                            }
                        }
                    }
                } while (error != WSAEWOULDBLOCK);
            }
        }
        if (addrGetted)
            cout << addrInfo;
    }

    closesocket(sendSock);
    closesocket(recvSock);
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

    if ((type == 0 && code == 0) || (type == 11) || (type == 3 && code == 3))
        return;
    if (type == 3) {
        cerr << "Ошибка: Адресат недостижим.\t";
        if (code == 0) {
            cerr << "Сеть недоступна.";
        } else if (code == 1) {
            cerr << "Узел недоступен.";
        } else if (code == 2) {
            cerr << "Протокол недоступен.";
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
