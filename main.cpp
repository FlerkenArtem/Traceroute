#include <combaseapi.h>
#include <iostream>
#include <optional>
#include <regex>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <chrono>

using namespace std;
using namespace std::chrono;

struct icmpHeader
{
    unsigned char type;
    unsigned char code;
    unsigned short checkSum;
    unsigned short id;
    unsigned short sequence;
};

struct icmpPacket
{
    icmpHeader header;
    GUID data;
};

/// Создание сокета
SOCKET createSocket();

/// Подключение сокета
optional<sockaddr_in> connectAddr();

/// Подключение сокета по IP-адресу
sockaddr_in connectIpAddr();

/// Подключение сокета по DNS-имени
optional<sockaddr_in> connectDnsAddr();

/// Получение максимального числа шагов
int maxHops();

/// Определение маршрута
void traceroute(SOCKET sock, int maxHops, sockaddr_in destAddr);

/// Вычисление контрольной суммы
unsigned short calculateChecksum(unsigned short *buffer, int size);

int main()
{
    system("chcp 65001");
    setlocale(LC_ALL, ".UTF8");

    cout << "TRACEROUTE" << endl;

    SOCKET sock = createSocket();
    if (sock == (unsigned long long) SOCKET_ERROR || sock == INVALID_SOCKET) {
        cerr << "Ошибка создания сокета" << sock << endl;
        return 1;
    }

    optional<sockaddr_in> destAddr = connectAddr();
    if (destAddr == nullopt) {
        cerr << "Ошибка подключения к адресу" << endl;
        return 1;
    }

    int hops = maxHops();

    traceroute(sock, hops, *destAddr);

    return 0;
}

unsigned long getLocalIP()
{
    SOCKET udpSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSock == INVALID_SOCKET)
        return INADDR_ANY;

    sockaddr_in loopback;
    loopback.sin_family = AF_INET;
    loopback.sin_addr.s_addr = inet_addr("8.8.8.8");
    loopback.sin_port = htons(53);

    if (connect(udpSock, reinterpret_cast<sockaddr *>(&loopback), sizeof(loopback))
        == SOCKET_ERROR) {
        closesocket(udpSock);
        return INADDR_ANY;
    }

    sockaddr_in localAddr;
    int len = sizeof(localAddr);
    if (getsockname(udpSock, reinterpret_cast<sockaddr *>(&localAddr), &len) == SOCKET_ERROR) {
        closesocket(udpSock);
        return INADDR_ANY;
    }

    closesocket(udpSock);
    return localAddr.sin_addr.s_addr;
}

SOCKET createSocket()
{
    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;

    int err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        cerr << "Ошибка инициализации WSAStartup: " << err << endl;
        return INVALID_SOCKET;
    }

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        cerr << "Не найдена нужная версия Winsock" << endl;
        WSACleanup();
        return INVALID_SOCKET;
    }

    cout << "Winsock 2.2 dll успешно найден" << endl;

    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock == INVALID_SOCKET) {
        int lastErr = WSAGetLastError();
        cerr << "Ошибка создания сокета: " << lastErr << endl;
        WSACleanup();
        return INVALID_SOCKET;
    }

    sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(0);
    localAddr.sin_addr.s_addr = getLocalIP();

    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(localAddr.sin_addr), ipStr, INET_ADDRSTRLEN);

    if (::bind(sock, reinterpret_cast<SOCKADDR *>(&localAddr), sizeof(localAddr)) == SOCKET_ERROR) {
        int lastErr = WSAGetLastError();
        cerr << "Ошибка bind для SOCK_RAW: " << lastErr << endl;
        closesocket(sock);
        WSACleanup();
        return INVALID_SOCKET;
    }

    cout << "Сокет успешно создан и привязан к интерфейсу" << endl;
    return sock;
}

optional<sockaddr_in> connectAddr()
{
    optional<sockaddr_in> conn;
    int type = 0;

    while (type != 1 && type != 2) {
        cout << "Выберите тип соединения: " << endl;
        cout << "1. IP" << endl;
        cout << "2. DNS" << endl;
        cin >> type;
        if (type != 1 && type != 2) {
            cout << "Ошибка при вводе типа подключения.";
        }
    }

    if (type == 1) {
        conn = connectIpAddr();
    } else if (type == 2) {
        conn = connectDnsAddr();
    } else {
        cerr << "Не выбран тип соединения, невозможно подключиться";
    }

    return conn;
}

sockaddr_in connectIpAddr()
{
    const regex ipPattern("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
                          "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    string ip;

    while (true) {
        cout << "Введите IP-адрес: ";
        cin >> ip;
        if (!regex_match(ip, ipPattern)) {
            cout << "IP-адрес введен неверно" << endl;
            continue;
        }
        break;
    }

    sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;                    // IPv4
    destAddr.sin_port = 0;                            // Выбор случайного порта
    destAddr.sin_addr.s_addr = inet_addr(ip.c_str()); // Установка IP-адреса

    return destAddr;
}

optional<sockaddr_in> connectDnsAddr()
{
    string hostname;
    sockaddr_in destAddr;

    cout << "Введите DNS-имя: ";
    cin >> hostname;

    struct addrinfo hints;
    struct addrinfo *result = nullptr;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP; // ICMP

    int dnsResult = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
    if (dnsResult != 0) {
        cerr << "Ошибка разрешения DNS: " << dnsResult << endl;
        return nullopt;
    }

    if (result != nullptr && result->ai_addr != nullptr) {
        memcpy(&destAddr, result->ai_addr, sizeof(sockaddr_in));
    }

    freeaddrinfo(result);
    return destAddr;
}

int maxHops()
{
    int hops = 0;
    while (hops <= 0) {
        cout << "Введите максимальное число шагов: ";
        cin >> hops;
        if (hops <= 0) {
            cout << "Введено некррекное число шагов. Введите число больше 0.";
        }
    }
    return hops;
}

void traceroute(SOCKET sock, int maxHops, sockaddr_in destAddr)
{
    unsigned short processId = static_cast<unsigned short>(GetCurrentProcessId());
    icmpPacket pac;
    DWORD timeout = 3000;

    if (setsockopt(sock,
                   SOL_SOCKET,
                   SO_SNDTIMEO,
                   reinterpret_cast<const char *>(&timeout),
                   sizeof(timeout))
            == SOCKET_ERROR
        || setsockopt(sock,
                      SOL_SOCKET,
                      SO_RCVTIMEO,
                      reinterpret_cast<const char *>(&timeout),
                      sizeof(timeout))
               == SOCKET_ERROR) {
        cerr << "Не удалось установить таймауты сокета: " << WSAGetLastError() << endl;
        return;
    }

    const int bufferSize = 1024;
    char recvBuffer[bufferSize];

    for (int i = 0; i < maxHops; i++) {
        GUID guid;
        CoCreateGuid(&guid);

        pac.header.type = 8;
        pac.header.code = 0;
        pac.header.checkSum = 0;
        pac.header.id = processId;
        pac.header.sequence = static_cast<unsigned short>(i);
        pac.data = guid;

        pac.header.checkSum = calculateChecksum(reinterpret_cast<unsigned short *>(&pac),
                                                sizeof(pac));

        int ttl = i + 1;
        if (setsockopt(sock, IPPROTO_IP, IP_TTL, reinterpret_cast<const char *>(&ttl), sizeof(ttl))
            == SOCKET_ERROR) {
            cerr << "Не удалось установить TTL: " << WSAGetLastError() << endl;
            return;
        }

        int res = sendto(sock,
                         reinterpret_cast<const char *>(&pac),
                         sizeof(pac),
                         0,
                         reinterpret_cast<SOCKADDR *>(&destAddr),
                         sizeof(destAddr));
        if (res == SOCKET_ERROR) {
            cerr << "Ошибка отправки: " << WSAGetLastError() << endl;
            return;
        }

        auto start = chrono::high_resolution_clock::now();

        sockaddr_in fromAddr;
        int fromLen = sizeof(fromAddr);
        bool stepCompleted = false;

        while (!stepCompleted) {
            int recvRes = recvfrom(sock,
                                   recvBuffer,
                                   bufferSize,
                                   0,
                                   reinterpret_cast<SOCKADDR *>(&fromAddr),
                                   &fromLen);
            auto end = high_resolution_clock::now();
            auto duration = high_resolution_clock::duration(end-start);
            auto durationMs = duration_cast<milliseconds>(duration);

            if (recvRes == SOCKET_ERROR) {
                if (WSAGetLastError() == WSAETIMEDOUT) {
                    cout << ttl << "\t* * *" << endl;
                    stepCompleted = true;
                    continue;
                } else {
                    cerr << "Ошибка получения: " << WSAGetLastError() << endl;
                    return;
                }
            }

            if (recvRes < 20)
                continue;

            unsigned char *ipHeader = reinterpret_cast<unsigned char *>(recvBuffer);
            int ipHeaderLen = (ipHeader[0] & 0x0F) * 4;

            if (recvRes < ipHeaderLen + 8)
                continue;

            icmpHeader *icmpRes = reinterpret_cast<icmpHeader *>(recvBuffer + ipHeaderLen);

            if (icmpRes->type == 0) {
                if (icmpRes->id != processId || icmpRes->sequence != i) {
                    continue;
                }

                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(fromAddr.sin_addr), ipStr, INET_ADDRSTRLEN);

                char hostName[NI_MAXHOST];
                int dnsRes = getnameinfo(reinterpret_cast<SOCKADDR *>(&fromAddr),
                                         sizeof(fromAddr),
                                         hostName,
                                         NI_MAXHOST,
                                         nullptr,
                                         0,
                                         0);

                if (dnsRes == 0 && strcmp(hostName, ipStr) != 0) {
                    cout << ttl << "\t" << hostName << "\t(" << ipStr << ")" << "\t(" << durationMs.count() << " мс)";
                } else {
                    cout << ttl << "\t" << ipStr << "\t(" << durationMs.count() << " мс)";
                }
                cout << "\tДостигнут целевой узел" << endl;

                return;
            } else if (icmpRes->type == 11) {
                int innerIpHeaderOffset = ipHeaderLen + 8;
                if (recvRes < innerIpHeaderOffset + 20)
                    continue;

                unsigned char *innerIpHeader = reinterpret_cast<unsigned char *>(
                    recvBuffer + innerIpHeaderOffset);
                int innerIpHeaderLen = (innerIpHeader[0] & 0x0F) * 4;

                if (recvRes < innerIpHeaderOffset + innerIpHeaderLen + 8)
                    continue;

                icmpHeader *originalIcmp = reinterpret_cast<icmpHeader *>(
                    recvBuffer + innerIpHeaderOffset + innerIpHeaderLen);

                if (originalIcmp->id != processId || originalIcmp->sequence != i) {
                    continue;
                }

                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(fromAddr.sin_addr), ipStr, INET_ADDRSTRLEN);

                char hostName[NI_MAXHOST];
                int dnsRes = getnameinfo(reinterpret_cast<SOCKADDR *>(&fromAddr),
                                         sizeof(fromAddr),
                                         hostName,
                                         NI_MAXHOST,
                                         nullptr,
                                         0,
                                         0);

                if (dnsRes == 0 && strcmp(hostName, ipStr) != 0) {
                    cout << ttl << "\t" << hostName << "\t(" << ipStr << ")"  << "\t(" << durationMs.count() << " мс)" << endl;
                } else {
                    cout << ttl << "\t" << ipStr  << "\t(" << durationMs.count() << " мс)" << endl;
                }

                stepCompleted = true;
            }
        }
    }
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
