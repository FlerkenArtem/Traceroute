#include <winsock2.h>
#include <ws2tcpip.h>
#include <combaseapi.h>
#include <iostream>
#include <optional>
#include <regex>
#include <chrono>

using namespace std;
using namespace std::chrono;

struct ipHeader
{
    unsigned char headerLength : 4;
    unsigned char version : 4;
    unsigned char typeOfService;
    unsigned short length;
    unsigned short id;
    unsigned short fragmentOffset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checkSum;
    IN_ADDR from;
    IN_ADDR dest;
};

struct ipPacket
{
    ipHeader header;
    GUID data;
};

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
SOCKET createIcmpSocket();

/// Создание сокета
SOCKET createUdpSocket();

/// Подключение сокета
optional<sockaddr_in> connectAddr();

/// Подключение сокета по IP-адресу
sockaddr_in connectIpAddr();

/// Подключение сокета по DNS-имени
optional<sockaddr_in> connectDnsAddr();

/// Получение максимального числа шагов
int maxHops();

/// Определение маршрута
void traceroute(SOCKET sockUdp, SOCKET sockIcmp, int maxHops, sockaddr_in destAddr);

/// Вычисление контрольной суммы
unsigned short calculateChecksum(unsigned short *buffer, int size);

int main()
{
    system("chcp 65001");
    setlocale(LC_ALL, ".UTF8");

    cout << "TRACEROUTE" << endl;

    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;

    int err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        cerr << "Ошибка инициализации WSAStartup: " << err << endl;
        return 1;
    }

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        cerr << "Не найдена нужная версия Winsock" << endl;
        WSACleanup();
        return 1;
    }

    cout << "Winsock 2.2 dll успешно найден" << endl;

    SOCKET sockImcp = createIcmpSocket();
    if (sockImcp == (unsigned long long) SOCKET_ERROR || sockImcp == INVALID_SOCKET) {
        cerr << "Ошибка создания сокета IMCP" << sockImcp << endl;
        WSACleanup();
        return 1;
    }

    SOCKET sockUdp = createUdpSocket();
    if (sockUdp == (unsigned long long) SOCKET_ERROR || sockUdp == INVALID_SOCKET) {
        cerr << "Ошибка создания сокета UDP" << sockUdp << endl;
        WSACleanup();
        return 1;
    }

    optional<sockaddr_in> destAddr = connectAddr();
    if (destAddr == nullopt) {
        cerr << "Ошибка подключения к адресу" << endl;
        return 1;
    }

    int hops = maxHops();

    traceroute(sockUdp, sockImcp, hops, *destAddr);

    WSACleanup();
    return 0;
}

unsigned long getLocalIP() {
    SOCKET udpSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSock == INVALID_SOCKET) return INADDR_ANY;

    sockaddr_in loopback;
    loopback.sin_family = AF_INET;
    loopback.sin_addr.s_addr = inet_addr("8.8.8.8");
    loopback.sin_port = htons(53);

    if (connect(udpSock, reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback)) == SOCKET_ERROR) {
        closesocket(udpSock);
        return INADDR_ANY;
    }

    sockaddr_in localAddr;
    int len = sizeof(localAddr);
    if (getsockname(udpSock, reinterpret_cast<sockaddr*>(&localAddr), &len) == SOCKET_ERROR) {
        closesocket(udpSock);
        return INADDR_ANY;
    }

    closesocket(udpSock);
    return localAddr.sin_addr.s_addr;
}

SOCKET createIcmpSocket()
{
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

    if (bind(sock, reinterpret_cast<SOCKADDR*>(&localAddr), sizeof(localAddr)) == SOCKET_ERROR) {
        int lastErr = WSAGetLastError();
        cerr << "Ошибка bind для SOCK_RAW: " << lastErr << endl;
        closesocket(sock);
        return INVALID_SOCKET;
    }

    cout << "Сокет успешно создан и привязан к интерфейсу" << endl;
    return sock;
}

SOCKET createUdpSocket()
{
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
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

    if (bind(sock, reinterpret_cast<SOCKADDR*>(&localAddr), sizeof(localAddr)) == SOCKET_ERROR) {
        int lastErr = WSAGetLastError();
        cerr << "Ошибка bind для SOCK_DGRAM: " << lastErr << endl;
        closesocket(sock);
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

void traceroute(SOCKET sockUdp, SOCKET sockIcmp, int maxHops, sockaddr_in destAddr)
{
    DWORD timeout = 3000;
    if (setsockopt(sockIcmp,
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&timeout),
                   sizeof(timeout)) == SOCKET_ERROR) {
        cerr << "Ошибка конфигурации таймаута ICMP: " << WSAGetLastError() << endl;
        return;
    }

    GUID guid;
    CoCreateGuid(&guid);

    char recvBuffer[1024];
    sockaddr_in fromAddr;
    int fromLen = sizeof(fromAddr);
    USHORT basePort = 33434;

    char destIpStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(destAddr.sin_addr), destIpStr, INET_ADDRSTRLEN);
    cout << "\nТрассировка маршрута к " << destIpStr
         << " с максимальным числом шагов " << maxHops << ":\n\n";

    for (int ttl = 1; ttl < maxHops; ttl++) {
        if (setsockopt(sockUdp,
                       IPPROTO_IP,
                       IP_TTL,
                       reinterpret_cast<const char*>(&ttl),
                       sizeof(ttl)) == SOCKET_ERROR) {
            cerr << "Ошибка установки TTL: " << WSAGetLastError() << endl;
            return;
        }

        destAddr.sin_port = htons(basePort + ttl);

        time_point start = high_resolution_clock::now();
        if (sendto(sockUdp, reinterpret_cast<const char*>(&guid), sizeof(GUID), 0,
                   reinterpret_cast<sockaddr*>(&destAddr), sizeof(destAddr)) == SOCKET_ERROR) {
            cerr << "Ошибка отправки пакета: " << WSAGetLastError() << endl;
            return;
        }

        int res = recvfrom(sockIcmp, recvBuffer, sizeof(recvBuffer), 0, reinterpret_cast<sockaddr*>(&fromAddr), &fromLen);
        time_point end = chrono::high_resolution_clock::now();
        duration<double, milli> elapsed = end - start;

        if (res == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                cout << ttl << "\t* * *\tВремя ожидания ответа истекло." << endl;
                continue;
            } else {
                cerr << "Ошибка recvfrom: " << err << endl;
                return;
            }
        }

        ipHeader* outIpHdr = reinterpret_cast<ipHeader*>(recvBuffer);
        int outIpLen = outIpHdr->headerLength * 4;

        icmpHeader* icmpHdr = reinterpret_cast<icmpHeader*>(recvBuffer + outIpLen);

        char responderIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(fromAddr.sin_addr), responderIp, INET_ADDRSTRLEN);

        cout << elapsed.count() << " мс\t" << responderIp;

        if (icmpHdr->type == 11) {
            char* innerPayload = reinterpret_cast<char*>(icmpHdr) + sizeof(icmpHeader);
            ipHeader* innerIpHdr = reinterpret_cast<ipHeader*>(innerPayload);
            int innerIpLen = innerIpHdr->headerLength * 4;

            GUID* innerGuid = reinterpret_cast<GUID*>(innerPayload + innerIpLen + 8);

            if (memcmp(innerGuid, &guid, sizeof(GUID)) == 0) {
                cout << " [OK]" << endl;
            } else {
                cout << " [Чужой пакет]" << endl;
            }
        }
        else if (icmpHdr->type == 3 && icmpHdr->code == 3) {
            cout << "\n\nТрассировка завершена. Цель достигнута." << endl;
            break;
        }
        else {
            cout << " (ICMP тип: " << (int)icmpHdr->type << ", код: " << (int)icmpHdr->code << ")" << endl;
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
