#include <winsock2.h>
#include <ws2tcpip.h>
#include <combaseapi.h>
#include <chrono>
#include <iostream>
#include <optional>
#include <regex>

using namespace std;
using namespace std::chrono;

/// Заголовок ICMP
struct icmpHeader
{
    unsigned char type;
    unsigned char code;
    unsigned short checkSum;
};

/// ICMP-пакет
struct icmpPacket
{
    icmpHeader header;
    GUID data;
};

/// Получение локального IP адреса
unsigned long getLocalIP();

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

/// Точка входа в программу
int main()
{
    system("chcp 65001");
    setlocale(LC_ALL, ".UTF8");

    cout << "TRACEROUTE" << endl;

    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;

    int err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        return 1;
    }

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        WSACleanup();
        return 1;
    }

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
    SOCKET udpSock = socket(AF_INET, SOCK_DGRAM, 0); // Создание сокета UDP
    if (udpSock == INVALID_SOCKET)
        return INADDR_ANY;

    sockaddr_in loopback;
    loopback.sin_family = AF_INET;
    loopback.sin_addr.s_addr = inet_addr("8.8.8.8");
    loopback.sin_port = htons(53); // Порт DNS

    // Подключение к адресу
    if (connect(udpSock, reinterpret_cast<sockaddr *>(&loopback), sizeof(loopback))
        == SOCKET_ERROR) {
        closesocket(udpSock);
        return INADDR_ANY;
    }

    // Извлечение IP-адреса
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
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock == INVALID_SOCKET) {
        int lastErr = WSAGetLastError();
        cerr << "Ошибка создания сокета: " << lastErr << endl;
        WSACleanup();
        return INVALID_SOCKET;
    }

    // Переключение в неблокирующий режим
    unsigned long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(0);
    localAddr.sin_addr.s_addr = getLocalIP();

    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(localAddr.sin_addr), ipStr, INET_ADDRSTRLEN);

    if (bind(sock, reinterpret_cast<SOCKADDR *>(&localAddr), sizeof(localAddr)) == SOCKET_ERROR) {
        int lastErr = WSAGetLastError();
        cerr << "Ошибка bind для SOCK_RAW: " << lastErr << endl;
        closesocket(sock);
        WSACleanup();
        return INVALID_SOCKET;
    }

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
    hints.ai_family = AF_INET;        // IPv4
    hints.ai_socktype = SOCK_RAW;     // Сырой сокет
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
    DWORD sendTimeout = 3000;

    if (setsockopt(sock,        // Сокет
                   SOL_SOCKET,  // Уровень сокета
                   SO_SNDTIMEO, // Таймаут отправки
                   reinterpret_cast<const char *>(
                       &sendTimeout),   // Указатель на значение таймаута отправки
                   sizeof(sendTimeout)) // Размер таймаута
        == SOCKET_ERROR) {
        cerr << "Не удалось установить таймаут отправки: " << WSAGetLastError() << endl;
        return;
    }

    const int bufferSize = 20 + sizeof(icmpPacket); // Размер буфера
    char recvBuffer[bufferSize];                    // Буфер

    for (int i = 0; i < maxHops; i++) {
        GUID origGuid;
        CoCreateGuid(&origGuid);
        GUID recvedGuid;

        // Формирование пакета на отправку
        icmpPacket sendPack;
        sendPack.header.type = 8;
        sendPack.header.code = 0;
        sendPack.header.checkSum = 0;
        sendPack.data = origGuid;
        sendPack.header.checkSum = calculateChecksum(reinterpret_cast<unsigned short *>(&sendPack),
                                                     sizeof(sendPack));
        // Расчет времени жизни
        int ttl = i + 1;
        cout << ttl;

        if (setsockopt(sock,                                 // Сокет
                       IPPROTO_IP,                           // Уровень IP
                       IP_TTL,                               // Имя параметра - время жизни
                       reinterpret_cast<const char *>(&ttl), // Указатель на переменную времени жизни
                       sizeof(ttl))                          // размер переменной времени жизни
            == SOCKET_ERROR) {
            cerr << "Не удалось установить TTL: " << WSAGetLastError() << endl;
            return;
        }

        for (int j = 0; j < 3; j++) {
            // Сохранение времени начала
            auto start = high_resolution_clock::now();

            sockaddr_in fromAddr;
            int fromLen = sizeof(fromAddr);

            bool stepCompleted = false;

            // Отправка
            int res = sendto(sock,
                             reinterpret_cast<const char *>(&sendPack),
                             sizeof(sendPack),
                             0,
                             reinterpret_cast<SOCKADDR *>(&destAddr),
                             sizeof(destAddr));

            // Обработка ошибок отправки
            if (res == SOCKET_ERROR) {
                cerr << "Ошибка отправки: " << WSAGetLastError() << endl;
                return;
            }

            // Длина адреса
            int addrLen = sizeof(destAddr);

            // Структура fd_set для хранения сокетов
            fd_set fdSet;
            FD_ZERO(&fdSet);      // Очистка
            FD_SET(sock, &fdSet); // Добавление сокета в набор

            // Таймаут получения
            timeval recvTimeout;
            recvTimeout.tv_sec = 3;  // с
            recvTimeout.tv_usec = 0; // мкс

            // Установка таймаута с помощью select
            int selectRes = select(0, &fdSet, NULL, NULL, &recvTimeout);

            int bytesRecved = 0;

            if (selectRes > 0) {
                bytesRecved = recvfrom(sock,       // сокет
                                       recvBuffer, // указатель на буфер для приема данных
                                       bufferSize, // размер буфера
                                       0,          // флаги
                                       reinterpret_cast<SOCKADDR *>(
                                           &fromAddr), // указатель на адрес источника
                                       &fromLen); // указатель на длину структуры адреса источнка
            } else if (selectRes == 0) {
                cerr << "\t*";

            } else {
                cerr << "Ошибка select: " << WSAGetLastError() << endl;
            }

            // Время принятия пакета
            auto end = high_resolution_clock::now();

            // Разница
            duration<double, milli> diff = end - start;

            if (bytesRecved > 0) {
                int outerIpHeaderLen = (recvBuffer[0] & 0x0F) * 4; // Вычисление длины внешнего IPv4 заголовка

                icmpPacket *recvPack = reinterpret_cast<icmpPacket *>(recvBuffer + outerIpHeaderLen);

                // Эхо-ответ
                if (recvPack->header.type == 0 && recvPack->header.code == 0) {

                    // Получение GUID из ответа
                    recvedGuid = recvPack->data;

                    // Сравнение оригинального и полученного GUID
                    if (IsEqualGUID(recvedGuid, origGuid)) {
                        cout << "\t" << diff.count() << " мс";
                        if (j == 2) {
                            // IP-адрес узла
                            char ipStr[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &(fromAddr.sin_addr), ipStr, INET_ADDRSTRLEN);

                            // DNS-имя узла
                            char hostName[NI_MAXHOST];
                            int dnsRes = getnameinfo(reinterpret_cast<SOCKADDR *>(&fromAddr),
                                                     sizeof(fromAddr),
                                                     hostName,
                                                     NI_MAXHOST,
                                                     nullptr,
                                                     0,
                                                     0);
                            if (dnsRes == 0 && strcmp(hostName, ipStr) != 0) {
                                cout << "\t" << hostName << " (" << ipStr << ")";
                            } else {
                                cout << "\t" << ipStr;
                            }
                            cout << endl << "Достигнут целевой узел." << endl;
                            return;
                        }
                    } else {
                        cerr << "Получен чужой пакет";
                        continue;
                    }
                }
                // Обработка ошибок
                else if (recvPack->header.type == 3) {
                    cerr << "Ошибка: Адресат недостижим.\t";
                    if (recvPack->header.code == 0) {
                        cerr << "Сеть недоступна";
                    } else if (recvPack->header.code == 1) {
                        cerr << "Узел недоступен";
                    } else if (recvPack->header.code == 2) {
                        cerr << "Протокол недоступен";
                    } else if (recvPack->header.code == 3) {
                        cerr << "Порт недоступен";
                    } else if (recvPack->header.code == 4) {
                        cerr << "Необходима фрагментация, но не задан бит ее запрета";
                    } else if (recvPack->header.code == 5) {
                        cerr << "Ошибка на исходном маршруте";
                    } else if (recvPack->header.code == 6) {
                        cerr << "Сеть адресата неизвестна";
                    } else if (recvPack->header.code == 7) {
                        cerr << "Узел адресата неизвестен";
                    } else if (recvPack->header.code == 8) {
                        cerr << "Исходный узел изолирован";
                    } else if (recvPack->header.code == 9) {
                        cerr << "Сеть адресата административно изолирована";
                    } else if (recvPack->header.code == 10) {
                        cerr << "Узел адресата административно изолирован";
                    } else if (recvPack->header.code == 11) {
                        cerr << "Сеть недоступна для TOS";
                    } else if (recvPack->header.code == 12) {
                        cerr << "Узел недоступен для TOS";
                    } else if (recvPack->header.code == 13) {
                        cerr << "Связь административно запрещена фильтрацией";
                    } else if (recvPack->header.code == 14) {
                        cerr << "Нарушение приоритета узлов";
                    } else if (recvPack->header.code == 15) {
                        cerr << "Пренебрежение приоритетом узлов";
                    } else {
                        cerr << "Ошибка";
                    }
                } else if (recvPack->header.type == 4 && recvPack->header.code == 0) {
                    cerr << "Ошибка.\tПодавление отправителя.";
                } else if (recvPack->header.type == 5) {
                    cerr << "Ошибка: Перенаправление.\t";
                    if (recvPack->header.code == 0) {
                        cerr << "Перенаправление для сети";
                    } else if (recvPack->header.code == 1) {
                        cerr << "Перенаправление на узел";
                    } else if (recvPack->header.code == 2) {
                        cerr << "Перенаправление на TOS и сеть";
                    } else if (recvPack->header.code == 3) {
                        cerr << "Перенаправление на TOS и узел";
                    } else {
                        cerr << "Ошибка";
                    }
                }
                // Обработка нецелевого узла
                else if (recvPack->header.type == 11) {
                    char *innerIpHeaderPtr = recvBuffer + outerIpHeaderLen + 8;
                    int innerIpLen = (innerIpHeaderPtr[0] & 0x0F) * 4;
                    icmpPacket *origIcmpPack = reinterpret_cast<icmpPacket *>(innerIpHeaderPtr + innerIpLen);
                    recvedGuid = origIcmpPack->data;

                    // Сравнение оригинального и полученного GUID
                    if (IsEqualGUID(recvedGuid, origGuid)) {
                        cout << "\t" << diff.count() << " мс";
                        if (j == 2) {
                            // IP-адрес узла
                            char ipStr[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &(fromAddr.sin_addr), ipStr, INET_ADDRSTRLEN);

                            // DNS-имя узла
                            char hostName[NI_MAXHOST];
                            int dnsRes = getnameinfo(reinterpret_cast<SOCKADDR *>(&fromAddr),
                                                     sizeof(fromAddr),
                                                     hostName,
                                                     NI_MAXHOST,
                                                     nullptr,
                                                     0,
                                                     0);
                            if (dnsRes == 0 && strcmp(hostName, ipStr) != 0) {
                                cout << "\t" << hostName << " (" << ipStr << ")";
                            } else {
                                cout << "\t" << ipStr;
                            }
                        }
                    } else {
                        cerr << "Получен чужой пакет";
                    }
                } else if (recvPack->header.type == 12) {
                    cerr << "Ошибка: Проблема параметра.\t";
                    if (recvPack->header.code == 0) {
                        cerr << "Неверный заголовок IP";
                    } else if (recvPack->header.code == 1) {
                        cerr << "Отсутствует требуемый параметр";
                    } else {
                        cerr << "Ошибка";
                    }
                } else {
                    cerr << "Ошибка";
                }
            }
        }
        cout << endl;
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
