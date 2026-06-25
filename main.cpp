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

/// ICMP-пакет
struct icmpPacket
{
    icmpHeader header;
    GUID data;
};

/// Структура пакета ICMP с ошибкой (UDP)
struct icmpErrorPacket
{
    icmpHeader icmpHdr;
    unsigned int unused;
    ipHeader origIpHdr;
    udpHeader origUdpHdr;
    GUID data;
};

/// Структура пакета ICMP с ошибкой (ICMP)
struct tracertIcmpErrorPacket
{
    icmpHeader icmpHdr;
    unsigned int restOfIcmp;
    ipHeader origIpHdr;
    GUID origData;
};

#pragma pack(pop)

/// Определение маршрута
void traceroute(string addr, int maxHops = 30);

/// Определение маршрута (ICMP)
void tracert(string addr, int maxHops = 30);

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
    } else if (argc == 3 && string(argv[2]) == "-I") {
        string addr = argv[1];
        tracert(addr);
    } else if (argc == 4 && string(argv[2]) == "-h") {
        string addr = argv[1];
        int hops = stoi(string(argv[3]));
        traceroute(addr, hops);
    } else if (argc == 5 && string(argv[2]) == "-I" && string(argv[3]) == "-h") {
        string addr = argv[1];
        int hops = stoi(string(argv[4]));
        tracert(addr, hops);
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

    // ICMP-сокет для получения
    SOCKET recvSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (recvSock == INVALID_SOCKET) {
        cerr << "Ошибка создания сокета на прием: " << WSAGetLastError() << endl;
        return;
    }

    // Перевод сокета в неблокирующий режим
    unsigned long mode = 1;
    int unblock = ioctlsocket(recvSock, FIONBIO, &mode);

    if (unblock == SOCKET_ERROR) {
        cerr << "Ошибка перевода сокета в неблокирующий режим: " << WSAGetLastError() << endl;
        return;
    }

    // UDP-сокет для отправки
    SOCKET sendSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sendSock == INVALID_SOCKET) {
        cerr << "Ошибка создания сокета на отправку: " << WSAGetLastError() << endl;
        return;
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

void tracert(string addr, int maxHops)
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
         << "по протоколу ICMP" << endl
         << "с максимальным числом прыжков " << maxHops << ":" << endl;

    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock == INVALID_SOCKET) {
        int lastErr = WSAGetLastError();
        cerr << "Ошибка создания сокета: " << lastErr << endl;
        WSACleanup();
        return;
    }

    // Переключение в неблокирующий режим
    unsigned long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    // Установка размера буфера
    const int bufferSize = 1024;

    // Создание буфера
    vector<char> recvBuffer(bufferSize);

    // Адрес отправителя
    sockaddr_in fromAddr{};

    // Размер адреса отправителя
    socklen_t fromAddrSize = sizeof(fromAddr);

    // Достижение цели
    bool destination = false;

    for (int ttl = 1; ttl <= maxHops; ttl++) {
        // Вывод номера шага
        cout << ttl << "\t";

        GUID origGuid;
        CoCreateGuid(&origGuid);

        // Формирование пакета на отправку
        icmpPacket sendPack{};
        sendPack.header.type = 8;
        sendPack.header.code = 0;
        sendPack.header.checkSum = 0;
        sendPack.data = origGuid;
        sendPack.header.checkSum = calculateChecksum((unsigned short *) &sendPack, sizeof(sendPack));

        // Настройка TTL
        setsockopt(sock, IPPROTO_IP, IP_TTL, (const char *) &ttl, sizeof(ttl));

        bool addrGetted = false;
        string addrInfo;
        for (int trying = 0; trying < 3; trying++) {
            // Время начала отправки
            auto start = high_resolution_clock::now();

            // Отправка
            int sendRes = sendto(sock,
                                 (const char *) &sendPack,
                                 sizeof(sendPack),
                                 0,
                                 (sockaddr *) &destAddr,
                                 socklen_t(sizeof(destAddr)));

            // Обрпаботка ошибок отправки
            if (sendRes == SOCKET_ERROR) {
                cerr << "Ошибка отправки: " << WSAGetLastError() << endl;
                continue;
            }

            // Структура fd_set для хранения сокетов
            fd_set fdSet;
            FD_ZERO(&fdSet);      // Очистка
            FD_SET(sock, &fdSet); // Добавление сокета в набор

            // Таймаут получения
            timeval recvTimeout{};
            recvTimeout.tv_sec = 1;  // с
            recvTimeout.tv_usec = 0; // мкс

            // Установка таймаута с помощью select
            int selectRes = select(0, &fdSet, NULL, NULL, &recvTimeout);

            // Полученные байты
            int bytesRecved;

            if (!FD_ISSET(sock, &fdSet)) {
                cout << "*\t";
                continue;
            }

            if (selectRes > 0) {
                int recvError = 0;

                do {
                    // Получение данных
                    bytesRecved = recvfrom(sock,
                                           recvBuffer.data(),
                                           bufferSize,
                                           0,
                                           (sockaddr *) &fromAddr,
                                           &fromAddrSize);

                    // Время окончания
                    auto end = high_resolution_clock::now();

                    // Разница
                    auto diff = duration<double, milli>(end - start);

                    if (bytesRecved != SOCKET_ERROR) {
                        if (bytesRecved <= 0) {
                            cout << "*\t";
                            continue;
                        }

                        // Получение IP-заголовка из буфера
                        ipHeader *ipHdr = (ipHeader *) recvBuffer.data();

                        // Вычисление длины IPv4 заголовка
                        int ipHeaderLen = ipHdr->len * 4;

                        // Проверка по длине,
                        // что полученный пакет содержит IP-заголовок
                        // и ICMP-пакет
                        if (bytesRecved < ipHeaderLen + (int) sizeof(icmpPacket)) {
                            cout << "*\t";
                            continue;
                        }

                        // Полученный ICMP-пакет
                        icmpPacket *recvPack = (icmpPacket *) (recvBuffer.data() + ipHeaderLen);

                        // Получение IP-адреса в текстовом формате
                        char ipStr[INET_ADDRSTRLEN] = {0};

                        inet_ntop(AF_INET, &(fromAddr.sin_addr), ipStr, INET_ADDRSTRLEN);

                        // Проверка целостности пакета
                        if (bytesRecved <= ipHeaderLen || ipHeaderLen < 20) {
                            cout << "*\t";
                            continue;
                        }

                        if (recvPack->header.type == 0 && recvPack->header.code == 0) {
                            if (fromAddr.sin_family == AF_INET) {
                                GUID recvedGuid = recvPack->data;

                                // Проверка соответствия оригинального и полученного GUID
                                if (origGuid == recvedGuid) {
                                    // Получение DNS-имени хоста
                                    char hostName[NI_MAXHOST];
                                    int dnsRes = getnameinfo((SOCKADDR *) &fromAddr,
                                                             sizeof(fromAddr),
                                                             hostName,
                                                             NI_MAXHOST,
                                                             nullptr,
                                                             0,
                                                             0);

                                    // Вывод времени
                                    if (diff.count() >= 1)
                                        cout << (int) diff.count() << "\t";
                                    else
                                        cout << "<1\t";

                                    // Запись имени узла или его IP-адреса в строку
                                    if (!addrGetted) {
                                        if (dnsRes == 0 && strcmp(hostName, ipStr) != 0) {
                                            addrInfo += "\t";
                                            addrInfo += hostName;
                                            addrInfo += "\t(";
                                            addrInfo += ipStr;
                                            addrInfo += ")";
                                        } else {
                                            addrInfo += "\t";
                                            addrInfo += ipStr;
                                        }

                                        // Получен адрес
                                        addrGetted = true;
                                    }
                                } else {
                                    cout << "*\t";
                                }

                                destination = true;
                            }
                        } else { // Обработка пакетов с ошибками
                            // Ошибка TTL
                            if (recvPack->header.type == 11) {
                                // Проверка по длине,
                                // что полученный пакет содержит IP-заголовок
                                // и ICMP-пакет с сообщением об ошибке
                                if (bytesRecved
                                    < ipHeaderLen + (int) sizeof(tracertIcmpErrorPacket)) {
                                    cout << "*\t";
                                    continue;
                                }

                                // Формирование ICMP-сообщения об ошибке
                                tracertIcmpErrorPacket errorPack = *(
                                    tracertIcmpErrorPacket *) (recvBuffer.data() + ipHeaderLen + 4);
                                // 4 байта - отступ, заложенный для id и sequence

                                // Получение GUID из сообщения
                                GUID recvData = errorPack.origData;

                                if (origGuid == recvData) {
                                    // Получение DNS-имени хоста
                                    char hostName[NI_MAXHOST];
                                    int dnsRes = getnameinfo((SOCKADDR *) &fromAddr,
                                                             sizeof(fromAddr),
                                                             hostName,
                                                             NI_MAXHOST,
                                                             nullptr,
                                                             0,
                                                             0);

                                    // Вывод времени
                                    if (diff.count() >= 1)
                                        cout << (int) diff.count() << "\t";
                                    else
                                        cout << "<1\t";

                                    // Запись имени узла или его IP-адреса в строку
                                    if (!addrGetted) {
                                        if (dnsRes == 0 && strcmp(hostName, ipStr) != 0) {
                                            addrInfo += "\t";
                                            addrInfo += hostName;
                                            addrInfo += "\t(";
                                            addrInfo += ipStr;
                                            addrInfo += ")";
                                        } else {
                                            addrInfo += "\t";
                                            addrInfo += ipStr;
                                        }
                                    }

                                    // Получен адрес
                                    addrGetted = true;
                                } else {
                                    cout << "*\t";
                                }
                                continue;
                            } else { // Обработка ошибок
                                errors(recvPack->header.type, recvPack->header.code);
                            }
                        }
                    } else {
                        recvError = WSAGetLastError();
                        if (recvError != WSAEWOULDBLOCK) {
                            cerr << "Возникла ошибка при получении: " << recvError << endl;
                            return;
                        }
                    }
                } while (recvError != WSAEWOULDBLOCK);

                // Обработка истечения таймаута
            } else if (selectRes == 0) {
                cout << "*\t";
            } else {
                return;
            }

            // Вывод адреса после последней попытки
            if (addrGetted && trying == 2) {
                cout << addrInfo;
            }
        }
        cout << endl;

        // Вывод информации о достижении целевого узла
        if (destination) {
            cout << "\tДостигнут целевой узел" << endl;
            cout << endl;
            break;
        }
        // Вывод информации о том, что целевой узел
        // не был достигнут за отведенное число шагов
        else if (ttl == maxHops) {
            cout << "Целевой узел не был достигнут за " << maxHops << " шагов." << endl;
            cout << endl;
            break;
        }
    }

    closesocket(sock);
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
