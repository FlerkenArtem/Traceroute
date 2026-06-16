#include <chrono>
#include <combaseapi.h>
#include <iostream>
#include <optional>
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

/// ICMP-пакет
struct icmpPacket
{
    icmpHeader header;
    GUID data;
};

/// Структура с дополнительными данными о пакете
struct packData
{
    GUID recvedGuid;
    time_point<steady_clock> sendTime = {};
    time_point<steady_clock> recvTime = {};

    bool sended = false;
    bool recved = false;
    bool timeout = false;
    bool error = false;
};

/// Структура пакета ICMP с ошибкой
struct icmpErrorPacket
{
    icmpHeader icmpHdr;
    unsigned int restOfIcmp;
    ipHeader origIpHdr;
    GUID origData;
};

#pragma pack(pop)

/// Создание сокета
SOCKET createSocket();

/// Подключение сокета к адресу
optional<sockaddr_in> connectAddr();

/// Получение максимального числа шагов
int maxHops();

/// Определение маршрута
void traceroute(SOCKET sock, sockaddr_in destAddr, int maxHops = 30);

/// Вычисление контрольной суммы
unsigned short calculateChecksum(unsigned short *buffer, int size);

/// Обработка ошибок ICMP
void errors(unsigned char charType, unsigned char charCode);

/// Точка входа в программу
int main()
{
    system("chcp 65001 > nul");
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
    if (sock == INVALID_SOCKET) {
        cerr << "Ошибка создания сокета" << sock << endl;
        return 1;
    }

    optional<sockaddr_in> destAddr = connectAddr();
    if (destAddr == nullopt) {
        cerr << "Ошибка подключения к адресу" << endl;
        return 1;
    }

    int hops = maxHops();

    traceroute(sock, *destAddr, hops);

    return 0;
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

    return sock;
}

optional<sockaddr_in> connectAddr()
{
    string hostname;
    sockaddr_in destAddr;

    cout << "Введите адрес: ";
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
    while (true) {
        int hops = 0;
        cout << "Введите максимальное число шагов: ";
        if (cin >> hops && hops > 0) {
            return hops;
        } else {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Введено некррекное число шагов. Введите число больше 0.";
        }
    }
}

void traceroute(SOCKET sock, sockaddr_in destAddr, int maxHops)
{
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
                                    }

                                    // Получен адрес
                                    addrGetted = true;
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
                                if (bytesRecved < ipHeaderLen + (int) sizeof(icmpErrorPacket)) {
                                    cout << "*\t";
                                    continue;
                                }

                                // Формирование ICMP-сообщения об ошибке
                                icmpErrorPacket errorPack = *(
                                    icmpErrorPacket *) (recvBuffer.data() + ipHeaderLen + 4);
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
