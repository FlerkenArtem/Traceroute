#include <chrono>
#include <combaseapi.h>
#include <iostream>
#include <optional>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>

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

/// Подключение сокета к адресу
optional<sockaddr_in> connectAddr();

/// Получение максимального числа шагов
int maxHops();

/// Определение маршрута
void traceroute(SOCKET sock, sockaddr_in destAddr, int maxHops = 30);

/// Вычисление контрольной суммы
unsigned short calculateChecksum(unsigned short *buffer, int size);

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
        sendPack.header.checkSum = calculateChecksum(reinterpret_cast<unsigned short *>(&sendPack),
                                                     sizeof(sendPack));

        // Настройка TTL
        setsockopt(sock, IPPROTO_IP, IP_TTL, reinterpret_cast<const char *>(&ttl), sizeof(ttl));

        bool addrGetted = false;
        string addrInfo;
        for (int trying = 0; trying < 3; trying++) {
            // Время начала отправки
            auto start = high_resolution_clock::now();

            // Отправка
            int sendRes = sendto(sock,
                                 reinterpret_cast<const char *>(&sendPack),
                                 sizeof(sendPack),
                                 0,
                                 reinterpret_cast<sockaddr *>(&destAddr),
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
            recvTimeout.tv_sec = 3;  // с
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
                // Получение данных
                bytesRecved = recvfrom(sock,
                                       recvBuffer.data(),
                                       bufferSize,
                                       0,
                                       reinterpret_cast<sockaddr *>(&fromAddr),
                                       &fromAddrSize);

                if (bytesRecved != SOCKET_ERROR) {
                    int ipHeaderLen = (recvBuffer[0] & 0x0F) * 4; // Вычисление длины IPv4 заголовка

                    // Полученный ICMP-пакет
                    icmpPacket *recvPack = reinterpret_cast<icmpPacket *>(recvBuffer.data()
                                                                          + ipHeaderLen);

                    // Время окончания
                    auto end = high_resolution_clock::now();

                    // Разница
                    auto diff = duration<double, milli>(end - start);

                    // Получение IP-адреса в текстовом формате
                    char ipStr[INET_ADDRSTRLEN] = {0};

                    // Проверка целостности пакета
                    if (bytesRecved <= ipHeaderLen || ipHeaderLen < 20) {
                        cout << "*\t";
                        continue;
                    }

                    if (recvPack->header.type == 0 && recvPack->header.code == 0) {
                        if (fromAddr.sin_family == AF_INET) {
                            GUID recvedGuid = recvPack->data;

                            inet_ntop(AF_INET, &(fromAddr.sin_addr), ipStr, INET_ADDRSTRLEN);

                            // Проверка соответствия оригинального и полученного GUID
                            if (memcmp(&origGuid, &recvedGuid, sizeof(GUID)) == 0) {
                                // Получение DNS-имени хоста
                                char hostName[NI_MAXHOST];
                                int dnsRes = getnameinfo(reinterpret_cast<SOCKADDR *>(&fromAddr),
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
                    } else if (recvPack->header.type == 11) {
                        if (fromAddr.sin_family == AF_INET) {
                            inet_ntop(AF_INET, &(fromAddr.sin_addr), ipStr, INET_ADDRSTRLEN);

                            // Вычисляем смещение до вложенного IP-заголовка
                            int outerIcmpLen = bytesRecved - ipHeaderLen;
                            // Вложенный IP-залоговок
                            unsigned char *innerIpHeader = reinterpret_cast<unsigned char *>(
                                                               recvPack)
                                                           + 8;

                            // Длина вложенного IP-заголовка
                            int innerIpHeaderLen = (innerIpHeader[0] & 0x0F) * 4;

                            if ((unsigned long long) outerIcmpLen
                                >= sizeof(icmpHeader) + innerIpHeaderLen + sizeof(icmpHeader)
                                       + sizeof(GUID)) {
                                // Проверяем, что буфер физически содержит весь GUID
                                int totalGuidOffset = 8 + innerIpHeaderLen + 4 + sizeof(GUID);
                                if (outerIcmpLen >= totalGuidOffset) {
                                    unsigned char *recvedGuid = innerIpHeader + innerIpHeaderLen
                                                                + 4;

                                    if (memcmp(&origGuid, recvedGuid, sizeof(GUID)) == 0) {
                                        // Получение DNS-имени хоста
                                        char hostName[NI_MAXHOST];
                                        int dnsRes = getnameinfo(reinterpret_cast<SOCKADDR *>(
                                                                     &fromAddr),
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
                                        cout << "*\t"; // GUID не совпал
                                    }
                                } else {
                                    // Маршрутизатор обрезал пакет и прислал меньше 16 байт GUID
                                    cout << "*\t";
                                }
                            } else {
                                // Слишком короткий ICMP-пакет ответа
                                cout << "*\t";
                            }
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
