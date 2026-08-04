#include <winsock2.h>
#include <chrono>
#include <combaseapi.h>
#include <iostream>
#include <map>
#include <string>
#include <vector>
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

/// Дополнительная информация об отправке
struct sendInfo
{
    /* 
     * Время отправки. 
     * Часам присвоено время начала эпохи по-умолчанию.
     */
    steady_clock::time_point sendTime = {};

    /* 
     * Время получения. 
     * Часам присвоено время начала эпохи по-умолчанию.
     */
    steady_clock::time_point recvTime = {};

    // Время жизни пакета.
    int ttl;

    // Попытка на которой был отправлен пакет.
    int attempt;

    // IP-адрес узла.
    string ipStr = "";

    // DNS-имя узла.
    string hostName = "";
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

/// Получение локального IP-адреса
unsigned long getLocalIP(string addr);

/// Оператор сравнения 2 GUID
bool operator<(const GUID &guid1, const GUID &guid2);

/// Точка входа в программу
int main(int argc, char *argv[])
{
    system("chcp 65001 > nul");
    setlocale(LC_ALL, ".UTF8");

    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;

    int err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        WSACleanup();
        return 1;
    }

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        WSACleanup();
        return 1;
    }

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
                "имя_узла_или_IP [-I] [-h количество_шагов]";
        WSACleanup();
        return 1;
    }

    cout << endl;
    WSACleanup();
    return 0;
}

void traceroute(string addr, int maxHops)
{
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
         << "с максимальным числом прыжков " << maxHops << ":";

    // ICMP-сокет для получения
    SOCKET recvSock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

    if (recvSock == INVALID_SOCKET) {
        int err = WSAGetLastError();
        if (err == WSAEACCES)
            cerr << endl
                 << "Для создания сырых сокетов необходимы права администратора. " << endl
                 << "Перезапустите программу от имени администратора.";
        else
            cerr << "Ошибка создания сокета на прием: " << err << endl;
        closesocket(recvSock);
        return;
    }

    sockaddr_in localAddr;
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(0);
    localAddr.sin_addr.s_addr = getLocalIP(addr);

    if (bind(recvSock, (sockaddr *) &localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        cerr << "Ошибка привязки принимающего сокета к локальному концу: " << err << endl;
        closesocket(recvSock);
        return;
    }

    DWORD dwValue = RCVALL_ON;
    DWORD dwBytesReturned = 0;

    if (WSAIoctl(recvSock,
                 SIO_RCVALL,
                 &dwValue,
                 sizeof(dwValue),
                 nullptr,
                 0,
                 &dwBytesReturned,
                 nullptr,
                 nullptr)
        == SOCKET_ERROR) {
        int err = WSAGetLastError();
        cerr << "Ошибка при переводе сокета в неразборчивый режим: " << err << endl;
        closesocket(recvSock);
        return;
    }

    // Перевод сокета в неблокирующий режим
    unsigned long mode = 1;
    int unblock = ioctlsocket(recvSock, FIONBIO, &mode);

    if (unblock == SOCKET_ERROR) {
        cerr << "Ошибка перевода сокета в неблокирующий режим: " << WSAGetLastError() << endl;
        closesocket(recvSock);
        return;
    }

    // UDP-сокет для отправки
    SOCKET sendSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sendSock == INVALID_SOCKET) {
        cerr << "Ошибка создания сокета на отправку: " << WSAGetLastError() << endl;
        closesocket(sendSock);
        closesocket(recvSock);
        return;
    }

    // Размер буфера для приема данных в байтах
    const int bufferSize = 65535;

    // Буфер приема данных
    vector<char> recvBuffer;

    // Время жизни пакета
    int ttl = 0;

    // Порт удаленного конца
    int sendPort = 0;

    // Счетчик попыток на ttl
    int attempt = 0;

    // Флаг получения последнего пакета
    bool lastPackGetted = false;

    // Флаг достижения цели
    bool destGetted = false;

    // Время отправки последнего пакета
    steady_clock::time_point lastSendTime;

    // Словарь по GUID и дополнительной информации об отправке
    map<GUID, sendInfo> sended;

    // Словарь по соответствию GUID и портов, с которых они были отправлены
    map<int, GUID> portsGuids;

    // Последний отправленный GUID
    GUID lastSendGuid{};

    for (int i = 0; i < maxHops * 3;) {
        /*
         * Отправка пакетов присходит раз в секунду. 
         * Если пакет на итерации не отправляется,
         * счетчик итераций не увеличивается.
         * При этом прием пакетов продолжается.
         */

        if (i == 0 || steady_clock::now() - lastSendTime > 1s) {
            if (ttl != 0) {
                // Обработка неполучения пакета
                if (!lastPackGetted)
                    cout << "*\t";
                // Вывод информации о прошлой итерации.
                else {
                    if (
                        // не получен
                        sended[lastSendGuid].recvTime < sended[lastSendGuid].sendTime

                        // получен позже чем через секунду после отправки
                        || sended[lastSendGuid].recvTime - sended[lastSendGuid].sendTime > 1s) {
                        cout << "*\t";
                    } else {
                        duration<double, milli> diff = sended[lastSendGuid].recvTime
                                                       - sended[lastSendGuid].sendTime;
                        if (diff.count() < 1)
                            cout << "<1\t";
                        else
                            cout << (int) diff.count() << "\t";
                    }
                }
                if (attempt == 2) {
                    auto addrIt = sended.end();
                    int maxAttempt = -1;
                    for (auto it = sended.begin(); it != sended.end(); it++) {
                        const sendInfo info = it->second;
                        if (info.ttl == ttl && info.ipStr != "" && !info.ipStr.empty()) {
                            if (info.attempt > maxAttempt) {
                                maxAttempt = info.attempt;
                                addrIt = it;
                            }
                        }
                    }

                    if (addrIt != sended.end()) {
                        GUID addrGuid = addrIt->first;
                        if (sended[addrGuid].ipStr != sended[addrGuid].hostName)
                            cout << sended[addrGuid].hostName + " (" + sended[addrGuid].ipStr + ")";
                        else
                            cout << sended[addrGuid].ipStr;
                    }
                }
            }

            // Увеличение счетчика итераций
            i++;

            // Расчет номера текущей попытки на текущем ttl
            attempt = (i - 1) % 3;

            // Сброс флага
            lastPackGetted = false;

            /*
             * Увеличение ttl и порта
             * происходит только на каждой
             * 3 итерации цикла.
             * 3 попытки на 1 ttl и порт.
             */

            if (attempt == 0) {
                // Обработка достижения цели
                if (destGetted) {
                    cout << endl << "\tДостигнут целевой узел." << endl;
                    closesocket(sendSock);
                    closesocket(recvSock);
                    return;
                }

                ttl++;
                cout << endl << ttl << "\t";
            }

            // Исходный GUID
            GUID origGuid{};

            // Обработка ошибки при создании GUID
            if (CoCreateGuid(&origGuid) != S_OK)
                continue;

            // Порт на текущей итерации
            sendPort = 33434 + i;

            // Установка порта
            destAddr.sin_port = htons(sendPort);

            // Установка TLL
            if (setsockopt(sendSock, IPPROTO_IP, IP_TTL, (char *) &ttl, sizeof(ttl))
                == SOCKET_ERROR) {
                int err = WSAGetLastError();
                cerr << "Ошибка установки TTL на отправляющий сокет: " << err << endl;
                closesocket(sendSock);
                closesocket(recvSock);
                return;
            }

            // Байт отправлено
            int bytesSended = sendto(sendSock,
                                     (char *) &origGuid,
                                     sizeof(origGuid),
                                     0,
                                     (sockaddr *) &destAddr,
                                     sizeof(destAddr));

            // Обработка ошибки отправки
            if (bytesSended == SOCKET_ERROR)
                continue;

            // Заполнение параметров текущей отправки
            lastSendGuid = origGuid;
            portsGuids[sendPort] = origGuid;
            sended[origGuid].ttl = ttl;
            sended[origGuid].attempt = attempt;
            lastSendTime = steady_clock::now();
            sended[origGuid].sendTime = lastSendTime;
        }

        // Получение пакетов

        fd_set fdSet{};
        FD_ZERO(&fdSet);
        FD_SET(recvSock, &fdSet);

        timeval timeout{};
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int selectRes = select(0, &fdSet, nullptr, nullptr, &timeout);

        if (selectRes <= 0) {
            continue;
        }

        if (FD_ISSET(recvSock, &fdSet)) {
            sockaddr_in fromAddr{};
            int error = 0;
            do {
                int fromSize = sizeof(fromAddr);
                recvBuffer.resize(bufferSize);
                int bytesRecved = recvfrom(recvSock,
                                           recvBuffer.data(),
                                           bufferSize,
                                           0,
                                           (sockaddr *) &fromAddr,
                                           &fromSize);

                if (bytesRecved == SOCKET_ERROR) {
                    error = WSAGetLastError();
                    if (error != WSAEWOULDBLOCK) {
                        cerr << "Ошибка приема: " << error;
                        closesocket(sendSock);
                        closesocket(recvSock);
                        return;
                    }
                } else {
                    ipHeader *ipHdr = (ipHeader *) recvBuffer.data();

                    if (ipHdr->proto != IPPROTO_ICMP) {
                        continue;
                    }

                    int ipLen = ipHdr->len * 4;

                    icmpErrorPacket *errPack = (icmpErrorPacket *) (recvBuffer.data() + ipLen);

                    if ((errPack->icmpHdr.type == 11 && errPack->icmpHdr.code == 0)
                        || (errPack->icmpHdr.type == 3 && errPack->icmpHdr.code == 3)) {
                        GUID recvedGuid = errPack->data;

                        if (errPack->icmpHdr.type == 11 && errPack->icmpHdr.code == 0) {
                            // Проверка совпадения GUID
                            auto it = sended.find(recvedGuid);

                            if (it != sended.end()) {
                                it->second.recvTime = steady_clock::now();

                                // Получение IP-адреса
                                char ipStr[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, &fromAddr.sin_addr, ipStr, sizeof(ipStr));
                                it->second.ipStr = ipStr;

                                // Получение DNS-имени
                                char hostName[NI_MAXHOST];
                                int dnsRes = getnameinfo((sockaddr *) &fromAddr,
                                                         sizeof(fromAddr),
                                                         hostName,
                                                         NI_MAXHOST,
                                                         nullptr,
                                                         0,
                                                         0);

                                if (dnsRes == 0 && strcmp(hostName, ipStr) != 0)
                                    it->second.hostName = hostName;
                                else
                                    it->second.hostName = ipStr;
                            }
                            lastPackGetted = true;
                        }

                        // При получении пакета с ошибкой 3:3, GUID не приходит
                        if (errPack->icmpHdr.type == 3 && errPack->icmpHdr.code == 3) {
                            // Проверка совпадения IP-адреса
                            if (errPack->origIpHdr.destIp != destAddr.sin_addr.s_addr) {
                                continue;
                            }

                            // Полученный порт
                            int recvedPort = ntohs(errPack->origUdpHdr.destPort);
                            bool portFound = false;
                            GUID recvedGUID{};

                            // Поиск полученного порта
                            auto it = portsGuids.find(recvedPort);
                            if (it != portsGuids.end()) {
                                recvedGUID = it->second;
                                portFound = true;
                            }

                            if (!portFound)
                                continue;

                            sended[recvedGUID].recvTime = steady_clock::now();

                            // Получение IP-адреса
                            char ipStr[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &fromAddr.sin_addr, ipStr, sizeof(ipStr));
                            sended[recvedGUID].ipStr = ipStr;

                            // Получение DNS-имени
                            char hostName[NI_MAXHOST];
                            int dnsRes = getnameinfo((sockaddr *) &fromAddr,
                                                     sizeof(fromAddr),
                                                     hostName,
                                                     NI_MAXHOST,
                                                     nullptr,
                                                     0,
                                                     0);
                            if (dnsRes == 0 && strcmp(hostName, ipStr) != 0)
                                sended[recvedGUID].hostName = hostName;
                            else
                                sended[recvedGUID].hostName = ipStr;

                            lastPackGetted = true;
                            destGetted = true;
                        }
                    }
                }
            } while (error != WSAEWOULDBLOCK);
        }
    }

    closesocket(sendSock);
    closesocket(recvSock);
}

void tracert(string addr, int maxHops)
{
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
        closesocket(sock);
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

    // Время жизни пакета
    int ttl = 0;

    // Счетчик попыток на ttl
    int attempt = 0;

    // Флаг получения последнего пакета
    bool lastPackGetted = false;

    // Время отправки последнего пакета
    steady_clock::time_point lastSendTime;

    // Словарь по GUID и дополнительной информации об отправке
    map<GUID, sendInfo> sended;

    // Последний отправленный GUID
    GUID lastSendGuid{};

    for (int i = 0; i < maxHops * 3;) {
        /*
         * Отправка пакетов присходит раз в секунду. 
         * Если пакет на итерации не отправляется,
         * счетчик итераций не увеличивается.
         * При этом прием пакетов продолжается.
         */

        if (i == 0 || steady_clock::now() - lastSendTime > 1s) {
            if (ttl != 0) {
                // Обработка неполучения пакета
                if (!lastPackGetted)
                    cout << "*\t";
                // Вывод информации о прошлой итерации.
                else {
                    if (
                        // не получен
                        sended[lastSendGuid].recvTime < sended[lastSendGuid].sendTime

                        // получен позже чем через секунду после отправки
                        || sended[lastSendGuid].recvTime - sended[lastSendGuid].sendTime > 1s) {
                        cout << "*\t";
                    } else {
                        duration<double, milli> diff = sended[lastSendGuid].recvTime
                                                       - sended[lastSendGuid].sendTime;
                        if (diff.count() < 1)
                            cout << "<1\t";
                        else
                            cout << (int) diff.count() << "\t";
                    }
                }

                if (attempt == 2) {
                    auto addrIt = sended.end();
                    int maxAttempt = -1;
                    for (auto it = sended.begin(); it != sended.end(); it++) {
                        const sendInfo info = it->second;
                        if (info.ttl == ttl && info.ipStr != "") {
                            if (info.attempt > maxAttempt) {
                                maxAttempt = info.attempt;
                                addrIt = it;
                            }
                        }
                    }

                    if (addrIt != sended.end()) {
                        GUID addrGuid = addrIt->first;
                        if (sended[addrGuid].ipStr != sended[addrGuid].hostName)
                            cout << sended[addrGuid].hostName + " (" + sended[addrGuid].ipStr + ")";
                        else
                            cout << sended[addrGuid].ipStr;
                    }
                }
            }

            // Увеличение счетчика итераций
            i++;

            // Расчет номера текущей попытки на текущем ttl
            attempt = (i - 1) % 3;

            // Сброс флага
            lastPackGetted = false;

            /*
             * Увеличение ttl и порта
             * происходит только на каждой
             * 3 итерации цикла.
             * 3 попытки на 1 ttl и порт.
             */

            if (attempt == 0) {
                // Обработка достижения цели
                if (destination) {
                    cout << endl << "\tДостигнут целевой узел." << endl;
                    closesocket(sock);
                    return;
                }

                ttl++;
                cout << endl << ttl << "\t";

                // Настройка TTL
                setsockopt(sock, IPPROTO_IP, IP_TTL, (const char *) &ttl, sizeof(ttl));
            }

            // Исходный GUID
            GUID origGuid{};

            // Обработка ошибки при создании GUID
            if (CoCreateGuid(&origGuid) != S_OK)
                continue;

            // Формирование пакета на отправку
            icmpPacket sendPack{};
            sendPack.header.type = 8;
            sendPack.header.code = 0;
            sendPack.header.checkSum = 0;
            sendPack.data = origGuid;
            sendPack.header.checkSum = calculateChecksum((unsigned short *) &sendPack,
                                                         sizeof(sendPack));

            // Байт отправлено
            int bytesSended = sendto(sock,
                                     (const char *) &sendPack,
                                     sizeof(sendPack),
                                     0,
                                     (sockaddr *) &destAddr,
                                     socklen_t(sizeof(destAddr)));

            // Обработка ошибки отправки
            if (bytesSended == SOCKET_ERROR)
                continue;

            // Заполнение параметров текущей отправки
            lastSendGuid = origGuid;
            sended[origGuid].ttl = ttl;
            sended[origGuid].attempt = attempt;
            lastSendTime = steady_clock::now();
            sended[origGuid].sendTime = lastSendTime;
        }

        // Получение пакетов

        fd_set fdSet{};
        FD_ZERO(&fdSet);
        FD_SET(sock, &fdSet);

        timeval timeout{};
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int selectRes = select(0, &fdSet, nullptr, nullptr, &timeout);

        if (selectRes <= 0) {
            continue;
        }

        if (FD_ISSET(sock, &fdSet)) {
            int recvError = 0;

            do {
                // Байт получено
                int bytesRecved = recvfrom(sock,
                                           recvBuffer.data(),
                                           bufferSize,
                                           0,
                                           (sockaddr *) &fromAddr,
                                           &fromAddrSize);

                if (bytesRecved != SOCKET_ERROR) {
                    if (bytesRecved <= 0) {
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
                        continue;
                    }

                    // Полученный ICMP-пакет
                    icmpPacket *recvPack = (icmpPacket *) (recvBuffer.data() + ipHeaderLen);

                    // Получение IP-адреса в текстовом формате
                    char ipStr[INET_ADDRSTRLEN] = {0};

                    inet_ntop(AF_INET, &(fromAddr.sin_addr), ipStr, INET_ADDRSTRLEN);

                    // Проверка целостности пакета
                    if (bytesRecved <= ipHeaderLen || ipHeaderLen < 20) {
                        continue;
                    }

                    if (recvPack->header.type == 0 && recvPack->header.code == 0) {
                        if (fromAddr.sin_family == AF_INET) {
                            GUID recvedGuid = recvPack->data;

                            // Проверка совпадения GUID
                            auto it = sended.find(recvedGuid);

                            if (it != sended.end()) {
                                it->second.recvTime = steady_clock::now();

                                // Получение IP-адреса
                                char ipStr[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, &fromAddr.sin_addr, ipStr, sizeof(ipStr));
                                it->second.ipStr = ipStr;

                                // Получение DNS-имени
                                char hostName[NI_MAXHOST];
                                int dnsRes = getnameinfo((sockaddr *) &fromAddr,
                                                         sizeof(fromAddr),
                                                         hostName,
                                                         NI_MAXHOST,
                                                         nullptr,
                                                         0,
                                                         0);

                                if (dnsRes == 0 && strcmp(hostName, ipStr) != 0)
                                    it->second.hostName = hostName;
                                else
                                    it->second.hostName = ipStr;
                            }

                            lastPackGetted = true;

                            destination = true;
                        }
                    } else { // Обработка пакетов с ошибками
                        // Ошибка TTL
                        if (recvPack->header.type == 11) {
                            // Проверка по длине,
                            // что полученный пакет содержит IP-заголовок
                            // и ICMP-пакет с сообщением об ошибке
                            if (bytesRecved < ipHeaderLen + (int) sizeof(tracertIcmpErrorPacket)) {
                                continue;
                            }

                            // Формирование ICMP-сообщения об ошибке
                            tracertIcmpErrorPacket errorPack = *(
                                tracertIcmpErrorPacket *) (recvBuffer.data() + ipHeaderLen + 4);
                            // 4 байта - отступ, заложенный для id и sequence

                            // Получение GUID из сообщения
                            GUID recvedGuid = errorPack.origData;

                            // Проверка совпадения GUID
                            auto it = sended.find(recvedGuid);

                            if (it != sended.end()) {
                                it->second.recvTime = steady_clock::now();

                                // Получение IP-адреса
                                char ipStr[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, &fromAddr.sin_addr, ipStr, sizeof(ipStr));
                                it->second.ipStr = ipStr;

                                // Получение DNS-имени
                                char hostName[NI_MAXHOST];
                                int dnsRes = getnameinfo((sockaddr *) &fromAddr,
                                                         sizeof(fromAddr),
                                                         hostName,
                                                         NI_MAXHOST,
                                                         nullptr,
                                                         0,
                                                         0);

                                if (dnsRes == 0 && strcmp(hostName, ipStr) != 0)
                                    it->second.hostName = hostName;
                                else
                                    it->second.hostName = ipStr;
                            }
                            lastPackGetted = true;
                        } else { // Обработка ошибок
                            errors(recvPack->header.type, recvPack->header.code);
                        }
                    }
                } else {
                    recvError = WSAGetLastError();
                    if (recvError != WSAEWOULDBLOCK) {
                        cerr << "Возникла ошибка при получении: " << recvError << endl;
                        closesocket(sock);
                        return;
                    }
                }
            } while (recvError != WSAEWOULDBLOCK);
        }
    }
    closesocket(sock);
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

unsigned long getLocalIP(string addr)
{
    SOCKET udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // Создание сокета UDP
    if (udpSock == INVALID_SOCKET)
        return INADDR_ANY;

    sockaddr_in loopback;
    loopback.sin_family = AF_INET;
    int addrRes = inet_pton(AF_INET, addr.c_str(), &(loopback.sin_addr));

    if (addrRes == 0) {
        cerr << "Ошибка подключения к адресу: Неверный формат IP-адреса." << endl;
        return INADDR_ANY;
    } else if (addrRes < 0) {
        cerr << "Ошибка подключения к адресу: Неподдерживаемое семейство протоколов" << endl;
        return INADDR_ANY;
    }

    // Подключение к адресу
    if (connect(udpSock, (sockaddr *) &loopback, sizeof(loopback)) == SOCKET_ERROR) {
        closesocket(udpSock);
        return INADDR_ANY;
    }

    // Извлечение IP-адреса
    sockaddr_in localAddr;
    int len = sizeof(localAddr);
    if (getsockname(udpSock, (sockaddr *) &localAddr, &len) == SOCKET_ERROR) {
        closesocket(udpSock);
        return INADDR_ANY;
    }

    closesocket(udpSock);
    return localAddr.sin_addr.s_addr;
}

bool operator<(const GUID &guid1, const GUID &guid2)
{
    if (guid1.Data1 != guid2.Data1) {
        return guid1.Data1 < guid2.Data1;
    }
    if (guid1.Data2 != guid2.Data2) {
        return guid1.Data2 < guid2.Data2;
    }
    if (guid1.Data3 != guid2.Data3) {
        return guid1.Data3 < guid2.Data3;
    }
    for (int i = 0; i < 8; i++) {
        if (guid1.Data4[i] != guid2.Data4[i]) {
            return guid1.Data4[i] < guid2.Data4[i];
        }
    }
    return false;
}
