#include <winsock2.h>
#include <ws2tcpip.h>
#include <combaseapi.h>
#include <chrono>
#include <iostream>
#include <optional>
#include <regex>

using namespace std;
using namespace std::chrono;

/// Структура заголовка ICMP
struct icmpHeader
{
    unsigned char type;
    unsigned char code;
    unsigned short checkSum;
    unsigned short id;
    unsigned short sequence;
};

/// Структура пакета ICMP
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
    unsigned short processId = static_cast<unsigned short>(GetCurrentProcessId());
    icmpPacket pac;
    DWORD timeout = 3000;

    if (setsockopt(sock,        // Сокет
                   SOL_SOCKET,  // Уровень сокета
                   SO_SNDTIMEO, // Таймаут отправки
                   reinterpret_cast<const char *>(
                       &timeout),   // Указатель на значение таймаута отправки
                   sizeof(timeout)) // Размер таймаута
            == SOCKET_ERROR
        || setsockopt(sock,        // Сокет
                      SOL_SOCKET,  // Уровень сокета
                      SO_RCVTIMEO, // Таймаут получения
                      reinterpret_cast<const char *>(
                          &timeout),   // Указатель на значение таймаута отправки
                      sizeof(timeout)) // Размер таймаута
               == SOCKET_ERROR) {
        cerr << "Не удалось установить таймауты сокета: " << WSAGetLastError() << endl;
        return;
    }

    const int bufferSize = 1024; // Размер буфера
    char recvBuffer[bufferSize]; // Буфер

    for (int i = 0; i < maxHops; i++) {
        // Созданте GUID для отправки
        GUID guid;
        CoCreateGuid(&guid);

        // ICMP эхо-запрос
        pac.header.type = 8;
        pac.header.code = 0;

        pac.header.checkSum = 0;
        pac.header.id = processId;
        pac.header.sequence = static_cast<unsigned short>(i);
        pac.data = guid;

        pac.header.checkSum = calculateChecksum(reinterpret_cast<unsigned short *>(&pac),
                                                sizeof(pac));

        // Расчет времени жизни
        int ttl = i + 1;

        if (setsockopt(sock,                                 // Сокет
                       IPPROTO_IP,                           // Уровень IP
                       IP_TTL,                               // Имя параметра - время жизни
                       reinterpret_cast<const char *>(&ttl), // Указатель на переменную времени жизни
                       sizeof(ttl))                          // размер переменной времени жизни
            == SOCKET_ERROR) {
            cerr << "Не удалось установить TTL: " << WSAGetLastError() << endl;
            return;
        }

        // Отправка данных
        int res = sendto(sock,                                    // Сокет
                         reinterpret_cast<const char *>(&pac),    // Указатель на буфер с данными
                         sizeof(pac),                             // Размер буфера
                         0,                                       // Флаги
                         reinterpret_cast<SOCKADDR *>(&destAddr), // Указатель на адрес назначения
                         sizeof(destAddr));                       // Размер адреса назначения
        if (res == SOCKET_ERROR) {
            cerr << "Ошибка отправки: " << WSAGetLastError() << endl;
            return;
        }

        // Время начала отправки
        auto start = chrono::high_resolution_clock::now();

        sockaddr_in fromAddr;
        int fromLen = sizeof(fromAddr);
        bool stepCompleted = false;

        while (!stepCompleted) {
            // Получение данных
            int recvRes = recvfrom(sock,       // Сокет
                                   recvBuffer, // Указаьель на буфер
                                   bufferSize, // Размер буфера
                                   0,          // Флаги
                                   reinterpret_cast<SOCKADDR *>(
                                       &fromAddr), // Указатель на адрес отправителя
                                   &fromLen);      // Длина адреса отправителя

            // Время получения
            auto end = high_resolution_clock::now();

            // Промежуток времени в мс
            auto durationMs = duration_cast<milliseconds>(
                high_resolution_clock::duration(end - start));

            // Обработка ошибок
            if (recvRes == SOCKET_ERROR) {
                // Превышен таймаут
                if (WSAGetLastError() == WSAETIMEDOUT) {
                    cout << ttl << "\t* * *" << endl;
                    stepCompleted = true;
                    continue;
                } else { // Отображение кода ошибки
                    cerr << "Ошибка получения: " << WSAGetLastError() << endl;
                    return;
                }
            }

            // Валидация длины
            // Заголовок IP-пакета равен 20 байт.
            if (recvRes < 20)
                continue;

            // Заголовок IP-пакета
            unsigned char *ipHeader = reinterpret_cast<unsigned char *>(recvBuffer);
            int ipHeaderLen = (ipHeader[0] & 0x0F) * 4; // Длина заголовка

            // Обработка ошибки
            // ipHeaderLen + 8 - Минимально допустимый размер пакета
            if (recvRes < ipHeaderLen + 8)
                continue;

            icmpHeader *icmpRes = reinterpret_cast<icmpHeader *>(recvBuffer + ipHeaderLen);

            // Эхо-ответ
            if (icmpRes->type == 0) {
                // Проверка ID процесса и последовательности
                if (icmpRes->id != processId || icmpRes->sequence != i) {
                    continue;
                }

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

                // Вывод данных
                if (dnsRes == 0 && strcmp(hostName, ipStr) != 0) {
                    cout << ttl << "\t" << hostName << "\t(" << ipStr << ")" << "\t("
                         << durationMs.count() << " мс)";
                } else {
                    cout << ttl << "\t" << ipStr << "\t(" << durationMs.count() << " мс)";
                }
                cout << "\tДостигнут целевой узел" << endl;

                return;
            } else if (icmpRes->type == 11) { // Промежуточный узел

                // Получение смещения до начала вложенного IP-пакета
                int innerIpHeaderOffset = ipHeaderLen + 8;
                if (recvRes < innerIpHeaderOffset + 20)
                    continue;

                // Извлечение IP-заголовка из IMCP-ответа
                unsigned char *innerIpHeader = reinterpret_cast<unsigned char *>(
                    recvBuffer + innerIpHeaderOffset);

                // Длина вложенного IP-заголовка
                int innerIpHeaderLen = (innerIpHeader[0] & 0x0F) * 4;

                // Вычисление минимального допустимого размера пакета
                if (recvRes < innerIpHeaderOffset + innerIpHeaderLen + 8)
                    continue;

                // Заголовок оригитального ICMP-запроса
                icmpHeader *originalIcmp = reinterpret_cast<icmpHeader *>(
                    recvBuffer + innerIpHeaderOffset + innerIpHeaderLen);

                // Проверка соответствия ID и последовательности
                if (originalIcmp->id != processId || originalIcmp->sequence != i) {
                    continue;
                }

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

                // Вывод данных
                if (dnsRes == 0 && strcmp(hostName, ipStr) != 0) {
                    cout << ttl << "\t" << hostName << "\t(" << ipStr << ")" << "\t("
                         << durationMs.count() << " мс)" << endl;
                } else {
                    cout << ttl << "\t" << ipStr << "\t(" << durationMs.count() << " мс)" << endl;
                }

                // Флаг завершения шага
                stepCompleted = true;
            }
        }
    }
}

unsigned short calculateChecksum(unsigned short *buffer, int size)
{
    unsigned long cksum = 0;

    // Суммируем каждые 2 байта (16 бит)
    while (size > 1) {
        cksum += *buffer++;
        size -= 2;
    }

    // Если остался один байт, обрабатываем его как младший байт в слове
    if (size) {
        cksum += *(static_cast<unsigned char *>(static_cast<void *>(buffer)));
    }

    // Сворачиваем 32-битную сумму в 16 бит (складываем старшие 16 бит с младшими)
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    // Возвращаем побитовое дополнение
    return static_cast<unsigned short>(~cksum);
}
