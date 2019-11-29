#ifndef TCPROXY_H
#define TCPROXY_H

#include <QTextEdit>
#include <QString>
#include <QThread>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

struct argument
{
public:
    unsigned short port;
    char client_ip[16];
    char** websites;
    int website_num;

    bool method_banned[9];
    int url_allowed;
    int file_type[3];
    char* file_names[3];
    int fd[3];
    int nSize[3];
};

class tcProxy: public QObject
{
    Q_OBJECT
public:
    bool flag;
    static QVector<int> openned_sockets;
public slots:
    void* test(argument*);
private:
    int listen_socket;
    int checkclient(unsigned int cli_addr);
signals:
    void* debug_msg(QString);
    void* start_single_connect(int);
};

class dns: public QObject
{
    Q_OBJECT
public:
    unsigned short port;
    char client_ip[16];
    char lan_ip[16];
    char wan_ip[16];
    char dns_ip[16];
    bool flag;
public slots:
    void dns_trans();
signals:
    void* debug_msg(QString);
    void error_msg(QString);
};

class singleConnect: public QThread
{
    Q_OBJECT
public:
    int clifd;
    static bool running;
void run() override;
int dns_trans(int clifd);
int http_trans(int clifd,int servfd);
int tcp_receive(int fd, char* &buf, char* &content, struct http_response_head* head_offsets);
int checkserver(unsigned int serv_addr);
signals:
    void* debug_msg(QString);
};

struct http_response_head{
    int head_len;
    int content_type_offset;
    int content_type_len;//including "Content-Type", not including "\r\n"
    int content_len_offset;
    int content_len_len;//not including "Content-Length: " and "\r\n"
};

#endif // TCPROXY_H
