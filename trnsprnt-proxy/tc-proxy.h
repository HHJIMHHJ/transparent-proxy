#ifndef TCPROXY_H
#define TCPROXY_H

#include <QTextEdit>
#include <QString>
#include <QThread>
#include <sys/types.h>
#include <unistd.h>

struct argument
{
public:
    unsigned short port;
    char** client_ip_list;
    int client_ip_num;
    char** websites;
    int website_num;

    bool method_banned[9];
    int url_allowed;
    int file_type[3];
    char* file_names[3];
    int fd[3];
    int nSize[3];

    bool flag;
};

class abstractThread: public QObject
{
    Q_OBJECT
public:
    static QVector<unsigned int> allowed_ip_address;
    static argument arg;
};
class tcProxy: public QObject
{
    Q_OBJECT
public slots:
    void* main_thread();
private:
    int listen_socket;
    int checkclient(unsigned int cli_addr);
    int get_allowed_ip_list();
    int get_client_ip_inet();
signals:
    void* debug_msg(QString);
    void error_msg(QString);
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
    void run() override;
    int http_trans(int clifd,int servfd);
    int tcp_receive(int fd, char* &buf, char* &content, struct http_response_head* head_offsets);
    int checkserver(unsigned int serv_addr);
signals:
    void* debug_msg(QString);
    void error_msg(QString);
};

struct http_response_head{
    int head_len;
    int content_type_offset;
    int content_type_len;//including "Content-Type", not including "\r\n"
    int content_len_offset;
    int content_len_len;//not including "Content-Length: " and "\r\n"
};

#endif // TCPROXY_H
