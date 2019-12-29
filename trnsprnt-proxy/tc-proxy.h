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
    char** website_list;
    int website_num;

    bool method_banned[9];
    int file_type[3];
    char* file_names[3];
    int fd[3];//file descriptor
    int nSize[3];//file size

    bool flag;//manage the running states of all subthreads
    bool black_or_white;//a black ip list or white ip list
};

class mainClass: public QObject
{
    Q_OBJECT
public slots:
    void main_thread();
private:
    int listen_socket;
    int check_client(unsigned int);
    int get_server_ip_list();
    int get_allowed_client_ip_list();
    int server_listen();
    int accept_client(int);
signals:
    void debug_msg(QString);
    void error_msg(QString);
    void important_msg(QString);
    void* start_single_connect(int);
    void start_dns();
};

class dns: public QObject
{
    Q_OBJECT
public:
    char lan_ip[16];
    char wan_ip[16];
    char dns_ip[16];
public slots:
    void dns_trans();
signals:
    void debug_msg(QString);
    void error_msg(QString);
    void important_msg(QString);
};

class singleConnect: public QThread
{
    Q_OBJECT
public:
    int clifd;
private:
    void run() override;
    int http_trans(int,int);
    int http_packet_reassemble(int, char* &, char* &, struct http_response_head*);
    int check_server(unsigned int);
    int connect_server(struct sockaddr_in servaddr);
signals:
    void debug_msg(QString);
    void error_msg(QString);
    void important_msg(QString);
};

struct http_response_head{
    int head_len;
    int content_type_offset;
    int content_type_len;//including "Content-Type", not including "\r\n"
    int content_len_offset;
    int content_len_len;//not including "Content-Length: " and "\r\n"
};

#endif // TCPROXY_H
