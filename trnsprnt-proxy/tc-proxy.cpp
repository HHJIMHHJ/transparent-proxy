#include <sys/stat.h>
#include <sys/epoll.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>
#include <linux/netfilter_ipv4.h>
#include <sys/ioctl.h>
#include <QMap>
#include "tc-proxy.h"

#define LISTENQ 10
#define MAXLINE 4096

int Connect_Serv(struct sockaddr_in);
int tcp_listen(int);
int checkclient(in_addr_t);
int get_client_ip_inet();

QVector<unsigned int> allowed_ip_address;
unsigned int* client_ip_inet;
extern argument arg;

void* tcProxy::main_thread()
{
    struct sockaddr_in cli_addr;
    socklen_t sin_size = sizeof(struct sockaddr_in);
    int connfd,sockfd;

    if (get_allowed_ip_list() == -1)return NULL;
    if (get_client_ip_inet() == -1) return NULL;

    system("rm -rf ./http_data");
    if (system("mkdir ./http_data") == -1) emit debug_msg(QString("cannot create directory http_data!"));
    sockfd=tcp_listen(arg.port);
    emit debug_msg(QString("listening on port: %1, sockfd: %2").arg(arg.port).arg(sockfd));
    listen_socket = sockfd;

    int nonblocked = 1;
    ioctl(sockfd, FIONBIO, (char*)&nonblocked);
    while(arg.flag){
        connfd=accept(sockfd,(struct sockaddr *)&cli_addr, &sin_size);
        if(connfd<0) {
            continue;
        }
        if (!checkclient(cli_addr.sin_addr.s_addr)){
            nonblocked = 0;
            ioctl(connfd, FIONBIO, (char*)&nonblocked);
            emit debug_msg(QString("connection with client established, client ip: %1, port: %2, fd: %3")
                           .arg(inet_ntoa(cli_addr.sin_addr)).arg(ntohs(cli_addr.sin_port)).arg(connfd));
            getsockname(connfd, (struct sockaddr *)&cli_addr, &sin_size);
            emit debug_msg(QString("socket port: %1, socket ip: %2").arg(ntohs(cli_addr.sin_port)).arg(inet_ntoa(cli_addr.sin_addr)));
            emit start_single_connect(connfd);
        }
        else
            close(connfd);
    }
    close(listen_socket);
    delete [] client_ip_inet;
    emit debug_msg(QString("transparent proxy terminated"));
    return nullptr;
}

void singleConnect::run(){
    int servfd;
    struct sockaddr_in servaddr;
    socklen_t servlen=sizeof(struct sockaddr_in);

    if ( (getsockopt(clifd,SOL_IP,SO_ORIGINAL_DST,&servaddr,&servlen)) != 0 ){
        close(clifd);
        emit debug_msg(QString("Could not recognize the client."));
        return;
    }
    if (checkserver(servaddr.sin_addr.s_addr) == -1){
        close(clifd);
        return;
    }
    if ((servfd = Connect_Serv(servaddr)) == -1){
        return;
    }

    emit debug_msg(QString("connection with server established, server ip: %1, port: %2, fd: %3")
                   .arg(inet_ntoa(servaddr.sin_addr)).arg(ntohs(servaddr.sin_port)).arg(servfd));
    http_trans(clifd,servfd);
    close(servfd);
    close(clifd);
    return;

}

void dns::dns_trans(){
    struct sockaddr_in local_addr;
    struct sockaddr_in client_addr;
    struct sockaddr_in dns_addr;
    struct sockaddr_in tmp_addr;
    int len;
    int on = 1;
    int nonblocked = 1;

    QMap<unsigned short, sockaddr_in> transaction_list;
    unsigned short* tmp;

    tmp = new unsigned short;

    socklen_t namelen = sizeof(sockaddr_in);
    local_addr.sin_addr.s_addr = inet_addr(lan_ip);
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(arg.port);

    unsigned int server_ip_net = inet_addr(dns_ip);
    dns_addr.sin_addr.s_addr = server_ip_net;
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(53);

    client_addr.sin_family = AF_INET;

    char buf[MAXLINE];

    int dnsfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    setsockopt(dnsfd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));
    if(bind(dnsfd, (struct sockaddr *)&local_addr, namelen) < 0) {
        emit error_msg(QString("dns binding failed!!!"));
        close(dnsfd);
        return;
    }
    local_addr.sin_addr.s_addr = inet_addr(wan_ip);
    int servfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(bind(servfd, (struct sockaddr *)&local_addr, namelen) < 0) {
        emit error_msg(QString("dns binding failed!!!"));
        close(dnsfd);
        close(servfd);
        return;
    }
    ::connect(servfd, (struct sockaddr *)&dns_addr, namelen);
    printf("dns service started\n");
    ioctl(dnsfd, FIONBIO, (char*)&nonblocked);
    ioctl(servfd, FIONBIO, (char*)&nonblocked);
    while(arg.flag){
        //printf("loop\n");
        if ((len = recvfrom(dnsfd, buf, MAXLINE, 0, (struct sockaddr *)&tmp_addr, &namelen)) > 0){
            //printf("%d\n", len);
            for (int i = 0;i < arg.client_ip_num;i++){
                if (tmp_addr.sin_addr.s_addr == client_ip_inet[i]){
                    memcpy(tmp, buf, 2);
                    transaction_list.insert(*tmp, tmp_addr);
                    printf("transaction:%hu, client:%u, port:%hu created\n", *tmp, tmp_addr.sin_addr.s_addr, tmp_addr.sin_port);
                    if (send(servfd, buf, len, 0) < 0) {
                        emit error_msg(QString("dns send to server failed!"));
                        close(dnsfd);
                        close(servfd);
                        return;
                    }
                }
                else emit debug_msg(QString("dns authentication failed!"));
            }
        }
        if((len = read(servfd, buf, MAXLINE)) > 0){
            printf("server dns response recieved\n");
            memcpy(tmp, buf, 2);
            client_addr = transaction_list[*tmp];
            printf("transaction:%hu, client:%u, port:%hu deleted\n", *tmp, tmp_addr.sin_addr.s_addr, tmp_addr.sin_port);
            transaction_list.remove(*tmp);
            if (sendto(dnsfd, buf, len, 0, (struct sockaddr *)&client_addr, namelen) < 0){
                emit error_msg(QString("dns send to client failed!"));
                close(dnsfd);
                close(servfd);
                return;
            }
        }
    }
    close(dnsfd);
    close(servfd);
    return;
}

int tcp_listen(int port)
{
    struct sockaddr_in cl_addr,proxyserver_addr;
    socklen_t sin_size = sizeof(struct sockaddr_in);
    int sockfd, accept_sockfd, on = 1;


    memset(&proxyserver_addr, 0, sizeof(proxyserver_addr));
    proxyserver_addr.sin_family = AF_INET;
    proxyserver_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    proxyserver_addr.sin_port = htons(port);

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0) {
        printf("Socket failed...Abort...\n");
        return -1;
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));

    if (bind(sockfd, (struct sockaddr *) &proxyserver_addr, sizeof(proxyserver_addr)) < 0) {
        printf("Bind failed...Abort...\n");
        return -1;
    }
    if (listen(sockfd, LISTENQ) < 0) {
        printf("Listen failed...Abort...\n");
        return -1;
    }
    return sockfd;
}

//return 0;normal;return -1:host dns failed
int tcProxy::get_allowed_ip_list(){
    struct hostent *hostinfo;
    unsigned int** allowedip_list;
    struct in_addr s;
    allowed_ip_address.clear();
    for (int i = 0; i < arg.website_num; i++){
        int j = 0;
        hostinfo = gethostbyname(arg.websites[i]);
        if (hostinfo == NULL) {
            emit error_msg(QString("gethostbyname failed!"));
            return -1;
        }
        printf("website: %s\n", arg.websites[i]);
        allowedip_list = (unsigned int** )hostinfo->h_addr_list;
        while (allowedip_list[j] != nullptr){
            allowed_ip_address.append(*allowedip_list[j]);
            s.s_addr = *allowedip_list[j];
            printf("%s\n",inet_ntoa(s));
            j++;
        }
    }
    return 0;
}

int tcProxy::get_client_ip_inet(){
    struct in_addr tmp;
    client_ip_inet = new unsigned int[arg.client_ip_num];
    for (int i = 0; i < arg.client_ip_num;i++){
        if (!inet_aton(arg.client_ip_list[i], &tmp)) {
            emit error_msg(QString("Invalid client address!"));
            return -1;
        }
        client_ip_inet[i] = tmp.s_addr;
    }
    return 0;
}

//return 0:passed;return -1:failed
int singleConnect::checkserver(unsigned int serv_addr) {
    struct in_addr s;
    for (int i = 0; i < allowed_ip_address.length(); i++){
        if (allowed_ip_address[i] == serv_addr){
            s.s_addr = serv_addr;
            printf("%s\n",inet_ntoa(s));
            emit debug_msg(QString("Server IP authentication passed!"));
            return 0;
        }
    }
    s.s_addr = serv_addr;
    emit debug_msg(QString("Server IP authentication failed!"));
    emit debug_msg(QString("Server IP: %1").arg(inet_ntoa(s)));
    return -1;
}

//return 0:passed;return -1:failed
int tcProxy::checkclient(unsigned int cli_addr) {
    struct in_addr s;
    for (int i = 0;i < arg.client_ip_num;i++){
        if (client_ip_inet[i] == cli_addr)	{
            emit debug_msg(QString("Client IP authentication passed ! "));
            return 0;
        }
    }
    s.s_addr = cli_addr;
    emit debug_msg(QString("Client IP authentication failed !"));
    emit debug_msg(QString("Client IP: %1").arg(inet_ntoa(s)));
    return -1;
}



int Connect_Serv(struct sockaddr_in servaddr)
{
    int cnt_stat, remoteSocket;

    remoteSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (remoteSocket < 0) {
        printf("Cannot establish socket.\n");
        return -1;
    }
    servaddr.sin_family= AF_INET;
    cnt_stat = connect(remoteSocket, (struct sockaddr *) &servaddr, sizeof(servaddr));
    if (cnt_stat < 0) {
        printf("Remote connect failed.\n");
        return -1;
    }
    return remoteSocket;
}

//return 0:terminated by the user;return -1:network problem;return 1:forbidden request type;return 2:forbidden file type;
int singleConnect::http_trans(int clifd, int servfd)
{
    int maxfdp, length;
    fd_set rset;
    struct timeval tv;
    char cli_buf[MAXLINE];
    char* serv_buf;
    char* serv_content;
    struct http_response_head *response_head_offsets = new http_response_head;
    char filename[50];
    FILE* f;
    char tmp[17];
    struct sockaddr_in servaddr;
    socklen_t servlen=sizeof(struct sockaddr_in);
    char request[100];
    char response_head[500];
    char* field;
    char* c1, *c2;

    getsockopt(clifd,SOL_IP,SO_ORIGINAL_DST,&servaddr,&servlen);

    sprintf(filename, "http_data/%d_%d_%s", clifd, servfd, inet_ntoa(servaddr.sin_addr));
    f = fopen(filename, "w");

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    maxfdp=(clifd>=servfd?clifd:servfd ) + 1;
    while(arg.flag)
    {
        FD_ZERO(&rset);
        FD_SET( clifd,&rset );
        FD_SET( servfd,&rset );

        if(select( maxfdp,&rset,nullptr,nullptr,&tv ) <= 0){
            //printf("server error.\n");
            continue;
        }

        if( FD_ISSET(clifd,&rset))
        {
            int s;
            length = read(clifd,cli_buf,MAXLINE);
            if( length <= 0 ) return length;
            printf("received a message from client socket %d, to server socket %d, length:%d.\n", clifd, servfd, length);
            c1 = strstr(cli_buf, "\r\n");
            if (c1 == nullptr) printf("not a http request head.\n");
            else{
                fprintf(f, "c-s\n%s\n\n", cli_buf);
                strncpy(request, cli_buf, c1 - cli_buf);
                request[c1 - cli_buf] = '\0';
                for (int i = 0; i < 9;i++){
                    if (arg.method_banned[i]){
                        switch (i){
                        case 0:if (strstr(request, "GET")){
                                fprintf(f, "GET method monitored!\n");
                                close(clifd);
                                close(servfd);
                                return 1;
                            }
                            break;
                        case 1:if (strstr(request, "HEAD")){
                                fprintf(f, "HEAD method monitored!\n");
                                close(clifd);
                                close(servfd);
                                return 1;
                            }
                            break;
                        case 2:if (strstr(request, "POST")){
                                fprintf(f, "POST method monitored!\n");
                                close(clifd);
                                close(servfd);
                                return 1;
                            }
                            break;
                        case 3:if (strstr(request, "PUT")){
                                fprintf(f, "PUT method monitored!\n");
                                close(clifd);
                                close(servfd);
                                return 1;
                            }break;
                        case 4:if (strstr(request, "DELETE")){
                                fprintf(f, "DELETE method monitored!\n");
                                close(clifd);
                                close(servfd);
                                return 1;
                            }break;
                        case 5:if (strstr(request, "CONNECT")){
                                fprintf(f, "CONNECT method monitored!\n");
                                close(clifd);
                                close(servfd);
                                return 1;
                            };break;
                        case 6:if (strstr(request, "OPTIONS")){
                                fprintf(f, "OPTIONS method monitored!\n");
                                close(clifd);
                                close(servfd);
                                return 1;
                            }break;
                        case 7:if (strstr(request, "TRACE")){
                                fprintf(f, "TRACE method monitored!\n");
                                close(clifd);
                                close(servfd);
                                return 1;
                            }break;
                        case 8:if (strstr(request, "PATCH")){
                                fprintf(f, "PATCH method monitored!\n");
                                close(clifd);
                                close(servfd);
                                return 1;
                            }
                        }
                    }
                }
            }
            if((s = send( servfd,cli_buf,length,0)) <= 0) {
                printf("send to server returns %d, error code %d.\n", s, errno);
                break;
            }
        }
        if( FD_ISSET(servfd,&rset) ){
            length = tcp_receive(servfd, serv_buf, serv_content, response_head_offsets);
            printf("received a message to client socket %d, from server socket %d, length:%d.\n", clifd, servfd, length);
            //printf("%s\n", serv_buf);
            if (length <= 0) break;
            if (serv_content == nullptr);
            else if(!response_head_offsets->content_len_offset);
            else{
                field = (char*)malloc(response_head_offsets->content_type_len + 1);
                strncpy(field, serv_buf + response_head_offsets->content_type_offset, response_head_offsets->content_type_len);
                field[response_head_offsets->content_type_len] = '\0';
                for (int i = 0; i < 3;i++){
                    if (arg.file_type[i]){
                        switch (i){
                        case 0:if (strstr(field, "application/pdf")){
                                fprintf(f, "pdf downloading monitored!\n");
                                if (arg.file_type[i] == 2){
                                    lseek(arg.fd[i], (off_t)0, SEEK_SET);
                                    length = arg.nSize[i]+ (serv_content - serv_buf);
                                    sprintf(tmp, "%d", arg.nSize[i]);
                                    serv_buf = (char*)realloc(serv_buf, arg.nSize[i] + (serv_content - serv_buf)
                                                              - response_head_offsets->content_len_len + strlen(tmp));
                                    if ((c1 = serv_buf + response_head_offsets->content_len_offset + strlen(tmp))
                                            != (c2 = serv_buf + response_head_offsets->content_len_offset + response_head_offsets->content_len_len))
                                    {
                                        memmove(c1, c2, serv_content - serv_buf - response_head_offsets->content_len_offset - response_head_offsets->content_len_len);
                                        serv_content = serv_content + strlen(tmp) - response_head_offsets->content_len_len;
                                        length += strlen(tmp) - response_head_offsets->content_len_len;
                                    }
                                    memcpy(serv_buf + response_head_offsets->content_len_offset, tmp, strlen(tmp));
                                    read(arg.fd[i], serv_content, arg.nSize[i]);
                                    i = 3;
                                }
                                else{
                                    close(clifd);
                                    close(servfd);
                                    return 2;
                                }
                            }
                            break;
                        case 2:if (strstr(field, "application/msword") || strstr(field, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")){
                                fprintf(f, "msword downloading monitored!\n");
                                if (arg.file_type[i] == 2){
                                    lseek(arg.fd[i], (off_t)0, SEEK_SET);
                                    length = arg.nSize[i]+ (serv_content - serv_buf);
                                    sprintf(tmp, "%d", arg.nSize[i]);
                                    serv_buf = (char*)realloc(serv_buf, arg.nSize[i] + (serv_content - serv_buf)
                                                              - response_head_offsets->content_len_len + strlen(tmp));
                                    if ((c1 = serv_buf + response_head_offsets->content_len_offset + strlen(tmp))
                                            != (c2 = serv_buf + response_head_offsets->content_len_offset + response_head_offsets->content_len_len))
                                    {
                                        memmove(c1, c2, serv_content - serv_buf - response_head_offsets->content_len_offset - response_head_offsets->content_len_len);
                                        serv_content = serv_content + strlen(tmp) - response_head_offsets->content_len_len;
                                        length += strlen(tmp) - response_head_offsets->content_len_len;
                                    }
                                    memcpy(serv_buf + response_head_offsets->content_len_offset, tmp, strlen(tmp));
                                    read(arg.fd[i], serv_content, arg.nSize[i]);
                                    i = 3;
                                }
                                else{
                                    close(clifd);
                                    close(servfd);
                                    return 2;
                                }

                            }
                            break;
                        case 1:if (strstr(field, "application/vnd.ms-excel") || strstr(field, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")){
                                fprintf(f, "msexcel downloading monitored!\n");
                                if (arg.file_type[i] == 2){
                                    lseek(arg.fd[i], (off_t)0, SEEK_SET);
                                    length = arg.nSize[i]+ (serv_content - serv_buf);
                                    sprintf(tmp, "%d", arg.nSize[i]);
                                    serv_buf = (char*)realloc(serv_buf, arg.nSize[i] + (serv_content - serv_buf)
                                                              - response_head_offsets->content_len_len + strlen(tmp));
                                    if ((c1 = serv_buf + response_head_offsets->content_len_offset + strlen(tmp))
                                            != (c2 = serv_buf + response_head_offsets->content_len_offset + response_head_offsets->content_len_len))
                                    {
                                        memmove(c1, c2, serv_content - serv_buf - response_head_offsets->content_len_offset - response_head_offsets->content_len_len);
                                        serv_content = serv_content + strlen(tmp) - response_head_offsets->content_len_len;
                                        length += strlen(tmp) - response_head_offsets->content_len_len;
                                    }
                                    memcpy(serv_buf + response_head_offsets->content_len_offset, tmp, strlen(tmp));
                                    read(arg.fd[i], serv_content, arg.nSize[i]);
                                    i = 3;
                                }
                                else{
                                    close(clifd);
                                    close(servfd);
                                    return 2;
                                }
                            }
                            break;
                        }
                    }
                }
                free(field);
            }
            fprintf(f, "s-c\n%s", response_head);
            if(send(clifd,serv_buf,length,0) <= 0) {
                printf("send error. \n");
                break;
            }
            free(serv_buf);
        }
    }
    free(response_head_offsets);
    fclose(f);
    return 0;
}

//len = 0:connection terminated;len = -1:error
int singleConnect::tcp_receive(int fd, char* &buf, char* &content, struct http_response_head* head_offsets){
    int len, content_len, total_len = 0;
    char* head, *field, *c1, *c2;
    char* tmp_buf;
    tmp_buf = (char*)malloc(MAXLINE);
    len = read(fd, tmp_buf, MAXLINE);
    //printf("inside tcp_receive %d\n", len);
    total_len += len;
    if (len <= 0) return len;
    if (strncmp(tmp_buf, "HTTP", 4) != 0) {
        printf("not a http response head\n");
        buf = tmp_buf;
        content = nullptr;
        return len;
    }
    else{
        c1 = strstr(tmp_buf, "\r\n\r\n");
        head_offsets->head_len = c1 - tmp_buf + 4;
        if (head_offsets->head_len == len) {
            printf("content is empty.\n");
            buf = tmp_buf;
            content = nullptr;
            return len;
        }
        content = c1 + 4;
        head = (char*)malloc(head_offsets->head_len + 1);//include the dividing "\r\n\r\n", in case "Content-Length" is the last field
        strncpy(head, tmp_buf, head_offsets->head_len);
        head[head_offsets->head_len] = '\0';
        if(!strstr(head, "Content-Length: ") || !strstr(head, "Content-Type: ")) {
            printf("unable to recognize content length or content type\n");
            buf = tmp_buf;
            content = buf + head_offsets->head_len;
            head_offsets->content_len_offset = 0;
            return len;
        }
        c2 = strstr(head, "Content-Length: ");
        c1 = strstr(c2, "\r\n");
        head_offsets->content_len_offset = c2 + 16 - head;
        head_offsets->content_len_len = c1 - c2 - 16;
        field = (char*)malloc(head_offsets->content_len_len + 1);
        strncpy(field, c2 + 16, head_offsets->content_len_len);
        field[head_offsets->content_len_len] = '\0';
        content_len = atoi(field);
        c1 = strstr(head, "Content-Type: ");
        c2 = strstr(c1, "\r\n");
        head_offsets->content_type_offset = c1 - head;
        head_offsets->content_type_len = c2 - c1;
        free(field);
        free(head);
        if (content_len == 0) {
            printf("malformed packet\n");
            return -1;
        }
        content_len -= tmp_buf + len - content;
        buf = (char*)malloc(total_len + content_len + 1);
        memcpy(buf, tmp_buf, total_len);
        content = buf + (content - tmp_buf);
        while(content_len > 0){
            len = read(fd, tmp_buf, MAXLINE);
            content_len -= len;
            memcpy(buf + total_len, tmp_buf, len);
            total_len += len;
        }
        buf[total_len] = '\0';
        return total_len;
    }
}
