#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <iostream>



MainWindow::MainWindow(QWidget *parent, int argc, char** argv)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->website->setText("jwc.sjtu.edu.cn|www.baidu.com|www.sohu.com|www.qq.com|weibo.com|www.sina.com.cn|tv.sohu.com|www.163.com|www.douban.com|www.iqiyi.com|"
                          "www.sjtu.edu.cn|www.tianya.cn|bbs.sjtu.edu.cn|www.xinhuanet.com");
    ui->client_IP->setText("192.168.88.2");
    ui->listen_port->setText("8888");
    ui->dns_ip->setText("192.168.1.1");
    ui->lan_ip->setText("192.168.88.1");
    ui->wan_ip->setText("192.168.1.113");
    QStringList string_list;
    string_list<<"allowed"<<"banned"<<"replace";
    ui->pdf->addItems(string_list);
    ui->doc->addItems(string_list);
    ui->xls->addItems(string_list);
    tc_proxy = new tcProxy;
    tc_proxy->moveToThread(&tc_proxy_thread);
    dns_trans = new dns;
    dns_trans->moveToThread(&dns_trans_thread);
    connect(this, &MainWindow::start_proxy, tc_proxy, &tcProxy::test);
    connect(tc_proxy, &tcProxy::debug_msg, this, &MainWindow::print);
    connect(tc_proxy, &tcProxy::start_single_connect, this, &MainWindow::create_single_connect);
    connect(this, &MainWindow::start_proxy, dns_trans, &dns::dns_trans);
    connect(dns_trans, &dns::debug_msg, this, &MainWindow::print);
    connect(dns_trans, &dns::error_msg, this, &MainWindow::error_handle);
    tc_proxy_thread.start();
    dns_trans_thread.start();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_toggled(bool checked)
{
    if (checked){
        //pass argument to main thread
        argument* arg = new argument;

        QStringList tmp = ui->website->text().split('|');
        arg->websites = new char*[tmp.size()];
        arg->website_num = tmp.size();
        for (int i = 0;i < tmp.size(); i++){
            arg->websites[i] = new char[tmp.at(i).length() + 1];
            memcpy(arg->websites[i], tmp.at(i).toStdString().c_str(), tmp.at(i).length() + 1);
        }
        //printf("%s\n", arg->websites[0]);
        std::string tmp2 = ui->client_IP->text().toStdString();
        memcpy(arg->client_ip, tmp2.c_str(), tmp2.size() + 1);

        arg->port = ui->listen_port->text().toInt();
        arg->method_banned[0] = ui->GET->isChecked();
        arg->method_banned[1] = ui->HEAD->isChecked();
        arg->method_banned[2] = ui->POST->isChecked();
        arg->method_banned[3] = ui->PUT->isChecked();
        arg->method_banned[4] = ui->DELETE->isChecked();
        arg->method_banned[5] = ui->CONNECT->isChecked();
        arg->method_banned[6] = ui->OPTIONS->isChecked();
        arg->method_banned[7] = ui->TRACE->isChecked();
        arg->method_banned[8] = ui->PATCH->isChecked();
        arg->file_type[0] = ui->pdf->currentIndex();
        arg->file_type[1] = ui->xls->currentIndex();
        arg->file_type[2] = ui->doc->currentIndex();
        for (int i = 0;i < 3; i++){
            if (arg->file_type[i] == 2){
                if (file_names[i].isEmpty()) {
                    QMessageBox msgBox;
                    msgBox.setText("Please choose a file.");
                    msgBox.exec();
                    ui->pushButton->setChecked(false);
                    return;
                }
                arg->file_names[i] = new char[file_names[i].length() + 1];
                memcpy(arg->file_names[i], file_names[i].toStdString().c_str(), file_names[i].length() + 1);
                arg->fd[i] = open(arg->file_names[i], O_RDONLY);
                arg->nSize[i] = lseek(arg->fd[i], 0, SEEK_END);
                if (arg->nSize[i] == -1) {
                    QMessageBox msgBox;
                    msgBox.setText("Cannot read this file.");
                    msgBox.exec();
                    ui->pushButton->setChecked(false);
                    return;
                }
            }
        }
        tc_proxy->flag = true;
        //pass argument to dns thread
        strcpy(dns_trans->client_ip, arg->client_ip);
        dns_trans->port = arg->port;
        tmp2 = ui->lan_ip->text().toStdString();
        memcpy(dns_trans->lan_ip, tmp2.c_str(), tmp2.size() + 1);
        tmp2 = ui->wan_ip->text().toStdString();
        memcpy(dns_trans->wan_ip, tmp2.c_str(), tmp2.size() + 1);
        tmp2 = ui->dns_ip->text().toStdString();
        memcpy(dns_trans->dns_ip, tmp2.c_str(), tmp2.size() + 1);
        dns_trans->flag = true;
        singleConnect::running = true;
        emit start_proxy(arg);
    }
    else {
        tc_proxy->flag = false;
        dns_trans->flag = false;
        singleConnect::running = false;
    }
}

void MainWindow::print(QString s){
    ui->textEdit->append(s);
}

void MainWindow::create_single_connect(int clifd){
    singleConnect* single_connect = new singleConnect;
    single_connect_threads<<single_connect;
    connect(single_connect, &singleConnect::debug_msg, this, &MainWindow::print);
    connect(single_connect, &singleConnect::finished, single_connect, &singleConnect::deleteLater);
    connect(single_connect, &singleConnect::finished, this, &MainWindow::single_connect_destroy);
    single_connect->clifd = clifd;
    single_connect->start();
}

void MainWindow::single_connect_destroy(){
    single_connect_threads.removeOne(nullptr);
}

void MainWindow::on_pushButton_pdf_clicked()
{
    file_names[0] = QFileDialog::getOpenFileName(this,
        tr("choose file"), "/home/hhjimhhj/build-trnsprnt-proxy-Desktop_Qt_5_13_1_GCC_64bit-Debug/files", tr("*.pdf"));
    ui->textEdit->append(file_names[0]);
}

void MainWindow::on_pushButton_xls_clicked()
{
    file_names[1] = QFileDialog::getOpenFileName(this,
        tr("choose file"), "/home/hhjimhhj/build-trnsprnt-proxy-Desktop_Qt_5_13_1_GCC_64bit-Debug/files", tr("*.xls *.xlsx"));
    ui->textEdit->append(file_names[1]);
}

void MainWindow::on_pushButton_doc_clicked()
{
    file_names[2] = QFileDialog::getOpenFileName(this,
        tr("choose file"), "/home/hhjimhhj/build-trnsprnt-proxy-Desktop_Qt_5_13_1_GCC_64bit-Debug/files", tr("*.doc *.docx"));
    ui->textEdit->append(file_names[2]);
}

void MainWindow::on_pdf_currentIndexChanged(int index)
{
    if (index == 2) ui->pushButton_pdf->setEnabled(true);
    else ui->pushButton_pdf->setEnabled(false);
}

void MainWindow::on_xls_currentIndexChanged(int index)
{
    if (index == 2) ui->pushButton_xls->setEnabled(true);
    else ui->pushButton_xls->setEnabled(false);
}

void MainWindow::on_doc_currentIndexChanged(int index)
{
    if (index == 2) ui->pushButton_doc->setEnabled(true);
    else ui->pushButton_doc->setEnabled(false);
}

void MainWindow::error_handle(QString msg)
{
    ui->textEdit->append(msg);
    ui->pushButton->setChecked(false);
}
