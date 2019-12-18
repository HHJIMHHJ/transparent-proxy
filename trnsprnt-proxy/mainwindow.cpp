#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <iostream>
#include <fstream>
#include <fcntl.h>

argument arg;

MainWindow::MainWindow(QWidget *parent, int argc, char** argv)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->website->setText("jwc.sjtu.edu.cn|www.baidu.com|www.sohu.com|www.qq.com|weibo.com|www.sina.com.cn|tv.sohu.com|www.163.com|www.douban.com|www.iqiyi.com|"
                         "www.sjtu.edu.cn|www.tianya.cn|bbs.sjtu.edu.cn");
    ui->client_IP->setText("192.168.88.2|192.168.88.3");
    ui->listen_port->setText("8888");
    ui->dns_ip->setText("192.168.72.2");
    ui->lan_ip->setText("192.168.88.1");
    ui->wan_ip->setText("192.168.72.128");
    QStringList string_list;
    string_list<<"allowed"<<"banned"<<"replace";
    ui->pdf->addItems(string_list);
    ui->doc->addItems(string_list);
    ui->xls->addItems(string_list);
    tc_proxy = new mainClass;
    tc_proxy->moveToThread(&tc_proxy_thread);
    dns_trans = new dns;
    dns_trans->moveToThread(&dns_trans_thread);
    connect(this, &MainWindow::start_proxy, tc_proxy, &mainClass::main_thread);
    connect(tc_proxy, &mainClass::debug_msg, this, &MainWindow::print_debug_msg);
    connect(tc_proxy, &mainClass::start_single_connect, this, &MainWindow::create_single_connect);
    connect(tc_proxy, &mainClass::error_msg, this, &MainWindow::error_handle);
    connect(tc_proxy, &mainClass::important_msg, this, &MainWindow::print_important_message);
    connect(this, &MainWindow::start_proxy, dns_trans, &dns::dns_trans);
    connect(dns_trans, &dns::debug_msg, this, &MainWindow::print_debug_msg);
    connect(dns_trans, &dns::error_msg, this, &MainWindow::error_handle);
    connect(dns_trans, &dns::important_msg, this, &MainWindow::print_important_message);
    log_file = open("log", O_CREAT|O_WRONLY, S_IRWXU);
    tc_proxy_thread.start();
    dns_trans_thread.start();
}

MainWindow::~MainWindow()
{
    ::close(log_file);
    delete ui;
}

void MainWindow::on_pushButton_toggled(bool checked)
{
    if (checked){

        QStringList tmp = ui->website->text().split('|');
        arg.website_list = new char*[tmp.size()];
        arg.website_num = tmp.size();
        for (int i = 0;i < tmp.size(); i++){
            arg.website_list[i] = new char[tmp.at(i).length() + 1];
            memcpy(arg.website_list[i], tmp.at(i).toStdString().c_str(), tmp.at(i).length() + 1);
        }
        tmp = ui->client_IP->text().split('|');
        arg.client_ip_list = new char*[tmp.size()];
        arg.client_ip_num = tmp.size();
        for (int i = 0;i < tmp.size(); i++){
            arg.client_ip_list[i] = new char[tmp.at(i).length() + 1];
            memcpy(arg.client_ip_list[i], tmp.at(i).toStdString().c_str(), tmp.at(i).length() + 1);
        }

        arg.port = ui->listen_port->text().toUShort();
        arg.method_banned[0] = ui->GET->isChecked();
        arg.method_banned[1] = ui->HEAD->isChecked();
        arg.method_banned[2] = ui->POST->isChecked();
        arg.method_banned[3] = ui->PUT->isChecked();
        arg.method_banned[4] = ui->DELETE->isChecked();
        arg.method_banned[5] = ui->CONNECT->isChecked();
        arg.method_banned[6] = ui->OPTIONS->isChecked();
        arg.method_banned[7] = ui->TRACE->isChecked();
        arg.method_banned[8] = ui->PATCH->isChecked();
        arg.file_type[0] = ui->pdf->currentIndex();
        arg.file_type[1] = ui->xls->currentIndex();
        arg.file_type[2] = ui->doc->currentIndex();
        arg.black_or_white = ui->radioButton->isChecked();
        for (int i = 0;i < 3; i++){
            if (arg.file_type[i] == 2){
                if (file_names[i].isEmpty()) {
                    QMessageBox msgBox;
                    msgBox.setText("Please choose a file.");
                    msgBox.exec();
                    ui->pushButton->setChecked(false);
                    return;
                }
                arg.file_names[i] = new char[file_names[i].length() + 1];
                memcpy(arg.file_names[i], file_names[i].toStdString().c_str(), file_names[i].length() + 1);
                arg.fd[i] = open(arg.file_names[i], O_RDONLY);
                arg.nSize[i] = lseek(arg.fd[i], 0, SEEK_END);
                if (arg.nSize[i] == -1) {
                    QMessageBox msgBox;
                    msgBox.setText("Cannot read this file.");
                    msgBox.exec();
                    ui->pushButton->setChecked(false);
                    return;
                }
            }
        }
        //pass argument to dns thread
        std::string tmp2 = ui->lan_ip->text().toStdString();
        memcpy(dns_trans->lan_ip, tmp2.c_str(), tmp2.size() + 1);
        tmp2 = ui->wan_ip->text().toStdString();
        memcpy(dns_trans->wan_ip, tmp2.c_str(), tmp2.size() + 1);
        tmp2 = ui->dns_ip->text().toStdString();
        memcpy(dns_trans->dns_ip, tmp2.c_str(), tmp2.size() + 1);
        arg.flag = true;
        emit start_proxy();
    }
    else {
        arg.flag = false;
        for (int i = 0;i < arg.website_num;i++){
            delete [] arg.website_list[i];
            arg.website_list[i] = nullptr;
        }
        delete [] arg.website_list;
        for (int i = 0;i < 3;i++){
            delete [] arg.file_names[i];
            arg.file_names[i] = nullptr;
            file_names[i].clear();
        }
        for (int i = 0;i < arg.client_ip_num;i++){
            delete [] arg.client_ip_list[i];
            arg.client_ip_list[i] = nullptr;
        }
        delete [] arg.client_ip_list;
        arg.client_ip_list = nullptr;
    }
}

void MainWindow::print_debug_msg(QString msg)
{//print debug message
    ui->textEdit->append(msg);
    std::string s = msg.toStdString();
    write(log_file, s.c_str(), msg.length());
    write(log_file, "\n", 1);
}

void MainWindow::error_handle(QString msg)
{//print error message on a new window and terminate the program
    QMessageBox msgBox;
    msgBox.setText(msg);
    msgBox.exec();
    ui->pushButton->setChecked(false);
}

void MainWindow::print_important_message(QString msg)
{
    ui->textEdit_2->append(msg);
}

void MainWindow::create_single_connect(int clifd){
    singleConnect* single_connect = new singleConnect;
    single_connect_threads<<single_connect;
    connect(single_connect, &singleConnect::debug_msg, this, &MainWindow::print_debug_msg);
    connect(single_connect, &singleConnect::finished, single_connect, &singleConnect::deleteLater);
    connect(single_connect, &singleConnect::finished, this, &MainWindow::single_connect_destroy);
    connect(single_connect, &singleConnect::important_msg, this, &MainWindow::print_important_message);
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
    ui->textEdit->append(QString("File \"%1\" is added.").arg(file_names[0]));
}

void MainWindow::on_pushButton_xls_clicked()
{
    file_names[1] = QFileDialog::getOpenFileName(this,
                    tr("choose file"), "/home/hhjimhhj/build-trnsprnt-proxy-Desktop_Qt_5_13_1_GCC_64bit-Debug/files", tr("*.xls *.xlsx"));
    ui->textEdit->append(QString("File \"%1\" is added.").arg(file_names[1]));
}

void MainWindow::on_pushButton_doc_clicked()
{
    file_names[2] = QFileDialog::getOpenFileName(this,
                    tr("choose file"), "/home/hhjimhhj/build-trnsprnt-proxy-Desktop_Qt_5_13_1_GCC_64bit-Debug/files", tr("*.doc *.docx"));
    ui->textEdit->append(QString("File \"%1\" is added.").arg(file_names[2]));
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
