#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <QMessageBox>
#include "tc-proxy.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr, int argc = 0, char** argv = nullptr);
    ~MainWindow();

private slots:

    void on_pushButton_toggled(bool);
    void print_debug_msg(QString);
    void create_single_connect(int);
    void single_connect_destroy();

    void on_pushButton_pdf_clicked();

    void on_pushButton_xls_clicked();

    void on_pushButton_doc_clicked();

    void on_pdf_currentIndexChanged(int);

    void on_xls_currentIndexChanged(int);

    void on_doc_currentIndexChanged(int);
    void error_handle(QString);
    void print_important_message(QString);

private:
    Ui::MainWindow *ui;
    QThread tc_proxy_thread;
    QThread dns_trans_thread;
    mainClass* tc_proxy;
    dns* dns_trans;
    QVector<QThread*> single_connect_threads;
    QString file_names[3];
    int log_file;
signals:
    void* start_proxy();
    void* close_proxy();
    void* single_connect_start(int);

};


#endif // MAINWINDOW_H
