#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    
private slots:
    void on_btnSend_clicked();
    void dataAvailable();

private:
    Ui::MainWindow *ui;
    pcap_t *deviceHandle;
    static void packet_callback( uchar *self, const pcap_pkthdr *header, const uchar *pdata );

};

#endif // MAINWINDOW_H
