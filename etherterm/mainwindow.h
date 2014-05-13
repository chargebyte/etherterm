#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"

#define OFFSET_ODA   0
#define LENGTH_ODA   6
#define OFFSET_OSA   OFFSET_ODA + LENGTH_ODA
#define LENGTH_OSA   6
#define OFFSET_MTYPE OFFSET_OSA + LENGTH_OSA
#define LENGTH_MTYPE 2
#define OFFSET_MMV   OFFSET_MTYPE + LENGTH_MTYPE
#define LENGTH_MMV   1
#define OFFSET_MMTYPE OFFSET_MMV + LENGTH_MMV
#define LENGTH_MMTYPE 2
#define OFFSET_FMI    OFFSET_MMTYPE + LENGTH_MMTYPE
#define LENGTH_FMI    2
#define OFFSET_OUI    OFFSET_FMI + LENGTH_FMI
#define LENGTH_OUI    3
#define OFFSET_MME_SUBVER OFFSET_OUI + LENGTH_OUI
#define LENGTH_MME_SUBVER 1
#define OFFSET_NET    OFFSET_MME_SUBVER + LENGTH_MME_SUBVER
#define LENGTH_NET    2
#define OFFSET_PAYL_LEN OFFSET_NET + LENGTH_NET
#define LENGTH_PAYL_LEN 2
#define OFFSET_SEQ_NUM OFFSET_PAYL_LEN + LENGTH_PAYL_LEN
#define LENGTH_SEQ_NUM 1
#define OFFSET_PAYLOAD OFFSET_SEQ_NUM + LENGTH_SEQ_NUM

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
    static QByteArray get_data_from_packet(QByteArray packet, uint offset, uint length);
    static QString getMacAddress();

    char seq_counter;
};

#endif // MAINWINDOW_H
