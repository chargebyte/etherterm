#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QSocketNotifier>


void MainWindow::packet_callback( uchar *self, const pcap_pkthdr *header, const uchar *pdata )
{
    MainWindow *mainwindow = reinterpret_cast<MainWindow *>(self);
    fprintf(stderr, "packet_callback() entry\n");
    fprintf(stderr, "packet = %X\n", pdata[0]);
    fprintf(stderr, "header.len=%d", header->len);
    fprintf(stderr, "packet_callback() after printing packet\n");
    mainwindow->ui->textBrowser->append(QString("test"));
    fprintf(stderr, "dataAvailable() exit\n");
}


void MainWindow::dataAvailable()
{
    fprintf(stderr, "dataAvailable() entry\n");
    int retval = pcap_dispatch( deviceHandle, -1 /* all packets*/, (pcap_handler)&MainWindow::packet_callback, (uchar *)this);
    fprintf(stderr, "number of dispatched packets or error code: %d", retval);
    fprintf(stderr, "dataAvailable() exit\n");
}



MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);


    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    }
    printf("Device: %s\n", dev);

    deviceHandle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (deviceHandle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    }

    pcap_set_promisc(deviceHandle,1);                                               //set Promisc-Mode
    pcap_activate(deviceHandle);                                                    //starts the session


    struct bpf_program pgm;

    if((pcap_compile(deviceHandle, &pgm, "ether proto 0x88E1", 1, PCAP_NETMASK_UNKNOWN)==-1))
    {
      pcap_perror(deviceHandle, "Compile");
    }

    if(pcap_setfilter(deviceHandle,&pgm) == -1)
    {
      fprintf(stderr,"Error setting filter\n");
    }

    int fd = pcap_get_selectable_fd(deviceHandle);
    QSocketNotifier *notifier = new QSocketNotifier( fd, QSocketNotifier::Read, this );
    connect( notifier, SIGNAL(activated(int)), this, SLOT(dataAvailable()) );
    notifier->setEnabled(true);

}


MainWindow::~MainWindow()
{
    delete ui;
    pcap_close(deviceHandle);
}

void MainWindow::on_btnSend_clicked()
{
    QString plaintext = ui->txtSend->toPlainText();
    QByteArray plainbytes = plaintext.toAscii();
    pcap_sendpacket(deviceHandle, (u_char*)plainbytes.data(), plainbytes.size());
}
