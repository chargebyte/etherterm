#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QSocketNotifier>
#include "QtNetwork/QNetworkInterface"


QString MainWindow::getMacAddress()
{
    foreach(QNetworkInterface interface, QNetworkInterface::allInterfaces())
    {
        // Return only the first non-loopback MAC Address
        if (!(interface.flags() & QNetworkInterface::IsLoopBack))
            return interface.hardwareAddress();
    }
    return QString("00:00:00:00:00:00");
}

QByteArray MainWindow::get_data_from_packet(QByteArray packet, uint offset, uint length)
{
    uint i;
    //TODO: offset+length makes i overflow, fix that
    QByteArray data = QByteArray();
    for (i = offset; i<offset+length;i++){
            data.append(packet[i]);
    }

    return(data);
}

void MainWindow::packet_callback( uchar *self, const pcap_pkthdr *header, const uchar *pdata )
{
    QByteArray homeplug_mtype = QByteArray();
    homeplug_mtype.append(0x88);
    homeplug_mtype.append(0xE1);

    QByteArray i2se_serial_over_mme_ind_mmtype = QByteArray();
    i2se_serial_over_mme_ind_mmtype.append((char)0x06);
    i2se_serial_over_mme_ind_mmtype.append(0xA0);


    MainWindow *mainwindow = reinterpret_cast<MainWindow *>(self);
    fprintf(stderr, "packet_callback() entry\n");

    QByteArray mme = QByteArray((char*) pdata, (int)(header->len));

    QByteArray sender = get_data_from_packet(mme, OFFSET_OSA, LENGTH_OSA);
    QByteArray mtype = get_data_from_packet(mme, OFFSET_MTYPE, LENGTH_MTYPE);

    //drop packet, it is not for us
    if (!mtype.contains(homeplug_mtype)){
        return;
    }

    QByteArray mmv = get_data_from_packet(mme, OFFSET_MMV, LENGTH_MMV);
    QByteArray mmtype = get_data_from_packet(mme, OFFSET_MMTYPE, LENGTH_MMTYPE);

    //drop packet, it is not for us
    if (!mmtype.contains(i2se_serial_over_mme_ind_mmtype)){
        return;
    }

    QByteArray oui = get_data_from_packet(mme, OFFSET_OUI, LENGTH_OUI);
    QByteArray mme_subver = get_data_from_packet(mme, OFFSET_MME_SUBVER, LENGTH_MME_SUBVER);
    QByteArray net = get_data_from_packet(mme, OFFSET_NET, LENGTH_NET);
    QByteArray payl_len = get_data_from_packet(mme, OFFSET_PAYL_LEN, LENGTH_PAYL_LEN);

    uint payl_len_int = payl_len[0]*10 + payl_len[1];

    fprintf(stderr,"payload length = %d", payl_len_int);

    QByteArray seq_num = get_data_from_packet(mme, OFFSET_SEQ_NUM, LENGTH_SEQ_NUM);
    QByteArray payload = get_data_from_packet(mme, OFFSET_PAYLOAD, payl_len_int);

    QByteArray display_text = QByteArray();
    display_text.append("incoming packet from: ");
    display_text.append(sender.toHex());
    display_text.append(" -> ");
    display_text.append(payload);

    mainwindow->ui->textBrowser->append(display_text);
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

   this->seq_counter = 0;
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

    uint plainbytes_len = plainbytes.size();

    QByteArray packet = QByteArray();
    packet.append(0xff);packet.append(0xff);packet.append(0xff);packet.append(0xff);packet.append(0xff);packet.append(0xff);//ODA
    QString mac = getMacAddress().remove(":");
    bool ok;
    qlonglong mac_longlong = mac.toULongLong(&ok, 16);
    QByteArray mac_byte = QByteArray();
    mac_byte.append((mac_longlong & 0xff0000000000) >> (5*8));
    mac_byte.append((mac_longlong & 0x00ff00000000) >> (4*8));
    mac_byte.append((mac_longlong & 0x0000ff000000) >> (3*8));
    mac_byte.append((mac_longlong & 0x000000ff0000) >> (2*8));
    mac_byte.append((mac_longlong & 0x00000000ff00) >> (1*8));
    mac_byte.append((mac_longlong & 0x0000000000ff) >> (0*8));
    packet.append(mac_byte);//OSA
    packet.append(0x88);packet.append(0xE1);//MTYPE HomePlug
    packet.append(0x01);//MMV
    packet.append(0x06); packet.append(0xA0);//MMTYPE
    packet.append((char)0x00);packet.append((char)0x00);//FMI
    packet.append((char)0x00);packet.append(0x01);packet.append(0x87);//OUI I2SE
    packet.append((char)0x00);//MME_SUBVER
    packet.append((char)0x00);packet.append((char)0x01);//NET
    packet.append((plainbytes_len & 0xff00) >> 8);packet.append((plainbytes_len & 0xff));//PAYL_LEN
    packet.append(this->seq_counter++);//SEQ_NUM = 0
    packet.append(plainbytes);//PAYLOAD
    while(packet.size() < 64){
        packet.append((char)0x00);
    }
    pcap_sendpacket(deviceHandle, (u_char*)packet.data(), packet.size());

    ui->txtSend->clear();
}
