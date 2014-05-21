etherterm
=========

Serial Terminal that uses I2SE specific broadcast ethernet packets



usage
-----

(only tested for ubuntu 12.04 and 13.10)

 - open the project in QtCreator
 - comile the application
 - cd to the release or debug folder, dependion on how you compiled
 - give the application permissions for capturing packets on ethernet interfaces: sudo setcap cap_net_raw,cap_net_admin+eip etherterm
 - run the application as normal user
