# ipt_TRASH

a simple module for iptables to defend real connection DDoS attack. (synproxy is better for syn-flood.)

it modify tcp e.g. psh packet to rst, so the server will close the connection while it's client waitting for timeout.

build
======

need package `iptables-devel`,`kernel-headers` and `kernel-devel`

    $ make
    $ sudo make install
    $ sudo insmod ipt_TRASH.ko

Examples
==========

1.To protect a tcp server
------------------------------------

    $ sudo iptables -A INPUT -p tcp --dport 61234 -m state --state NEW -m recent --update --seconds 30 --hitcount 30 --name trash --mask 255.255.255.0 --rsource -j TRASH --action continue
    $ sudo iptables -A INPUT -p tcp --dport 61234 -m state --state NEW -m recent --set --name trash --mask 255.255.255.0 --rsource -j ACCEPT

2.To protect a web server
----------------------------------------

    $ sudo iptables -A INPUT -p tcp --dport 80 -m string --string "host: test.example.com" --algo kmp --to 1480 -m recent --update --seconds 60 --hitcount 120 --name web --mask 255.255.255.0 --rsource -j TRASH --action continue
    $ sudo iptables -A INPUT -p tcp --dport 80 -m string --string "host: test.example.com" --algo kmp --to 1480 -m recent --set --name web --mask 255.255.255.0 --rsource -j ACCEPT


