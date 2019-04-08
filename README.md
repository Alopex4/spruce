# Spruce
> Spruce is a versatile network sniffer

Spruce is an mix network sniffer, it can monitor both 
your local network node flow also LAN  network nodes.  
Through ARP scan you can gather LAN nodes information 
swift and effortless, not only that the export format
is very rich.  

Like other sniffer, you can use spruce to capture 
packages and analysis them by one click. After capture
 finish you can save the package to `.pcap` format or 
 reopen it under spruce or other sniffer you like to 
 further processing.

Spruce support some intimate function to users. You can
`right click` your scan item to query some useful information
like `IP address belongs` and `Computer terms(protocol) query`
Of course, you can use this function individual or simultaneously
under capture packages. You can gather the figure after
capture stop, those figure is a visible resource make you
understand what packets you capture and how the network flow
during this period.
 

![start screen](https://raw.githubusercontent.com/Alopex4/spruce/master/shoot/start.png?token=Ac0AsBXS3M5olE-wNzQwT2eLYV53Nw_yks5cqxhxwA%3D%3D)

## Installation

OS X & Linux:

```sh
pip3 install spurce-sniffer
```

## Usage example

```sh
sudo spruce-sniffer
```

Make sure under root privilege to run the software.

## Redistribute the software is permissible

You can built the software from source code to frozen distribute version.

```sh
# Example of `pyinstaller`

cd spruce
pyinstaller spruce.py   \
--hidden-import prettytable \
--hidden-import scapy   \
--hidden-import request \
--hidden-import ctype   \
--hidden-import netifaces   \
--add-data icon/\*.ico:icon \
--add-data static/help.html:static \
--add-data static/oui.csv:static 

```

## Release History

* 0.1.0
    * The first proper release
    * date: Mon Apr  8 14:27:17 CST 2019

## Meta

alopex cheung – alopex4@163.com

Distributed under the `MIT` license. See ``LICENSE`` for more information.

[spruce under license](https://github.com/Alopex4/spruce/blob/master/LICENSE)

## Contributing

1. Fork it (<https://github.com/Alopex4/spruce>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request
