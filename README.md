# modificacion del paquete arp-scan
# Se ha añadido la opcion G <i> o --grx=<i>, donde <i> es un entero entre 1 y 255
# Cuando usamos arp-scan para buscar un listado de host, tenemos la opcion de asignar ip_source = ip_dest
# con -arpspa=dest, pero en los router de la Diputacion de Granada no funciona esta opcion.
# Esta opcion implementada toma el valor de una ip_dest y crea un ip_source con la terminacion <i>.
# Ejem.  Tenemos un archivo llamado "listado" con las ip que queremos buscar que contiene 192.168.1.1 y 10.100.1.254
# cat listado| sudo arp-scan --file=- -x -q --grx=55
# Esto buscará la ip_dest=192.168.1.1 con ip_source=192.168.1.55 y la ip_dest=10.100.1.254 con ip_source=10.100.1.55
# Nuestro caso lo usamos para buscar en que red nos encontramos de la wan de la Diputacion, conseguimos autoconfigurar el puesto de red en menos de 2 segundos
# buscando en 180 subredes

# arp-scan

[![Build Status](https://secure.travis-ci.org/royhills/arp-scan.png)](http://travis-ci.org/royhills/arp-scan)
[![Coverage Status](https://coveralls.io/repos/royhills/arp-scan/badge.png?branch=master)](https://coveralls.io/r/royhills/arp-scan?branch=master)

The ARP scanner

## Table of Contents
- [Installation](#installation)
- [Documentation](#documentation)

Installation
------------

arp-scan uses the standard GNU automake and autoconf tools, so the typical installation process is:

- Run ```git clone https://github.com/royhills/arp-scan.git``` to obtain the project source code
- Run ```cd arp-scan``` to enter source directory
- Run ```autoreconf --install``` to generate a viable ./configure file
- Run ```./configure``` to generate a makefile for your system
- Run ```make``` to build the project
- Optionally run ```make check``` to verify that everything works as expected
- Run ```make install``` to install (you'll need root or sudo for this part)

You will need GNU automake and autoconf, the make utility, an ANSI C compiler (for example gcc or clang), the development header files and libraries, and libpcap version 1.0 or later.

If you want to run the Perl scripts arp-fingerprint, get-oui and get-iab, you
will need to have the Perl interpreter installed.  These scripts were tested
on Perl 5.8 and 5.10, but will probably run on other versions of Perl 5 as well.
In addition, for get-oui and get-iab, you will need the LWP::UserAgent Perl
module.

You can pass various options to "configure" to control the build and
installation process.  See the file INSTALL for more details.

arp-scan is known to compile and run on the following platforms:

 - Linux
 - FreeBSD
 - OpenBSD
 - NetBSD
 - DragonflyBSD
 - MacOS X
 - Solaris

All platforms use libpcap (http://www.tcpdump.org/) to send the ARP packets
and receive the responses.

The only peice of the code that is implementation-specific is the function to
obtain the interface MAC address. This uses Packet Socket on Linux, BPF on
BSD and DLPI on Solaris.

Documentation
-------------

The primary source of documentation is the arp-scan wiki at
http://www.nta-monitor.com/wiki/

For usage information, including details of all the options, use:

```arp-scan --help```

For more detailed documentation, see the manual pages: arp-scan(1),
arp-fingerprint(1), get-iab(1), get-oui(1) and mac-vendor(5).
