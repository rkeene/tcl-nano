Tcl Nano
========

[Nano](https://nano.org)
------------------------
Nano is a low-latency payment platform that requires minimal resources; making Nano ideal for peer-to-peer transactions.

[Tcl](https://www.tcl-lang.org/)
--------------------------------
Tcl (Tool Command Language) is a very powerful but easy to learn dynamic programming language, suitable for a very wide range of uses, including web and desktop applications, networking, administration, testing and many more. Open source and business-friendly, Tcl is a mature yet evolving language that is truly cross platform, easily deployed and highly extensible.

Tcl Nano
--------
Tcl Nano implements a few different facets of Nano in Tcl, as well as allows
for interoperating with other Nano implementations.

   - [Downloads](/wiki/Downloads)
   - [Manual](/wiki/Manual)

Dependencies
------------
Tcl Nano depends on few other packages:

   - A C compiler (such as _gcc_)
   - A POSIX shell (such as _bash_)
   - The [Tcl interpreter](https://www.tcl-lang.org/)
   - The Tcl package [json](https://core.tcl.tk/tcllib/dir?ci=trunk&name=modules/json&type=tree)
   - The Tcl package [json::write](https://core.tcl.tk/tcllib/dir?ci=trunk&name=modules/json&type=tree)

The following optional dependencies should also be available (some features may not be
available without these packages):

   - The Tcl package [ip](https://core.tcl.tk/tcllib/dir?ci=trunk&name=modules/dns&type=tree)
   - The Tcl package [dns](https://core.tcl.tk/tcllib/dir?ci=trunk&name=modules/dns&type=tree)
   - The Tcl package [defer](https://core.tcl.tk/tcllib/dir?ci=trunk&name=modules/defer&type=tree)
   - The Tcl package [lmdb](https://github.com/ray2501/tcl-lmdb)
   - The Tcl package [udp](http://tcludp.sourceforge.net/)
   - The Tcl package [tclreadline](http://tclreadline.sourceforge.net/)

On a Debian system you should be able to do the following:

```
$ sudo apt install -y tcl8.6 tcllib tcl-udp tcl-tclreadline
```
