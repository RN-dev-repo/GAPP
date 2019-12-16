# GAPP
Generic Automatic Parallel Profiler
-----------------------------------

GAPP is a profiler to detect serialization bottlenecks in parallel Linux applications.  It works by tracing kernel context switch events by kernel probes managed using the extended Berkeley Packet Filter (eBPF) framework. It has been tested on multi-threaded and MPI C/C++ applications.

Pre-requisites
------------
1. Linux kernel version >= 4.9
2. BCC - BPF Compiler Collection
   https://github.com/iovisor/bcc/blob/master/INSTALL.md
3. Binutils
   https://www.gnu.org/software/binutils/
4. The application should be compiled with compiler options -fno-omit-frame-pointer, -fno-pie, and linker options -no-pie.
   
How to use GAPP
---------------
1. Download GAPP

2. Switch to super user

	2.1. Run GAPP in a terminal

3. Run the application to be traced in a different terminal

4. Teminate GAPP by hitting \<Ctrl\-C\>.
  If there are samples left in the buffer while hitting \<Ctrl\-C\>, you might not get instant results. You will have to wait till all       samples are processed.

Running and Customizing GAPP
----------------
GAPP allows customizing its execution through several command line arguments.

1. To see the options provided:

    python GAPP_thread_process.py -h
  
    usage: GAPP_thread_process.py [-h] -x <Path to executable> [-t <Threshold>]
                                [-f <Sampling Frequency>] [-d <Stack Depth>]
                                [-b <Ring buffer Size>] [--threads_only]
                                [--process_only] [--trace_lib]

2. Mandatory arguments:

    -x <Path to executable> - Absolute path to the executable file to be profiled.

3. Optional arguments:

    -h, --help            - show this help message and exit
    
    -t <Threshold>        - Number active threads to trigger stack trace. Default = total no. of threads/2
  
    -f <Sampling Frequency>
                          - Sampling frequency in Hz. Default = 333Hz (equivalent to 3 ms)
  
    -d <Stack Depth>      - Maximum Stack depth for stack unwinding. Default = 10
  
    -b <Ring buffer Size>
                          - Number of pages to be allocated for the ring buffer (should be power of 2), Default = 64.
  
    --threads_only        - Trace threads alone
    
    --process_only        - Trace processes alone
    
    --trace_lib           - Include library paths in tracing


Optional arguments explained
1. -t 		: Threshold - Number of active threads when profiling should start
   The default value of the threshold is 'n/2', where 'n' is the total number of threads. For example, if the application creates 16        threads, by default, tracing happens if the number of active threads during execution is less than or equal to 8.
   
   We can specify an absolute value for the threshold with the '-t' switch. For example, if we want to find code sections that execute      with 4 or less number of threads, run GAPP as:
   python GAPP.py -x /a/b/foo -t 4
 
2. --process_only: Trace only processes in the application (Omit threads)
3. --threads_only: Trace only threads in the application (Omit processes)
4. --trace-lib   : Include stack traces triggered from dynamic shared libraries (You will get full stack trace only if the libraries are                    compiled with frame pointers)

For example, 

python GAPP.py -x /home/myHome/foo -f 999 -d 20 --threads-only --trace-lib

will profile only threads in '/home/myHome/foo', with a sampling frequency of approximately 1 ms and print stack traces of upto a depth of 20, including those from dynamic libraries.
