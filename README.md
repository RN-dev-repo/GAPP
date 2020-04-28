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

    --kernel_stack        - Show kernel stack traces of the critical paths

Optional arguments explained
1. -t 		: Threshold - Number of active threads when profiling should start
   The default value of the threshold is 'n/2', where 'n' is the total number of threads. For example, if the application creates 16        threads, by default, tracing happens if the number of active threads during execution is less than or equal to 8.
   
   We can specify an absolute value for the threshold with the '-t' switch. For example, if we want to find code sections that execute      with 4 or less number of threads, run GAPP as:
   python GAPP.py -x /a/b/foo -t 4
 
2. --process_only: Trace only processes in the application (Omit threads)
3. --threads_only: Trace only threads in the application (Omit processes)
4. --trace-lib   : Include stack traces triggered from dynamic shared libraries (You will get full stack trace only if the libraries are                    compiled with frame pointers)
5. --kernel_stack: Display kernel stack traces of the critical paths. This helps to identify bottlenecks caused by hardware events.

For example, 

python GAPP.py -x /home/myHome/foo -f 999 -d 20 --threads-only --trace-lib

will profile only threads in '/home/myHome/foo', with a sampling frequency of approximately 1 ms and print stack traces of upto a depth of 20, including those from dynamic libraries.

Sensitivity of GAPP to input parameters
---------------------------------------
In this section, we evaluate GAPP's behaviour for different values of input parameters, based on the experiments performed on chosen applications.

**1. Threshold - N_min**

For the experiments conducted, the threshold N_min wass set to n/2, where n is the total number of threads in the application. With a lower threshold value of n/4,the number of critical stack traces decreased. However, the critical functions and lines of code remained the same for the applications evaluated. A lower N_min will correctly pinpoint more ‘extreme’ bottlenecks, but is likely to miss situations where there is more modest loss of parallelism.

We have found that smaller values of Nmin tend to identify bottlenecks caused by synchronization primitives such as locks quite well.

**2. Sampling period** 

The sampling probe was set up with a period of Δt = 3ms for the experiments conducted. This was chosen as it was around half the average time-slice duration, which will result in around two additional sample probe points for every time-slice, on average. Reducing Δt to 1 ms did not produce any observable change in the bottleneck locations identified, but increased the frequency of bottleneck functions and lines of code, making them conspicuous. This change was more noticeable with applications that generated a limited number of stack trace. With Δt = 1 ms, there was only a marginal increase in the average overhead; from 4% to 5%.

With a lower sampling rate of 10 msec, even though the critical functions and lines of code remained the same, sometimes the order of bottleneck functions changed as there were fewer samples from smaller functions.

**3. Size of the ring buffer** 
The default size of the ring buffer is set as 8 pages by eBPF. With a sampling period Δt = 3ms, three applications, viz. Dedup, Facesim and Streamcluster caused the ring buffer to overflow. To prevent overflow, the buffer size had to be increased to 256, 16 and 4096 pages respectively for each of these applications. This increased the memory usage of GAPP to 372 MB, 118 MB and 2.8 GB respectively for these applications. However, it was observed that even with lost samples, the results remained the same as those generated with the increased buffer sizes. This is because samples are generated only from bottlenecks, and the more  frequent/ longer the bottleneck, the more samples are generated.

To limit the memory usage, we have set the buffer size to 64 pages, which resulted in a maximum memory overhead of
782MB, for Streamcluster. However, this parameter, which should be a power of 2, is also configurable by the user through the command line argument, -d.
