#!/usr/bin/python

#Sorts based on top 50 CMetric, all callPaths - CMetric
#, all call paths - call path count and all samples

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from bcc import BPF
import sys
import ctypes as ct # For mapping the 'C' structure to Python
import argparse	#For parsing command line arguments
import datetime
import os
import operator
import subprocess
import re

# arg validation
def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival
	
def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival

parser = argparse.ArgumentParser(description="Generates stack traces for critical code sections")

parser.add_argument("-x", metavar="<Path to executable>", dest = "targetPath", required = True, help = "Full path to the executable file to be profiled - Required")
parser.add_argument("-t", metavar="<Threshold>", dest = "threshold", type = positive_int, required = False, help = "Number active threads to trigger stack trace. Default = total no. of threads/2" )
parser.add_argument("-f", metavar="<Sampling Frequency>", dest = "sample_freq", type = positive_int, required = False, help = "Sampling frequency in Hz. Default = 333Hz (equivalent to 3 ms)" )
parser.add_argument("-d", metavar="<Stack Depth>", dest = "stack_depth", type = positive_int, required = False, help = "Maximum Stack depth for stack unwinding. Default = 10" )
parser.add_argument("-b", metavar="<Ring buffer Size>", dest = "buffer", type = positive_int, required = False, help = "Number of pages to be allocated for the ring buffer, Default = 64" )

parser.add_argument("--threads_only", help = "Trace threads alone", action = "store_true")
parser.add_argument("--process_only", help = "Trace processes alone", action = "store_true")
parser.add_argument("--trace_lib", help = "Include library paths in tracing", action = "store_true")
parser.add_argument("--kernel_stack", help = "Get kernel stack traces", action = "store_true")

args = parser.parse_args()

# define BPF program
bpf_text = """

#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>
#include <linux/types.h>

//Structure to pass information from the kernel probe to the user probe
struct key_t {
    u32 tid;  //Thread ID
    u32 tgid; // Parent thread ID
    u64 cm;  //CMetric
    int source; // 0 - sampling, 1 - critical time slice, 2 - non-critical time slice
    int user_stackid;
    int kernel_stackid;
    u64 inst_ptr;
    int store_stackTop;
};

BPF_HASH(threadList, u32, u32);     //Stores threadIds of participating threads - Global
BPF_HASH(threadCount, u32, u32, 1); //Stores number of active threads - Global

BPF_HASH(tsp, u32, u64, 1);         //Stores timestamp of previous event

BPF_ARRAY(count, u32, 1);	    //Stores the total thread count (parent not included)

BPF_HASH(global_CM, u32, u64, 1);      //Keeps track of cumulative sum of CMetric - Global
BPF_PERCPU_ARRAY(local_CM, u64, 1); // To store the snapshot of global_CM when a thread is switched in
BPF_HASH(CM_hash, u32, u64);  // Criticality Metric hash map for each thread
BPF_HASH(GLOBAL_WT_TC, u32, u64,1); //Stores the cumulative sum of weighted thread Count - Global
BPF_PERCPU_ARRAY(LOCAL_WT_TC, u64,1); //Stores the snapshot of GLOBAL_WT_TC - CPU Local
BPF_PERCPU_ARRAY(inTS, u64, 1); //Store the time at which a thread was switched in - CPU Local
BPF_PERF_OUTPUT(events); //Buffer to write event details
BPF_STACK_TRACE(user_stacktraces, 4086);
BPF_STACK_TRACE(kernel_stacktraces, 4086);

/*sched_switch_args {
    // from /sys/kernel/debug/tracing/events/sched/sched_switch/format
    u64 __unused__;
    char prev_comm[16];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    pid_t next_pid;
    int next_prio;
};
*/

TRACEPOINT_PROBE(task, task_rename){

    u32 threadId, totalCount;
    char comm[16];
    u32 zero32 = 0, one = 1;

    int len = bpf_probe_read_str(&comm, sizeof(args->newcomm), args->newcomm);
    
    if(!len)
      return 0;

    //Compare the command argument with traced command
    if(PGM_FILTER){

      bpf_probe_read(&threadId, sizeof(threadId), &args->pid);
      threadList.insert(&threadId, &zero32); //Store the thread ID in the hash           startTracing.lookup_or_init(&threadId, &zero32);

      u32 *countVal = count.lookup_or_init(&zero32, &zero32);
      lock_xadd(countVal,1);
    }
    return 0;
}

TASK_NEWTASK

int do_perf_event(struct bpf_perf_event_data *ctx){

    u32 zero32 = 0;

    u32 threadId = bpf_get_current_pid_tgid();
    u32 *val = threadList.lookup(&threadId);
    if(!val)
        return 0;

    u32 *activeCount = threadCount.lookup(&zero32);
    if(!activeCount)
            {return 0;}

    u32 tempCount;
    bpf_probe_read(&tempCount, sizeof(tempCount), activeCount);

    u32 *totalThreadCount = count.lookup(&zero32);
    if(!totalThreadCount)
      return 0;

    u32 totalCount;
    bpf_probe_read(&totalCount, sizeof(totalCount), totalThreadCount);

    if( (tempCount <= STACK_FILTER) || tempCount ==1 ){
            
        struct key_t key = {};
        key.tid 	= bpf_get_current_pid_tgid();
        key.tgid	= bpf_get_current_pid_tgid()>>32;	
        key.cm		= 0;
        key.source	= 0;
        if(TRACE_THREADS_ONLY){
          key.inst_ptr	= PT_REGS_IP(&ctx->regs); //Get the instruction pointer
          events.perf_submit(ctx, &key, sizeof(key)); //Write details to the ring buffer			  
        }
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit){

  u32 zero32 = 0;
  //Get the current tid
  u32 threadId;
  bpf_probe_read(&threadId, sizeof(threadId), &args->pid);
  //Check if the thread ID belongs to the application
  u32 *val      = threadList.lookup(&threadId);
  if(!val)
    return 0;

  //Decrement the number of threads
  u32 *countVal = count.lookup(&zero32);
  if(!countVal)
    return 0; 
  //lock_xadd(countVal, -1);
  countVal -= 1;
  return 0;
}


TRACEPOINT_PROBE(sched, sched_wakeup){

  u32 targetID, zero32 = 0, status, one32 = 1;

  //Check if thread being woken up belongs to the application
  bpf_probe_read(&targetID, sizeof(targetID), &args->pid);
  u32 *list = threadList.lookup(&targetID);
  if (!list)
    return 0;		

  /////////////////////////////////////////////////////////////////////

  if(args->success){ //If waking was successful

    u32 *activeCount = threadCount.lookup(&zero32);
    if(!activeCount)
    {return 0;}
    u32 prev_tCount; //Local variable to store thread count
    bpf_probe_read(&prev_tCount, sizeof(prev_tCount), activeCount);

    //Increment thread count if thread was inactive
    bpf_probe_read(&status, sizeof(status), list);
    if(status == 0)
      lock_xadd(activeCount,1);

    //Set thread as active
    threadList.update(&targetID,&one32);
  }		
  return 0;		
}

//Tracepoint probe for the Sched_Switch tracepoint

TRACEPOINT_PROBE(sched, sched_switch){

  u32 one32=1, arrayKey=0, zero32=0;
  u32 *listVal, *listVal1;  //Pointers to entries in threadList map
  u32 next_pid, prev_pid;

  u64 zero64 = 0;

  //Copy data to BPF stack
  bpf_probe_read(&next_pid, sizeof(next_pid), &args->next_pid);
  bpf_probe_read(&prev_pid, sizeof(prev_pid), &args->prev_pid);

  //Look up thread ids in the list created by sys_clone()
  listVal1 = threadList.lookup(&next_pid);
  listVal = threadList.lookup(&prev_pid);

  u32 prev=0, next=0;
  if(listVal){
    bpf_probe_read(&prev, sizeof(prev),listVal);
    prev = 1;
  }

  if(listVal1){
    bpf_probe_read(&next, sizeof(next),listVal1);
    next = 1;
  }

  //Return if the switching threads do not belong to the application
  if( !prev && !next)
    return 0;

  //////////////////////////////////////////////////////////////////////

  //Calculate values common for all switching events

  u64 interval, intervalCM;

  u64 *oldTS = tsp.lookup_or_init(&arrayKey, &zero64);

  if(!oldTS)
  {return 0;}

  u64 tempTS;
  bpf_probe_read(&tempTS, sizeof(tempTS), oldTS); //Copy Old time from bpf map to local variable
  u64 newTS = bpf_ktime_get_ns();
  tsp.update(&arrayKey, &newTS);      //Update time stamp

  //The thread count is initialized to one as the first switch in event is always missed.
  u32 *ptr_threadCount = threadCount.lookup_or_init(&arrayKey, &one32);

  if(!ptr_threadCount)
  {return 0;}

  int prev_tc; //Temporary variable to store thread count for the  previous switching interval
  bpf_probe_read(&prev_tc, sizeof(prev_tc),ptr_threadCount);		

  if(newTS < tempTS)//Very rarely, event probes are triggered out of order, which are ignored
    return 0;

  if(tempTS==0 || prev_tc==0){ //If first event or no active threads in during the previous interval, prev interval = 0
    interval = 0;
  }

  else 
    interval = (newTS - tempTS); //Switching interval

  u64 *ptr_globalCM = global_CM.lookup_or_init(&arrayKey, &zero64);

  if(!ptr_globalCM)
    return 0;

  //Calculate the CMetric for previous interval and add it to global_CM
  if (interval != 0){
    intervalCM = interval/prev_tc;
    lock_xadd(ptr_globalCM, intervalCM);
  }

  //Calculate weighted thread count for previous interval
  u64 wt_threadCount = (interval) * prev_tc;
  u64 *g_wt_threadCount = GLOBAL_WT_TC.lookup_or_init(&arrayKey, &zero64);
  if(!g_wt_threadCount)
    return 0;
  lock_xadd(g_wt_threadCount, wt_threadCount); //Add to global weighted thread count

  //////////////////////////////////////////////////////////////////////

  //If previous thread was a peer thread
  if(prev){

    //Decrement active thread count only if thread switched out is not in RUNNING (0) state
    if(args->prev_state != TASK_RUNNING){

      if(prev_tc > 0 ){
        lock_xadd(ptr_threadCount, -1);
      }
      //Mark the thread as inactive in the threadList hash map
      threadList.update(&prev_pid,&zero32);
    }

    else
      //Mark the thread as active as thread is switched out to TASK_RUNNING state
      threadList.update(&prev_pid,&one32);	

    u64 temp;
    //Get updated CM
    bpf_probe_read(&temp, sizeof(temp),ptr_globalCM);

    //Get snapshot of global_CM which was stored in local_CM when prev_pid was switched in
    u64 *cpuCM = local_CM.lookup_or_init(&arrayKey, &zero64);

    if(!cpuCM)
    {return 0;}

    //Update the CM of the thread by adding the CM for the time slice
    u64 updateCM = temp - (*cpuCM);
    u64 *tCM = CM_hash.lookup_or_init(&prev_pid, &zero64);
    if(!tCM)
    {return 0;}
    *tCM = *tCM + updateCM;

    //Get LOCAL_WT_TC, the thread's weighted threadCount at the time it was switched in. 
    u64 *t_wt_threadCount;	
    t_wt_threadCount	= LOCAL_WT_TC.lookup_or_init(&arrayKey, &zero64);	
    if(!t_wt_threadCount)
    {return 0;}

    u64 temp_g_wt_threadCount, temp_t_wt_threadCount;

    bpf_probe_read(&temp_g_wt_threadCount, sizeof(temp_g_wt_threadCount), g_wt_threadCount);
    bpf_probe_read(&temp_t_wt_threadCount, sizeof(temp_t_wt_threadCount), t_wt_threadCount);    

    //Reset the per-CPU CMetric counter
    local_CM.update(&arrayKey, &zero64);      
    //Reset local weighted ThreadCount counter
    LOCAL_WT_TC.update(&arrayKey, &zero64);

    //Get time when this thread was switched in
    oldTS = inTS.lookup_or_init(&arrayKey, &zero64);
    if(!oldTS)
      return 0;

    u64 switch_in_time, timeSlice;	
    bpf_probe_read(&switch_in_time, sizeof(switch_in_time), oldTS);
    timeSlice = (newTS - switch_in_time);
    //Reset switch in time
    inTS.update(&arrayKey, &zero64);

    u32 *totalThreadCount = count.lookup(&zero32);
    if(!totalThreadCount)
      return 0;
    u32 totalCount;
    bpf_probe_read(&totalCount, sizeof(totalCount), totalThreadCount);

    //Calculate the average number of threads	
    u32 ratio = (temp_g_wt_threadCount - temp_t_wt_threadCount) / timeSlice;     

    struct key_t key = {};
    key.tid 	      = prev_pid;
    key.tgid	      = bpf_get_current_pid_tgid()>>32;	
    key.cm	      = updateCM;      

    if( (ratio <= STACK_FILTER || ratio == 1) && TRACE_THREADS_ONLY){ //If thread_avg < threshold and not parent thread

      key.user_stackid	= user_stacktraces.get_stackid(args, BPF_F_USER_STACK);
      if (GET_KERNEL_STACK)
        key.kernel_stackid= kernel_stacktraces.get_stackid(args, 0);
      key.source	= 1;       	
    }
    else{
      key.user_stackid = 0;
      key.source  = 2;
    }
    key.store_stackTop = ((prev_tc <= STACK_FILTER) || prev_tc == 1)? 1:0;
    if(TRACE_THREADS_ONLY)
      events.perf_submit(args, &key, sizeof(key));   
  }

  //Next thread is a peer thread

  if(next){

    //Get the previous state of this thread from the THREADLIST

    u32 tempNext;
    bpf_probe_read(&tempNext, sizeof(tempNext), listVal1);

    //If the thread was not in TASK_RUNNING state
    if(tempNext == 0){
      lock_xadd(ptr_threadCount, 1); //Increment the number of active threads	        	
    }
    threadList.update(&next_pid, &one32);	//Set the thread status to RUNNING state

    u64 temp;
    //Get updated CM and store it to the CPU counter
    bpf_probe_read(&temp, sizeof(temp),ptr_globalCM);
    local_CM.update(&arrayKey,&temp);

    //Store switch in time
    inTS.update(&arrayKey, &newTS);

    //Store the local cumulative weighted thread count
    u64 temp_g_wt_threadCount;
    bpf_probe_read(&temp_g_wt_threadCount, sizeof(temp_g_wt_threadCount), g_wt_threadCount);
    LOCAL_WT_TC.update(&arrayKey, &temp_g_wt_threadCount);
  }	
  return 0;
  }
  """
task_newtask_pgm = """TRACEPOINT_PROBE(task, task_newtask){

    u32 zero32=0;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    //We can also check for the parent id in the threadlist
    //But if the parent was created before starting tracing this can fail
    //So we check the command line instead

    //If application is being traced
    if(PGM_FILTER){
        u32 threadId;
        bpf_probe_read(&threadId, sizeof(threadId), &args->pid);
        u32 *val = threadList.lookup_or_init(&threadId, &zero32); //Store the thread ID in the hash

        u32 *countVal = count.lookup_or_init(&zero32, &zero32);
        lock_xadd(countVal,1);
    }
    return 0;
}"""

#Path to executable
targetPath = ""
#Executable name
pgmName = ""

#Segments for customizing the filters
task_newtask_probe = task_newtask_pgm
trace_threads_only = '1'
get_kernel_stack = '0'

if args.threads_only:
  trace_threads_only = 'key.tgid != key.tid'

if args.process_only:
  task_newtask_probe = ''

if args.kernel_stack:
  get_kernel_stack = '1'

#Get the path to target
if args.targetPath is not None:
  targetPath = args.targetPath.rstrip(os.sep)
  pgmName = os.path.basename(targetPath)

if pgmName is not None:
  pgm_filter = 'comm[0]==\'%c\' && comm[1]==\'%c\' && comm[2]==\'%c\' && comm[3]==\'%c\'' % (pgmName[0],pgmName[1], pgmName[2], pgmName[3])

if args.threshold is not None:
  stack_filter = '%d' % ( (args.threshold) )
else:
  stack_filter = 'totalCount/2'

if args.sample_freq is not None:
  freq = args.sample_freq
else:
  freq = 333

if args.stack_depth is not None:
  depth = args.stack_depth
else:
  depth = 10

if args.buffer is not None:
  buffer_size = args.buffer
else:
  buffer_size = 64

bpf_text = bpf_text.replace('TASK_NEWTASK', task_newtask_probe)
bpf_text = bpf_text.replace('PGM_FILTER', pgm_filter)
bpf_text = bpf_text.replace('STACK_FILTER', stack_filter)
bpf_text = bpf_text.replace('TRACE_THREADS_ONLY', trace_threads_only)
bpf_text = bpf_text.replace('GET_KERNEL_STACK', get_kernel_stack)

#Print the customized program
#print(bpf_text)
print ("\n\n---Press Ctrl-C to start post processing---")
# load BPF program
b = BPF(text=bpf_text)
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
              ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
              sample_freq=freq)

class Data(ct.Structure):
  _fields_ = [
             ("tid", ct.c_uint),
             ("tgid", ct.c_uint),
             ("cm", ct.c_ulonglong),
             ("source", ct.c_uint),
             ("user_stack_id", ct.c_int),
             ("kernel_stack_id", ct.c_int),
             ("inst_ptr", ct.c_ulonglong),
             ("store_stackTop", ct.c_int)]

user_stack_traces = b["user_stacktraces"]
kernel_stack_traces = b["kernel_stacktraces"]

sampleAddr = dict() #Stores addresses corresponding to samples
CMetric = dict() #Dictionary to store CMetric
CM_Entry = 1 #Number of CMetric entry
CMetric_sampleAddr = dict() # Stores the sample address for each Cmetric - to get line of code
CMetric_callPath   = dict() # Stores the call path for each CMetric
user_symbolMap     = dict() #Store symbols corresponding addresses
kernel_symbolMap   = dict() 
total_switch = 0
noSample     = 0

###############################################
#Function to trim the symbols of arguments
def trimSymbol(string_ret):

  if '[' in string_ret:
    symbol = (string_ret.rsplit('[',1))
    if '@' in symbol[0]:
      function = (symbol[0].split('@', 1)[0])
      string_ret = function + "()" + "[" + symbol[1]
      return string_ret
    else:
      string_ret = symbol[0].split('(',1)
      return string_ret[0]+'()['+ symbol[1]
  else:
    return string_ret.split('(',1)[0]+'()'
################################################
def getKernelStack(kernel_stack_id):

    kernel_call_path = ""
    kernel_flag = 0

    kernel_stack =[] if kernel_stack_id < 0 else \
                    kernel_stack_traces.walk(kernel_stack_id)
    #For each address in the stack trace, get the symbols and create call path

    for addr in kernel_stack:
      if addr in kernel_symbolMap:
        kernel_string_ret = kernel_symbolMap[addr]
      else:
        kernel_string_ret = b.ksym(addr)
        kernel_symbolMap[addr] = kernel_string_ret
      if kernel_flag == 0:
        kernel_call_path = kernel_call_path + (kernel_string_ret.split('+',1)[0]).strip("\n ' '")
        kernel_flag += 1
      else: #If not stack top address
        kernel_call_path = kernel_call_path + ("\n\t") + "<---" + (kernel_string_ret.split('+',1)[0]).strip("\n ' '")

    return kernel_call_path

################################################

def print_event(cpu, data, size):

    global CM_Entry #Unique id for stack traces
    global total_switch # Total number of context switches
    global noSample #Stores the number of switches without samples

    event = ct.cast(data, ct.POINTER(Data)).contents
    flag = 0
    user_call_path = ""
    kernel_call_path = ""
      
    if event.source == 0: #Sample data
      if event.inst_ptr in user_symbolMap:
        string_ret  = user_symbolMap[event.inst_ptr]
      else:
        #Map address to symbols
        string_ret = b.sym(event.inst_ptr, event.tgid, show_offset=False, show_module = True)
        string_ret = trimSymbol(string_ret)
        user_symbolMap[event.inst_ptr]=string_ret

      if "unknown" in string_ret:
          return

      #Add to list of samples for this thread ID         			
      if event.tid not in sampleAddr:
        sampleAddr[event.tid] = list()

      if (string_ret.find(pgmName) >= 0): # If address belongs to application address map
        sampleAddr[event.tid].append("0x" + format(event.inst_ptr, 'x'))			
      else:
        sampleAddr[event.tid].append(string_ret)
      return

    if event.source == 2: # Reset Sample array if time slice not critical	
      if event.tid in sampleAddr:
          sampleAddr[event.tid]=[]
      total_switch += 1
      return
                      
    if event.source == 1: #Critical Stack trace

      skip_stackTop = 0
      appl_addr = 0

      total_switch += 1
      user_stack =[] if event.user_stack_id < 0 else \
              user_stack_traces.walk(event.user_stack_id)	
      #For each address in the stack trace, get the symbols and create call path	
      for addr in user_stack:		
        if addr in user_symbolMap:
          string_ret  = user_symbolMap[addr]
        else:
          string_ret = b.sym(addr, event.tgid, show_offset=False, show_module = True)
          string_ret = trimSymbol(string_ret)
          user_symbolMap[addr]=string_ret

        if "unknown" in string_ret:
          if flag == 0:
              skip_stackTop = 1
          continue

        if (string_ret.find(pgmName) >= 0):  # If address belongs to application address map
          appl_addr = 1

        if appl_addr or args.trace_lib:
          if flag == 0: #Store top address of stack trace, if no samples				                                       
            if event.tid not in sampleAddr:
              sampleAddr[event.tid] = list()
            if len(sampleAddr[event.tid]) ==0 and event.store_stackTop == 1 and skip_stackTop ==0:
              noSample += 1
              if appl_addr:
                sampleAddr[event.tid].append("0xz" + format(addr, 'x'))
                
            user_call_path = user_call_path+ (string_ret.split('+',1)[0]).strip("\n ' '")
                              
          else: #If not stack top address
            user_call_path = user_call_path + "\n\t" + "<---" + (string_ret.split('+',1)[0]).strip("\n ' '")
  
          flag += 1			
          if flag==depth:	#Number of stack frames
            break

      if flag>0:

        if get_kernel_stack == '1':
          kernel_call_path = getKernelStack(event.kernel_stack_id)
        CMetric[CM_Entry] = event.cm	#Stores Cmetric of this critical stack trace
	#Stores sample addresses of this critical stack trace
        CMetric_sampleAddr[CM_Entry] = list(sampleAddr[event.tid])
        CMetric_callPath[CM_Entry] = (user_call_path, kernel_call_path) #Stores call path of this critical stack trace
        CM_Entry += 1
      
      sampleAddr[event.tid]=[]		
      return
		
#Function to execute for each event written to the ring buffer
b["events"].open_perf_buffer(print_event, page_cnt=buffer_size)

#To print criticality metric of each thread
threadCM = b.get_table("CM_hash")
sum = 0;
criticalSwitch      = dict()
criticalSwitch_allCM= dict()
criticalLine        = dict()
critLineSamples     = dict()
critLineSamples_all = dict()
critKernelPaths     = dict()
allFunction = dict()
allLines    = dict()
addrMap_fun = dict()
addrMap_line= dict()

def combine_Results(function, line, count, resultFunc, resultLine, tempFunc, tempLine):

    #resultFunc and resultLine are for displaying the 
    #critical functions and lines combining results of 
    #Top 10 critical paths
    if function:
      if function in resultFunc:
        resultFunc[function] += count
        if line in resultLine[function]:
          resultLine[function][line] += count
        else:
          resultLine[function][line] = count
          
      else:
        resultFunc[function] = count
        resultLine[function] = dict()
        resultLine[function][line] = count

      #tempFunc and tempLine are functions and lines of current critical path alone
      if function in tempFunc:
        tempFunc[function] += count
        if line in tempLine[function]:
          tempLine[function][line] += count
        else:
          tempLine[function][line] = count

      else:
        tempFunc[function] = count
        tempLine[function] = dict()
        tempLine[function][line] = count
    return

def combine_samples(addrList, resultFunc, resultLine):

  tempFunc = dict()
  tempLine = dict()
  function = ""
  line     = "" 
  addrStringList =[]
  addrCountList = []
  stackTopList = []
  
  for element, count in addrList.items():
    specialString = ""
    if "0x" in element:
      #'0xz' pattern in the address denotes this is a stack top address(return address)
      # not a sample address 
      if 'z' in element:
        specialString=" (StackTop)"
        #remove 'z'
        element = element.replace('z','')
      else:
        specialString = ""
      if element in addrMap_fun:
        function = addrMap_fun[element]
        line     = addrMap_line[element]
        #Add (StackTop) label to the line
        if specialString:
           line = line + specialString
        #Combine all samples for this path      
        combine_Results(function, line, count, \
                resultFunc, resultLine, tempFunc, tempLine);
      else:
        #Prepre to call addr2line
        addrStringList.append(element)
        addrCountList.append(count)
        if specialString:
          stackTopList.append(1)
        else:
          stackTopList.append(0)
        #result = str(subprocess.check_output(['addr2line', '-s', '-C', '-f', '-p', '-i', element, '-e', "/data/rn1115/cfd/test/IncNavierStokesSolver-g"], stderr=subprocess.STDOUT))
    else:
      #library functions
      function = element
      line = ""
      combine_Results(function, line, count, resultFunc, \
              resultLine, tempFunc, tempLine)
  #Map address to function name and line of code
  if addrStringList != []:
      cmd = ['addr2line', '-s', '-C', '-f', '-p']
      cmd.extend(addrStringList)
      cmdLast = ['-e', targetPath]
      cmd.extend(cmdLast)
      sourceLines = str(subprocess.check_output(cmd, stderr=subprocess.STDOUT))
      for result in sourceLines.split('\n'):
        specialString = ""
        if result:
          count = addrCountList.pop(0)
          if stackTopList.pop(0) == 1:
            specialString = " (StackTop)"
          else:
            specialString = ""
          result = result.strip("\n ' '")
        if result:
          #Retrieve function and line number from addr2line result
	  result = result.split('\n', 1)[0]
	  result = result.strip("\n ' '")
          if " at " in result:
	    function = result.split(" at ", 1)[0]
	    line = result.split(" at ", 1)[1]
	    function = function.strip()
            if function:
              addrMap_fun[element] = function
              line = line.strip()
              if line:
                line = line.split(' (', 1)[0]
                addrMap_line[element] = line
                if specialString:
                  line = line + specialString      
              #There will not be any line if sample is not from application binary
              else:
                addrMap_line[element] = ""
              combine_Results(function, line, count, \
                resultFunc, resultLine, tempFunc, tempLine);

  i=0
  print("\tFunctions and lines + Frequency")
  print("\t--------------------------------")
  for key, value in sorted(tempFunc.items(), key=lambda x:x[1], reverse=True):
    print("\n\t%s -- %u" % (key, value))

    k=0
    for line, count in sorted(tempLine[key].items(), key=lambda x:x[1], reverse=True):
      print("\t\t%s -- %u" % (line, count))
      k = k+1
      if k==3:
        break
    i = i+1
    if i == 5:
      break
  return

def choose_path(pathDict, strategy):

  resultFunc = dict()
  resultLine = dict()

  i=0
  print ("***************************************************")
  for key, value in sorted(pathDict.items(), key=lambda x:x[1][0], reverse=True):
    if ( i<10 ):
      print("\nCritical Path %d -- CMetric, Frequency" % (i+1))
      print("----------------------------------------")
      print("\t%s --%u, %d. \n" % (key, value[0], value[1]))  
      addrList = critLineSamples_all[key]
      #for element, count in addrList.items():
       # print(element,count)
      combine_samples(addrList, resultFunc, resultLine) 
      if get_kernel_stack:
        print("\n\tKernel Call Paths")
        print("\t-----------------------")
        for path, count in sorted(critKernelPaths[key].items(), key=lambda x:x[1], reverse=True):
          print("\t%s -- %d\n" % (path, count))
      i+= 1;
    else:
      break;  

  print ("***************************************************")
  i=0
  print ("\nTop Critical Functions and lines of code with frequency")
  for key, value in sorted(resultFunc.items(), key=lambda x:x[1], reverse=True):
    print("\n\t%s -- %u" % (key, value)) 

    k=0	
    for line, count in sorted(resultLine[key].items(), key=lambda x:x[1], reverse=True):
      print("\t\t%s -- %u" % (line, count)) 
      k = k+1
      if k==3:
        break
    i = i+1
    if i == 10:
      break
  print ("***************************************************")
  resultFunc.clear()
  resultLine.clear()
  return  

try:
	while 1:		
		b.kprobe_poll()
		
finally:	
	#Post Processing the stack traces
	start = datetime.datetime.now()
	print("Criticality Metric for each thread");	
	for k, v in sorted(threadCM.items(), key=lambda x:x[1].value):
		print("%10u %u " % ((k.value), (v.value)))
		sum += v.value
	print ("Sum = %d" % sum)
        print ("***************************************************")

	#for key, value in sorted(CMetric.items(), key=lambda x:x[1], reverse= True): # key is CM_Entry, value is CMetric
	for key, value in CMetric.items(): # key is CM_Entry, value is CMetric
	  user_callPath = CMetric_callPath[key][0]
          kernel_callPath = CMetric_callPath[key][1]

          #Combine all call paths irrespective of CMetric value and then sort as per CMetric value
          if user_callPath in criticalSwitch_allCM:
            criticalSwitch_allCM[user_callPath][0] += value
            criticalSwitch_allCM[user_callPath][1] += 1
          else:
            criticalSwitch_allCM[user_callPath] = [value,1]  

          #Combine the sample addresses
          if user_callPath not in critLineSamples_all:
            critLineSamples_all[user_callPath] = dict()
          lineDict = critLineSamples_all[user_callPath]
          addrList = CMetric_sampleAddr[key]
            
          for element in addrList:
            if element in lineDict:
              lineDict[element] += 1
            else:
              lineDict[element] = 1          

          #Combine kernel call paths
          if user_callPath not in critKernelPaths:
            critKernelPaths[user_callPath] = dict()
          allKernelPaths = critKernelPaths[user_callPath]

          if kernel_callPath in allKernelPaths:
            allKernelPaths[kernel_callPath] += 1
          else:
            allKernelPaths[kernel_callPath] = 1
          
          user_callPath = ""
          kernel_callPath = ""
        
	print ("Critical Call Paths, functions and Lines of Code:")
	choose_path(criticalSwitch_allCM, 1)

	end = datetime.datetime.now()
	post_time = end - start		
	print ("Post Processing time in milli seconds: %u" % int(post_time.total_seconds() * 1000))
	print ("Total switches: %u Critical switches: %u" % (total_switch, CM_Entry ))
        print ("Stack trace with no samples: %u" % noSample)
	print ("***************************************************")
	sys.exit()

