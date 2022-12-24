# Static Analysis of C Source Code

### Laboratory for the class “Security Verification and Testing” (01TYASM/01TYAOV)

### Politecnico di Torino – AY 2021/

### Prof. Riccardo Sisto

### prepared by:

### Riccardo Sisto (riccardo.sisto@polito.it)

### v. 1.0 (22/11/2021)

## Contents

1 Static Analysis with Flawfinder and PVS-Studio 2

```
1.1 Fixing and Re-analyzing CWE121.c............................... 2
1.2 Analyzing other simple examples................................. 3
1.3 Analyzing and Fixing vulnerability CVE-2017-1000249.................... 3
```
## Purpose of this laboratory

The purpose of this lab is to make experience with static source code analysis tools for the C/C++ languages.
More specifically, two tools will be experimented: a simple lexical scanner (flawfinder) and a more sophisti-
cated commercial static analysis tool (PVS-Studio). As the two tools have not only different features but also
different coverage of vulnerabilities, their combined use is recommended. (they are not specialized on security). For the installation of the tools,
please refer to the gettingStartedv2.1.2.pdf guide.

All the material necessary for this lab can be found in the course web pages on didattica.polito.it, Materiale
Didattico 2021/22 section, 04LabStaticAnalysisC folder.

## Getting started with flawfinder and PVS-Studio

Before starting with the real exercises, let us make some tests to check the tools are properly set.

### Running flawfinder to reproduce some of the results shown in the classroom

#### Usage
/* Flawfinder: ignore */ to avoid signaling again a vulnerability that was already marked as false positive
```
file:line: [severity] (type of vulnerability)
```

#### Test
Run flawfinder on the CWE121.c file taken from the NIST Juliet Test Suite for C/C++, and check that you get
the expected 4 hits that we saw in the classroom (you should get 4 hits if you use version 1.31. If you use later
versions you may get a different number of hits).

```
└─╼ flawfinder CWE121.c 
Flawfinder version 2.0.10, (C) 2001-2019 David A. Wheeler.
Number of rules (primarily dangerous function names) in C/C++ ruleset: 223
Examining CWE121.c

FINAL RESULTS:

CWE121.c:85:  [3] (random) srand:
  This function is not sufficiently random for security-related functions
  such as key and nonce creation (CWE-327). Use a more secure technique for
  acquiring random values.
CWE121.c:27:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
CWE121.c:42:  [2] (buffer) memcpy:
  Does not check for buffer overflows when copying to destination (CWE-120).
  Make sure destination can always hold the source data.

ANALYSIS SUMMARY:

Hits = 3
Lines analyzed = 99 in approximately 0.01 seconds (9454 lines/second)
Physical Source Lines of Code (SLOC) = 60
Hits@level = [0]   0 [1]   0 [2]   2 [3]   1 [4]   0 [5]   0
Hits@level+ = [0+]   3 [1+]   3 [2+]   3 [3+]   1 [4+]   0 [5+]   0
Hits/KSLOC@level+ = [0+]  50 [1+]  50 [2+]  50 [3+] 16.6667 [4+]   0 [5+]   0
Minimum risk level = 1
Not every hit is necessarily a security vulnerability.
There may be other security vulnerabilities; review your code!
See 'Secure Programming HOWTO'
(https://dwheeler.com/secure-programs) for more information.

```

CWE121.c

Best for CWE121.c is for the tool to find the vulnerability in the vulnerable function, but not reporting anything in the good (patched) function!
1. srand -> does not provide sufficient randomness for security-related applications
2. char charFirst[16] -> statically-sized arrays can be improperly restricted!
3. memcpy -> buffer overflow in the bad function (memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid));) (even in this case it would not be a real vulnerability since the string is defined in the code itself and not taken from an attacker, but it is still a bug!)
4. memcpy -> buffer overflow in the good function (memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid.charFirst));) <--- now the destination size is correctly indicated! false vulnerability! In new version of flawfinder it is not reported!

---
CVE-2013-6462
/src/bitmap/bdfread.c
1. line 341 sscanf -> 
```
    #define BDFLINELEN  1024

    unsigned char *line;
    unsigned char        lineBuf[BDFLINELEN];
	char        charName[100]; <--- charName can be up to 100 characters long

    line = bdfGetLine(file, lineBuf, BDFLINELEN); <--- Line can be up to 1024 characters long. If we assume that line comes from a file under the control of an attacker  (uploaded by an attacker), then this is a real vulnerability!

	if (sscanf((char *) line, "STARTCHAR %s", charName) != 1) { <--- charName can overflow!
	    bdfError("bad character name in BDF file\n");
	    goto BAILOUT;	/* bottom of function, free and return error */
	}
```
2. line 547 sscanf -> false positive, since the size is the right one!
3. less dangerous errors: handle strings not \0 terminated using string functions.

### Getting Started with PVS-Studio

Make sure you have run the following command to install the free academic license:

```
pvs-studio-analyzer credentials PVS-Studio Free FREE-FREE-FREE-FREE
```
Note that, when working with the Labinf VMs, this command has to be entered again after each re-start of the
VM. With the Labinf physical machines, instead, the PVS-Studio license should remain stored in your home
directory after the first execution of the command.

As we use PVS-Studio from the command line, some bash scripts are provided to simplify running PVS-Studio.
They are included in the zip file named pvs-script.zip. Extract this archive in your home directory. The scripts
will be copied to your bin directory, which will be created if not yet present. In order to complete the setup add
the bin directory to the PATH if not yet included. This can be done by adding the following line to the .bashrc
file in your home directory:

```
export PATH=$PATH:[home directory]/bin
```
where [home directory] is your home directory.

- The pvs-addcomment script can be used to add the necessary comment to all the .c files in the current directory.
```
for filename in ./*.c 
do
sed -i '1i// This is a personal academic project. Dear PVS-Studio, please check it.' ${filename}
sed -i '2i// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com' ${filename}
done
```
- The pvs-run script can be used to run PVS-Studio. You must run it with the same command-line arguments that
you use for the ’make’ command when you compile the program. The report is generated in HTML format (in
the htmlreport directory). If you want to change the options used to run PVS-Studio you can edit the pvs-run
script.
```
echo "pvs-run with parameters: $@"
pvs-clean
pvs-studio-analyzer trace -- make "$@"
pvs-studio-analyzer analyze -a 'GA;OWASP' -o ./project.log
plog-converter -a 'GA:1,2,3' -t fullhtml -o ./htmlreport ./project.log
```
- The pvs-clean script makes a cleaning by removing the files generated by PVS-Studio, including the
result files. It is called automatically by pvs-run before running PVS-Studio.
```
rm -f -r htmlreport
rm -f project.log
rm -f strace_out
```
- Finally, pvs-setlicense can be used to set the license again (e.g. in the labinf VM).
```
pvs-studio-analyzer credentials PVS-Studio Free FREE-FREE-FREE-FREE
```

CWE121.c
Place comment at the start of the file to analyze
// This is a personal academic project. Dear PVS-Studio, please check it.' ${filename}
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com' ${filename}

You need to run the tool with a compiler (easier with makefile). pvs-studio analyse all files.
It can then generate an html report.

Script to run pvs-studio (pvs-run):

clean necessary to remove the exe previously created.
with analyze you can specify the classes of analysis to perform, the output file
converter generates html report.

In this case only the bad function is reported!

For snippets of code to analyse for vulnerabilities (not full projects) there is also an online portal at pvs-studio.com/en/pvs-studio/godbolt

### Running PVS-Studio to reproduce some of the results shown in the classroom

Run PVS-Studio on the CWE121.c file taken from the NIST Juliet Test Suite for C/C++, by entering the
following commands from the CWE121 directory (note that the makefile in this case requires no arguments):

```
pvs-addcomment
pvs-run
```
Check that the analysis proceeds without errors and that you get the html report containing a single entry, as
shown in the classroom.
```
General Analysis	CWE121.c:44	High	V512	A call of the 'memcpy' function will lead to overflow of the buffer 'structCharVoid.charFirst'.
```
Now, try to run PVS-Studio from the demonstration web site:

```
https://pvs-studio.com/en/pvs-studio/godbolt/
```
Here, you can edit the C code that is in the left hand side text area. When you change the code, you can see
the new results on the right hand side. If you prefer, you can open an alternative view, by clicking on ’Edit on
Compiler Explorer’ (https://godbolt.org/#g:!((g:!((g:!((h:codeEditor,i:(filename:'1',fontScale:14,fontUsePx:'0',j:1,lang:c%2B%2B,source:'//+PVS-Studio+static+code+analyzer:+https://pvs-studio.com/en/pvs-studio/%0A%0A%23include+%3Ccstdlib%3E%0A%0Aint+*my_alloc()+%7B+return+new+int%3B+%7D%0A%0Avoid+use(int+*p)+%7B+*p+%3D+1%3B+%7D%0A%0Avoid+foo(bool+x,+bool+y)%0A%7B%0A++++int+*a+%3D+nullptr%3B%0A++++int+*b+%3D+nullptr%3B%0A++++%0A++++a+%3D+my_alloc()%3B%0A++++a+%3D+my_alloc()%3B%0A%0A++++use(a)%3B%0A++++use(b)%3B%0A%0A++++std::free(a)%3B%0A++++std::free(b)%3B%0A%7D'),l:'5',n:'0',o:'C%2B%2B+source+%231',t:'0'),(h:compiler,i:(compiler:clang1000,filters:(b:'0',binary:'1',commentOnly:'0',demangle:'0',directives:'0',execute:'0',intel:'0',libraryCode:'1',trim:'1'),flagsViewOpen:'1',fontScale:14,fontUsePx:'0',j:1,lang:c%2B%2B,libs:!(),options:'',source:1,tree:'1'),l:'5',n:'0',o:'x86-64+clang+10.0.0+(C%2B%2B,+Editor+%231,+Compiler+%231)',t:'0')),k:50,l:'4',n:'0',o:'',s:0,t:'0'),(g:!((h:tool,i:(args:'',argsPanelShow:'1',compiler:1,editor:1,fontScale:14,fontUsePx:'0',monacoEditorHasBeenAutoOpened:'1',monacoEditorOpen:'1',monacoStdin:'1',stdin:'',stdinPanelShown:'1',toolId:PVS-Studio,wrap:'0'),l:'5',n:'0',o:'PVS-Studio+%231+with+x86-64+clang+10.0.0',t:'0')),k:50,l:'4',m:100,n:'0',o:'',s:0,t:'0')),l:'2',n:'0',o:'',t:'0')),version:4)

```
// PVS-Studio static code analyzer: https://pvs-studio.com/en/pvs-studio/

#include <cstdlib>

int *my_alloc() { return new int; }

void use(int *p) { *p = 1; }

void foo(bool x, bool y)
{
    int *a = nullptr;
    int *b = nullptr;
    
    a = my_alloc();
    a = my_alloc();

    use(a);
    use(b);

    std::free(a);
    std::free(b);
}
```
```
The documentation for all analyzer warnings is available here: https://pvs-studio.com/en/docs/warnings/.

<source>:15:1: error: V773 The 'a' pointer was assigned values twice without releasing the memory. A memory leak is possible.
<source>:7:1: error: V522 Dereferencing of the null pointer 'p' might take place. The null pointer is passed into 'use' function. Inspect the first argument. Check lines: 7, 18.
<source>:20:1: error: V611 The memory was allocated using 'new' operator but was released using the 'free' function. Consider inspecting operation logics behind the 'a' variable.
<source>:15:1: warning: V519 The 'a' variable is assigned values twice successively. Perhaps this is a mistake. Check lines: 14, 15.
```

Try to fix the sample code that is displayed and check that the errors reported disappear.
```
// PVS-Studio static code analyzer: https://pvs-studio.com/en/pvs-studio/

#include <cstdlib>

int *my_alloc() { return new int; }

void use(int *p) { if(p!=nullptr) *p = 1; }

void foo(bool x, bool y)
{
    int *a = nullptr;
    int *b = nullptr;
    
    a = my_alloc();
    //a = my_alloc();

    use(a);
    use(b);

    //std::free(a);
    //std::free(b);
    delete a;
    delete b;
}
```
The archive of the lab contains a very simple test file that contains a classical format string vulnerability. It is
in the test1 directory. Copy the contents of the file and paste it in the left-hand size window, by overwriting the
previous code.
```
char buf[5012];

strncpy(buf, argv[1], sizeof buf - 1);
buf[sizeof buf - 1] = 0;

printf(buf); /* FIX */
```
```
<source>:28:1: warning: V618 It's dangerous to call the 'printf' function in such a manner, as the line being passed could contain format specification. The example of the safe code: printf("%s", str);
```
The format string vulnerability should be pointed out by PVS-Studio. Fix the code and check
that PVS-Studio does not report the error after the fix.
```
printf("%s",buf); /* FIXEd */
```

## 1 Static Analysis with Flawfinder and PVS-Studio

### 1.1 Fixing and Re-analyzing CWE121.c

Fix the vulnerability found in CWE121.c and then re-run the tools (flawfinder and PVS-Studio). What is the
result? How can it be explained?

```
Flawfinder still finds 2 false positives because it only performs lexical analysis
```

```
PVS-Studio doesn't find any false positives because it is more advanced
Fail/Info		High		Congratulations! PVS-Studio has not found any issues in your source code!
```

### 1.2 Analyzing other simple examples

Use Flawfinder and PVS-Studio to analyze the other simple examples found in the lab material (test1, test2).
For each one of them, run Flawfinder and PVS-Studio. Then, analyze each reported problem and decide if it is
a true positive or a false positive. Explain your decision.

#### Test1
```
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {

char buf[5012];

strncpy(buf, argv[1], sizeof buf - 1);
buf[sizeof buf - 1] = 0;

printf(buf); /* FIX */

return (0);

}
```

| bug                                                                                                                                                                                                                                                                                                                                                         | Found On               | True/False Positive | Reason                                                                                                     |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- | ------------------- | ---------------------------------------------------------------------------------------------------------- |
| test1.c:28:  [4] (format) printf: If format strings can be influenced by an attacker, they can be exploited (CWE-134). Use a constant for the format specification.<br />↑ V618 It's dangerous to call the 'printf' function in such a manner, as the line being passed could contain format specification. The example of the safe code: printf("%s", str) | Flawfinder, PVS-Studio | true positive!      |
| test1.c:23:  [2] (buffer) char:   Statically-sized arrays can be improperly restricted, leading to potential overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use functions that limit length, or ensure that the size is larger than the  maximum possible ength.                                                                    | Flawfinder             | false positive      | because we use strncpy to copy at most sizeof buf -1 bytes, so that buffer cannot overflow: bound checking |
| test1.c:25:  [1] (buffer) strncpy: Easily used incorrectly; doesn't always \0-terminate or check for invalid pointers [MS-banned] (CWE-120).                                                                                                                                                                                                                | Flawfinder             | false positive      | because manually terminated by \0, strncpy used properly                                                   |

#### Test2
```
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <inttypes.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>

#define RBUFLEN		128
#define	MAXSIZE		138

/* GLOBAL VARIABLES */
char buf[RBUFLEN];		 /* reception buffer */

/* Provides service on the passed socket */
void service(int s)
{
    int	 n;

    for (;;)
    {
        n=read(s, buf, RBUFLEN-1);
        if (n < 0)
        {
            printf("Read error\n");
            close(s);
            printf("Socket %d closed\n", s);
            break;
        }
        else if (n==0)
        {
            printf("Connection closed by party on socket %d\n",s);
            close(s);
            break;
        }
        else
        {
            char local[MAXSIZE];
            char log[MAXSIZE];
            buf[RBUFLEN-1]='\0';
            strcpy(local,"script.sh ");
            strcat(local,buf);
            system(local);
            strncpy(log,local,140);
            syslog(1,"%s",local);
            strncpy(buf,log,MAXSIZE);
            if(write(s, buf, strlen(buf)) != strlen(buf))
              printf("Write error while replying\n");
            else
              printf("Reply sent\n");
        }
    }
}
```

Flawfinder:
```
test2.c:46:  [4] (buffer) strcat:
  Does not check for buffer overflows when concatenating to destination
  [MS-banned] (CWE-120). Consider using strcat_s, strncat, strlcat, or
  snprintf (warning: strncat is easily misused).
test2.c:47:  [4] (shell) system:
  This causes a new program to execute and is difficult to use safely
  (CWE-78). try using a library call that implements the same functionality
  if available.
test2.c:17:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
test2.c:42:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
test2.c:43:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
test2.c:45:  [2] (buffer) strcpy:
  Does not check for buffer overflows when copying to destination [MS-banned]
  (CWE-120). Consider using snprintf, strcpy_s, or strlcpy (warning: strncpy
  easily misused). Risk is low because the source is a constant string.
test2.c:26:  [1] (buffer) read:
  Check buffer boundaries if used in a loop including recursive loops
  (CWE-120, CWE-20).
test2.c:48:  [1] (buffer) strncpy: -> True Positive: 
  Easily used incorrectly; doesn't always \0-terminate or check for invalid
  pointers [MS-banned] (CWE-120).
test2.c:50:  [1] (buffer) strncpy: -> True Positive: 
  Easily used incorrectly; doesn't always \0-terminate or check for invalid
  pointers [MS-banned] (CWE-120).
test2.c:51:  [1] (buffer) strlen:
  Does not handle strings that are not \0-terminated; if given one it may
  perform an over-read (it could cause a crash if unprotected) (CWE-126).
test2.c:51:  [1] (buffer) strlen:
  Does not handle strings that are not \0-terminated; if given one it may
  perform an over-read (it could cause a crash if unprotected) (CWE-126).
```
PVS-Studio
```
General Analysis	test2.c:50	High	V512	A call of the 'strncpy' function will lead to overflow of the buffer 'log'.
strncpy(log,local,140);
↑ V512 A call of the 'strncpy' function will lead to overflow of the buffer 'log'.

General Analysis	test2.c:52	High	V512	A call of the 'strncpy' function will lead to overflow of the buffer 'buf'.
strncpy(buf,log,MAXSIZE);
↑ V512 A call of the 'strncpy' function will lead to overflow of the buffer 'buf'.
```
test2.c
- strcpy -> error
- if I call system(buf) -> No errors reported, but this is a vulnerability if I execute a command from buf read from the network and not previously sanitized!
- if I call printf(buf) -> Error reported: format string vulnerability (common pattern)
- if I call printf(buf,n) -> Error not reported, format string vulnerability even if the attacker does not control n!

| bug                                                                                                                                | Found On       | True/False Positive | Reason                                                                                                                                                           |
| ---------------------------------------------------------------------------------------------------------------------------------- | -------------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| test2.c:50 strncpy(log,local,140);                                                                                                 | PVS,Flawfinder | True Positive       | #define	MAXSIZE		138 char log[MAXSIZE]; can't contain 140 characters!                                                                                            |
| test2.c:52 strncpy(buf,log,MAXSIZE);                                                                                               | PVS,Flawfinder | True Positive       | #define	MAXSIZE		138 char log[MAXSIZE]; #define RBUFLEN		128 char buf[RBUFLEN];	            strncpy(buf,log,MAXSIZE); cannot copy 138 characters in a 128 buffer |
| (shell) system:47 This causes a new program to execute and is difficult to use safely                                              | Flawfinder     | True Positive       | Input for the system function is not sanitized (taken directly from buf)                                                                                         |
| (buffer) char buf[RBUFLEN]:17 Statically-sized arrays can be improperly restricted, leading to potential overflows or other issues | Flawfinder     | True Positive       | buf[RBUFLEN] cannot contain the same amount of bytes as the source buffer char log[MAXSIZE]                                                                      |
| (buffer) char log[MAXSIZE]:43 Statically-sized arrays can be improperly restricted, leading to potential overflows or other issues | Flawfinder     | True Positive       | log[MAXSIZE] cannot contain more than MAXSIZE bytes!                                                                                                             |
| (buffer)  strcat:46, read, strncpy, strlen : Does not check for buffer overflows when concatenating to destination                 | Flawfinder     | False Positive      | Correct usage                                                                                                                                                    |
### 1.3 Analyzing and Fixing vulnerability CVE-2017-

CVE-2017-1000249 refers to a buffer overflow vulnerability that was found in an implementation of the UNIX
file() command. In this exercise we try to find a vulnerability is a real application code. In the material for
the lab, you can find a pdf document with the CVE description of the vulnerability and the package with the
sources of a version of the software affected by the vulnerability. Read the CVE description and then run
flawfinder on the file readelf.c, which is the one containing the vulnerability. 
```
 lets an attacker overwrite a fixed 20 bytes stack buffer with a specially crafted .notes section in an ELF binary.
```
Analyse the results of the run and
find the vulnerability the CVE refers to. Classify the hits given by flawfinder into true positives (TP) and false
positives (FP). How many TP and how many FP did you find? For each one of them, explain the reason for
your classification.

| bug                                                                                      | TP/FP | Reason                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------------------------------------------------------------------------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| readelf.c:81:  [2] (buffer) char c[2]:                                                   | FP    | The only instructions that use this array are: retval.c[0] = tmpval.c[1];	retval.c[1] = tmpval.c[0];                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| readelf.c:100:  [2] (buffer) char c[4]:                                                  | FP    | The only instructions that use this array are the swap instructions as above                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| readelf.c:121:  [2] (buffer) char c[8]:                                                  | FP    | The only instructions that use this array are the swap instructions as above                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| readelf.c:333:  [2] (buffer) char nbuf[BUFSIZ]:                                          | FP    | stdio.h -> /* Default buffer size.  */ #define BUFSIZ 8192 <br/> In its scope of definition the buffer is used consistently!                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| readelf.c:535:  [2] (buffer) `(void)memcpy(desc, &nbuf[doff], descsz)`:                  | TP    | Does not check for buffer overflows when copying to destination. This is called by `do_bid_note` function. (The do_bid_note function is called by `do_bid_note(ms, nbuf, xnh_type, swap, namesz, descsz, noff, doff, flags)` inside `donote`. donote is called by `dophn_core`, `doshn`, `dophn_exec`, which are called in the `elfclass.h`). Limit your research to the scope of the function! The number of bytes copied by memcpy,  i.e.  variable descsz,  is not properly checked because  the  condition  `(descsz>=4||descsz<=20)`  is  always  true;  the  problem  can  be  fixed  by correcting the condition into `(descsz>=4 && descsz<=20)`, which guarantees that descsz is less than 20, i.e. that less than 20 bytes are copied (`uint8_t desc[20];` is the destination buffer) |
| readelf.c:720:  [2] (buffer) sbuf[512]:                                                  | FP    | It never takes input?                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| readelf.c:723:  [2] (buffer) memcpy(&pi, nbuf + doff, descsz):                           | TP    | In the function do_core_note, called inside donote with `do_core_note(ms, nbuf, xnh_type, swap, namesz, descsz, noff, doff, flags, size, clazz)` Does not check for buffer overflows when copying to destination (does not check descsz), so depending on how the function is called, this could be a vulnerability.                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| readelf.c:954:  [2] (buffer) (void)memcpy(xauxv_addr, &nbuf[doff + off], xauxv_sizeof):  | FP    | `for(size_t off = 0; off + elsize <= descsz; off += elsize)`. `#define xauxv_addr	(clazz == ELFCLASS32 ? (void *)&auxv32 : (void *)&auxv64) = xauxv_sizeof` so the destination will alway be able to hold the content.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| readelf.c:996:  [2] (buffer) char buf[256]:                                              | FP    | Used consistently in its scope                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| readelf.c:1040:  [2] (buffer)	`(void)memcpy(xnh_addr, &nbuf[offset], xnh_sizeof)`:       | FP    | `#define xauxv_addr	(clazz == ELFCLASS32 ? (void *)&auxv32 : (void *)&auxv64) = xauxv_sizeof` so the destination will alway be able to hold the content.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| readelf.c:1214:  [2] (buffer) char name[50]:                                             | FP    | Used consistently in its scope                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| readelf.c:1327:  [2] (buffer) `char cbuf[/*CONSTCOND*/MAX(sizeof cap32, sizeof cap64)]`: | FP    | Used consistently in its scope                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| readelf.c:1366:  [2] (buffer) `(void)memcpy(xcap_addr, cbuf, xcap_sizeof)`:              | FP    | As with xauxv_addr and sizeof, the sizes are equal                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| readelf.c:1477:  [2] (buffer) `char nbuf[BUFSIZ]`:                                       | FP    | Used consistently in its scope                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| readelf.c:1478:  [2] (buffer) `char ibuf[BUFSIZ]`:                                       | FP    | Used consistently in its scope                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| readelf.c:1578:  [2] (buffer) `char c[sizeof (int32_t)];`:                               | FP    | Unused!                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| readelf.c:1331:  [1] (buffer) `read(fd, cbuf, (size_t)xcap_sizeof)`:                     | FP    | `if (read(fd, cbuf, (size_t)xcap_sizeof) != (ssize_t)xcap_sizeof)` checks no overflow                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| readelf.c:1350:  [1] (buffer) `p += strlen(p) + 1`:                                      | TP    | Since we cannot guarantee that the tring is \0 terminated this could be a vulnerability `char cbuf[/*CONSTCOND*/MAX(sizeof cap32, sizeof cap64)]; read(fd, cbuf, (size_t)xcap_sizeof); if (cbuf[0] == 'A') { char *p = cbuf + 1;`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |


Now, try to use PVS-Studio for the analysis of the code. Before being able to compile the code by the ’make’
command it is necessary to generate the makefile, by running the following commands (see README.DEVELOPER):

```
autoreconf -f -i
./configure --disable-silent-rules
```
Then, you can check that the code can be compiled by running

```
make -j
```
another preliminary operation before running PVS-Studio is to insert the two special comment lines at the
beginning of each C file. This can be done by means of the pvs-addcomment script, after having moved into
the src directory:

```
cd src
pvs-addcomment
```
Finally, PVS-Studio can be run from the main directory by running

```
make clean
pvs-run -j
```
Note that whenever you want to repeat the analysis you need to clean the project, because PVS-Studio can only
analyze the files that are actually compiled (make will automatically avoid the compilation of files if the result
of compilation is up to date). Look at the problems reported by PVS-Studio on the readelf.c file. What can we
say about the ability of PVS-Studio to find the known vulnerability in this file?

```
It finds different (possible) vulnerabilities! For our vulnerability, it finds the cause of the vulnerability instead of the vulnerability itself.
```
- General Analysis	readcdf.c:246	Medium	V1004	The 'c' pointer was used unsafely after it was verified against nullptr. Check lines: 241, 246.
- General Analysis	readelf.c:500	Low	V576	Incorrect format. Consider checking the third actual argument of the 'file_printf' function. The SIGNED integer type argument is expected.
- General Analysis	readelf.c:516	Medium	V560	A part of conditional expression is always true: descsz <= 20. 
- General Analysis	readelf.c:591	Low	V576	Incorrect format. Consider checking the third actual argument of the 'file_printf' function. The SIGNED integer type argument is expected.
- General Analysis	readelf.c:591	Low	V576	Incorrect format. Consider checking the fourth actual argument of the 'file_printf' function. The SIGNED integer type argument is expected.
- General Analysis	readelf.c:591	Low	V576	Incorrect format. Consider checking the fifth actual argument of the 'file_printf' function. The SIGNED integer type argument is expected.

Find a fix for the vulnerability and write a patched version of the file.

 `(descsz>=4||descsz<=20)`  is  always  true;  the  problem  can  be  fixed  by correcting the condition into `(descsz>=4 && descsz<=20)`

## Other examples
 ...