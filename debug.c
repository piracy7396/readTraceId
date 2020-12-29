//
// Created by wireghost on 2019/7/29.
//

#include "thsdk.h"
#include "debug.h"
#include <time.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdbool.h>


time_t start_time;
time_t end_time;
#define PATH_LEN 256
#define BUFF_LEN 4096

/*
 * 对应10进制的23946，IDA调试的默认端口
 */
#define TCP_PORT1 "5D8A"
/*
 * 对应10进制的27402、27403，Frida Hook时默认会占用的两个端口号
 */
#define TCP_PORT2 "6B0A"
#define TCP_PORT3 "6B0B"

void single_step();
bool checkSystem();
void fork_and_attach();
void my_sigtrap(int sig);
void get_taskstate(char* path);
void getWchanStatus(char* path);
void checkTracePid(char* path, int pid);
typedef bool (*artDbgIsDebuggerActive)();
typedef bool (*dvmDbgIsDebuggerConnected)();

void set_SIGTRAP(){
    // 设置SIGTRAP信号的处理函数为my_sigtrap
    long g_ret = (long)signal(SIGTRAP, my_sigtrap);
    if (g_ret == (long)SIG_ERR) {
        LOGE("signal ret value is SIG_ERR.");
    }
    LOGI("signal ret value is %x", (unsigned char*)g_ret);
    raise(SIGTRAP);  // 主动给自己进程发送SIGTRAP信号
}

void fork_and_attach() {
    int pid = fork();
    if (pid == 0) {
        int ppid = getppid();
        if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0) {
            waitpid(ppid, NULL, 0);
            /* Continue the parent process */
            ptrace(PTRACE_CONT, NULL, NULL);
        }
    }
}


//void eachother_ptrace(){
//    pid_t child;
//    child = fork();
//    if (child) {
//        wait(NULL);
//    }
//    else {
//        pid_t parent = getppid();
//        if (ptrace(PTRACE_ATTACH, parent, 0, 0) < 0) {
//            while(1);
//        }
//        sleep(1);
//        ptrace(PTRACE_DETACH, parent, 0, 0);
//        exit(0);
//    }
//}

void CheckParents() {
    // 设置buf
    char strPpidCmdline[PATH_LEN] = {0};
    snprintf(strPpidCmdline, sizeof(strPpidCmdline), "/proc/%d/cmdline", getppid());
    // 打开文件
    int file = open(strPpidCmdline, O_RDONLY);
    if (file < 0) {
        LOGE("CheckParents open错误!\n");
        return;
    }
    // 文件内容读入内存
    memset(strPpidCmdline, 0, sizeof(strPpidCmdline));
    ssize_t ret = read(file, strPpidCmdline, sizeof(strPpidCmdline));
    if (ret == -1) {
        LOGE("CheckParents read错误!\n");
        return;
    }
    LOGI("父进程cmdline：%s", strPpidCmdline);
    if (strstr(strPpidCmdline,"zygote") == NULL) {
        // 执行到这里，判定为调试状态
        LOGE("父进程cmdline没有zygote子串!\n");
        exit(0);
    }
}

void check_keyprocfile() {
    int pid = getpid();
    char path[40] = {'\0'};
    sprintf(path, "/proc/%d/status", pid);
    checkTracePid(path, pid);
    sprintf(path, "/proc/%d/task/%d/status", pid, pid);
    checkTracePid(path, pid);
    sprintf(path, "/proc/%d/stat", pid);
    get_taskstate(path);
    sprintf(path, "/proc/%d/task/%d/stat", pid, pid);
    get_taskstate(path);
    sprintf(path, "/proc/%d/wchan", pid);
    getWchanStatus(path);
    sprintf(path, "/proc/%d/task/%d/wchan", pid, pid);
    getWchanStatus(path);
}

/*
 * 循环检查TCP端口
 */
void scan_port() {
    LOGI("tcp_monitor");
    FILE *fp;
    FILE *fd;
    char buff[BUFF_LEN];
    char line[BUFF_LEN];
    const char* dir = "/proc/net/tcp";
    fp = fopen(dir, "r");
    if(fp == NULL) {
        LOGE("file failed [errno:%d, desc:%s]", errno, strerror(errno));
        return;
    }
    while (fgets(buff, BUFF_LEN, fp) != NULL) {
        if (strstr(buff, TCP_PORT1) != NULL || strstr(buff, TCP_PORT2) != NULL || strstr(buff, TCP_PORT3) != NULL) {
            LOGI("可疑端口Line:%s", buff);  // 记录有可疑端口的输出信息
            fclose(fp);
            //exit(0);
        }
    }
    fclose(fp);
    LOGW("cat /proc/net/tcp 未发现可疑端口！");
    fd = popen("netstat -apn", "r");  // 检查所有进程和端口使用情况
    if (fd == NULL) {
        LOGE("not found any ports!");
        return;
    }
    while (fgets(line, sizeof(line), fd) != NULL) {
        char* str0 = NULL;
        char* str1 = NULL;
        char* str2 = NULL;
        str0 = strstr(line, " 23946/");
        str1 = strstr(line, " 27402/");
        str2 = strstr(line, " 27403/");
        if (str0 || str1 || str2) {
            pclose(fd);
            LOGI("可疑端口Line:%s", buff);  // 记录有可疑端口的输出信息
            //exit(0);
        }
    }
    pclose(fd);
    LOGW("netstat -apn 未发现可疑端口！");
}

void check_process() {
    /*
     * ps命令读取进程列表
     */
    char buf[BUFF_LEN];
    //FILE* pfile = popen("ls sys/class", "r");
    FILE* pfile = popen("ps -ef", "r");  // popen可以执行shell命令，并读取此命令的返回值
    if (pfile == NULL) {
        LOGE("no process exist!");
        return;
    }
    while (fgets(buf, sizeof(buf), pfile) != NULL) {
        // 查找子串
        char* strA = NULL;
        char* strB = NULL;
        char* strC = NULL;
        char* strD = NULL;
        strA = strstr(buf, "android_server");
        strB = strstr(buf, "gdbserver");
        strC = strstr(buf, "gdb");
        strD = strstr(buf, "frida_server");  // frida hook框架
        LOGI("PS进程列表:%s",buf);
        if (strA || strB || strC) {
            LOGI("isDebugProcessExist find debug");
            pclose(pfile);
            //exit(0);
        }
        if (strD) {
            LOGI("find frida hook process");
            pclose(pfile);
            //exit(0);
        }
    }
    LOGI("PS命令未发现可疑进程！");
    pclose(pfile);
    /*
     * 遍历/proc目录下所有pid目录
     */
    struct dirent *pde = NULL;
    FILE *fp = NULL;
    char buff[BUFF_LEN];
    char szName[BUFF_LEN];
    DIR* pdir = opendir("/proc");
    if(!pdir){
        perror("open /proc fail.\n");
        return;
    }
    while(pde = readdir(pdir)){
        if((pde->d_name[0] < '0') || (pde->d_name[0] > '9')) {
            continue;
        }
        sprintf(buff, "/proc/%s/status", pde->d_name);
        fp = fopen(buff, "r");
        if(fp){
            fgets(buff, sizeof(buff), fp);
            fclose(fp);
            sscanf(buff, "%*s %s", szName);
            LOGE("进程szName信息 %s\n", szName);
            if(strstr(szName, "gdb") || strstr(szName, "android_server") || strstr(szName, "gdbserver")|| strstr(szName, "frida_server")) {
                closedir(pdir);
                LOGI("isDebugProcessExist find debug");
                //exit(0);
            }
        }
    }
    closedir(pdir);
    LOGI("遍历/proc目录下所有pid目录未发现可疑进程！");
}

void single_step() {
    time(&start_time);
    /*
     * 将需要监控的关键代码放在这里
     */
    time(&end_time);
    LOGI("start time:%d, end time:%d", start_time, end_time);
    if(end_time - start_time > 2){
        LOGI("存在单步调试现象");
        exit(0);
    }
}

// 这段注意下
void isDbgConnected(JNIEnv *env, jobject obj, jboolean jbool) {
    if (jbool == JNI_TRUE) {
        LOGW("运行在art虚拟机");
        //貌似7.0以后的版本不允许使用非ndk原生库，dlopen(libart.so)会失败。
        void *handle = dlopen("/system/lib/libart.so", RTLD_LAZY);
        if (!handle) {
            LOGE("wtf?! load libart.so failed.\n");
            return;
        }
        artDbgIsDebuggerActive realfunc = (artDbgIsDebuggerActive) dlsym(handle,"_ZN3art3Dbg16IsDebuggerActiveEv");
        if (realfunc == NULL) {
            LOGE("dlsym获取_ZN3art3Dbg15gDebuggerActiveE符号失败!\n");
            return;
        }
        bool result = realfunc();
        if (result) {
            LOGI("debug_status: true");
            exit(0);
        } else {
            LOGI("debug_status: false");
        }
    } else {
        LOGW("运行在dalvik虚拟机");
        void *handle = dlopen("/system/lib/libdvm.so", RTLD_LAZY);
        if (!handle) {
            LOGE("wtf?! load libdvm.so failed.\n");
            return;
        }
        dvmDbgIsDebuggerConnected realfunc = (dvmDbgIsDebuggerConnected) dlsym(handle, "_Z25dvmDbgIsDebuggerConnectedv");
        if(realfunc == NULL)
        {
            LOGE("dlsym获取_Z25dvmDbgIsDebuggerConnectedv符号失败!\n");
            return;
        }
        bool result = realfunc();
        if(result){
            LOGI("debug_status: true");
            exit(0);
        } else {
            LOGI("debug_status: false");
        }
    }
}

void my_sigtrap(int sig) {
    signal(SIGTRAP, 0);
    LOGI("-----执行我的函数-----");
    /*
     * 可以将加解密等关键代码放在这里执行
     */
    return;
}

void checkTracePid(char* path, int pid) {
    char line[BUFF_LEN];
    FILE* fd = fopen(path, "r");
    if (fd != NULL) {
        while (fgets(line, BUFF_LEN, fd)) {
            if (strncmp(line, "TracerPid", 9) == 0) {
                int statue = atoi(&line[10]);
                LOGI("%s的TracerPid等于%d", path, statue);
                //若当前tracePid不为0或者当前pid(防止有守护进程)
                if (statue != 0 && statue != pid) {
                    LOGI("be attached !! kill %d", pid);
                    fclose(fd);
 //                   exit(0);
                }
                else if (statue == 0) {
                    /*
                     * 即便我们读出来的tracerpid等于0，也可能是因为对手修改了源码，让tracerpid永远为0。
                     * 针对这种情况，我们可以创建一个子进程，让子进程主动ptrace自身设为调试状态。
                     * 此时正常情况下，子进程的tracerpid应该不为0。所以我们可通过检查子进程的tracepid看它是否为0，如果等于0说明源码被修改了，目标对象已经有了反调试的意识
                     * 以下代码若检查到源码被修改的现象，将直接退出程序
                     */
                    if (checkSystem) {
                        LOGI("check succeed.");
                    } else {
                        LOGI("check failed.");
                    }
                }
                //break;
            }
        }
        fclose(fd);
    } else {
        LOGI("open %s fail...", path);
    }
}

void get_taskstate(char* path) {
    char line[BUFF_LEN];
    char cmd[50] = "cat ";
    strcat(cmd, path);
    FILE* fd = popen(cmd, "r");
    if (fd != NULL) {
        fgets(line, BUFF_LEN, fd);  // stat文件只有一行
        LOGE("stat文件输出：%s\n", line);
        char charlist[50][50] = {""}; //指定分隔后子字符串存储的位置，这里定义二维字符串数组
        int i = 0;
        char *substr = strtok(line, " "); //利用现成的分割函数,substr为分割出来的子字符串
        while (substr != NULL) {
            strcpy(charlist[i], substr);  //把新分割出来的子字符串isubstr拷贝到要存储的charlsit中
            i++;
            printf("%s\n", substr);
            substr = strtok(NULL," ");  //在第一次调用时，strtok()必需给予参数str字符串，往后的调用则将参数str设置成NULL。每次调用成功则返回被分割出片段的指针。
        }
        LOGE("当前任务状态task_state：%s\n", charlist[2]);
        if (charlist[2] == "t" || charlist[2] == "T") {
            LOGI("I was be traced");
            pclose(fd);
            exit(0);
        }
        pclose(fd);
    }
}

void getWchanStatus(char* path) {
    char wchaninfo[BUFF_LEN];
    char cmd[50] = "cat ";
    strcat(cmd, path);
    LOGI("shell cmd：%s", cmd);
    FILE* ptr = popen(cmd, "r");
    if (ptr != NULL) {
        fgets(wchaninfo, BUFF_LEN, ptr);
        LOGI("wchaninfo = %s\n", wchaninfo);
        if (strcmp(wchaninfo, "ptrace_stop\0") == 0) {
            LOGI("I was be traced");
            pclose(ptr);
            exit(0);
        }
        pclose(ptr);
    }
}

bool checkSystem(){
    // 建立管道
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        LOGE("pipe() error.\n");
        return false;
    }
    // 创建子进程
    pid_t pid = fork();
    LOGI("father pid is: %d\n", getpid());
    LOGI("child pid is: %d\n", pid);
    // fork失败
    if (pid < 0) {
        LOGE("fork() error.\n");
        return false;
    }
    // 子进程程序
    int childTracePid = 0;
    if (pid == 0) {
        int iRet = ptrace(PTRACE_TRACEME, 0, 0, 0);  // 子进程反调试
        if (iRet == -1) {
            LOGE("child ptrace failed.\n");
            exit(0);
        }
        LOGE("ptrace succeed.\n");
        // 获取tracepid
        char path[PATH_LEN] = {0};
        char readbuf[BUFF_LEN] = {0};
        sprintf(path, "/proc/%d/status", getpid());
        int fd = openat(NULL, path, O_RDONLY);
        if (fd == -1) {
            LOGE("openat failed.\n");
            return false;
        }
        read(fd, readbuf, 100);
        close(fd);
        uint8_t *start = (uint8_t *)readbuf;
        uint8_t des[100] = {0x54, 0x72, 0x61, 0x63, 0x65, 0x72, 0x50, 0x69, 0x64, 0x3A, 0x09};  // 对应字符 TracerPid:
        int i = 100;
        bool flag= false;
        while (--i) {
            if (memcmp(start,des,10) == 0) {
                start = start + 11;
                childTracePid = atoi((char*)start);
                flag = true;
                break;
            } else {
                start = start + 1;
                flag= false;
            }
        }
        if (!flag) {
            LOGE("get tracepid failed.\n");
            return false;
        }
        // 向管道写入数据
        close(pipefd[0]); // 关闭管道读端
        write(pipefd[1], (void*)&childTracePid, 4); // 向管道写端写入数据
        close(pipefd[1]); // 写完关闭管道写端
        LOGE("child succeed, Finish.\n");
        exit(0);
    }
    else {
        // 父进程程序
        LOGE("开始等待子进程.\n");
        waitpid(pid,NULL,NULL); // 等待子进程结束
        int buf = 0;
        close(pipefd[1]); // 关闭写端
        read(pipefd[0], (void*)&buf, 4); // 从读端读取数据到buf
        close(pipefd[0]); // 关闭读端
        LOGI("子进程传递的内容为:%d\n", buf); // 输出内容
        // 判断子进程ptarce后的tracepid
        if (buf == 0) {
            LOGE("源码被修改了.\n");
            exit(0);
        } else {
            LOGE("源码没有被修改.\n");
        }
        return true;
    }
}

