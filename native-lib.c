//
// Created by piracy on 5/7/17.
//
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <jni.h>
#include <assert.h>
#include <android/log.h>
#include <stdbool.h>
#include <pthread.h>
#include <zconf.h>





#define LOGI(...) while(0){}
#define NELEM(x)  (sizeof(x)/sizeof((x)[0]))

void  readStatus();

jboolean readProcInfo(JNIEnv* env, jobject thiz )
{

 

      pthread_t pthreadId = 3;



    pthread_create(&pthreadId,NULL,readStatus,NULL);


    return false;
}

void  readStatus(){
    char path[40];
    char str[1024];

    sprintf(path, "/proc/%d/status",getpid());


    while(true) {
        FILE *file = fopen(path, "r");
        if (file == NULL) {
            __android_log_print(ANDROID_LOG_INFO, "piracy", "文件为空");

        }
        int lines = 0;
        int code = feof(file);      //返回0，表示文件未结束
        while (!code) {    //如果文件未结束，就循环读取
            fgets(str, 1024, file);
            lines++;
            if (lines == 6) {         //tracerPid 的值
                int traceId = convertNumber(str);
                if (traceId != 0) {
                    __android_log_print(ANDROID_LOG_INFO, "piracy", "检测有反调试存在");
                    exit(0);
                }
                __android_log_print(ANDROID_LOG_INFO, "piracy", "检测正常");
                break;
            }
        }
        fclose(file);
        sleep(3);
    }

}

/**
 * 字符串转换成数字
 */
int convertNumber(char *str){
    char count[10];
    int i= 0;
    while(*str){
        if(*str >= 48 && *str <=57){
            count[i++] = *str;
        }
        str++;
    }
    return atoi(count);
}

/**
* 方法对应表
*/
static JNINativeMethod gMethods[] = {
        {"readProcInfo", "()Z", (void*)readProcInfo}

};

/*
* 为某一个类注册本地方法
*/
static int registerNativeMethods(JNIEnv* env
        , const char* className
        , JNINativeMethod* gMethods, int numMethods) {
    jclass clazz;
    clazz = (*env)->FindClass(env, className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if ((*env)->RegisterNatives(env, clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}
/*
* 为所有类注册本地方法
*/
static int registerNatives(JNIEnv* env) {

jclass clazz = (*env) -> FindClass(env, JNIREG_CLASS);//通过文件绝对路径获取jclass
(*env)->RegisterNatives(env, clazz, gMethods, NELEM(gMethods));//调用JNIEnv的RegisterNative函数注册，NELEM(gMethods)是用来计算gMethods的大小
}

/*
* System.loadLibrary("lib")时调用
* 如果成功返回JNI版本, 失败返回-1
*/
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {


    LOGI("jni_OnLoad begin");//需要自定义日志#include <android/log.h>
    JNIEnv* env = NULL;
    jint result = -1;

    if ((*vm)->GetEnv(vm,(void**) &env, JNI_VERSION_1_4) != JNI_OK) {
        LOGI("ERROR: GetEnv failed\n");
        return -1;
    }
    assert(env != NULL);//需要添加#include <assert.h>

    registerNatives(env);

    return JNI_VERSION_1_4;//在源码中已经写死，正确的JNI_VERSION必须是JNI_VERSION_1_2或JNI_VERSION_1_4或JNI_VERSION_1_6
}
