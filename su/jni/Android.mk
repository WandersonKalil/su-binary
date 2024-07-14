LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := su
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_LDLIBS := -llog -lc
LOCAL_SRC_FILES := su/su.c su/utils.c su/daemon.c
include $(BUILD_EXECUTABLE)
