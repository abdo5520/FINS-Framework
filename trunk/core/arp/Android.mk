LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := fins_arp
#TEST_FILES := test_arp.c
#LOCAL_SRC_FILES := arp.c arp_in_out.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_STATIC_LIBRARIES := fins_common fins_data_structure fins_switch
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
LOCAL_EXPORT_LDLIBS := -lz
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID
include $(BUILD_STATIC_LIBRARY)

$(call import-module,common)
$(call import-module,core/data_structure)
$(call import-module,core/switch)