# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_CFLAGS := -DHAVE_CONFIG_H
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../../../opus-android/jni/installed/include/ \
	$(LOCAL_PATH)/../../../polarssl-1.2.8/include
LOCAL_MODULE := vcrypt_libclient
LOCAL_SRC_FILES := \
../../client.c \
../../client_p2p.c \
../../client_rsa.c \
../../common.c \
../../connect.c \
../../dummycallbacks.c \
../../fifo.c \
../../queue.c \
../../vcrypt_errors.c \
../../worker.c \
../../public_keys.c \
../../packets.c \
../../dh_keys.c \
../../dh_sessions.c \
../../commands.c \
../../ssl_wrap.c \
../../audio.c \
../../resampler/resample.c \
../../call.c

include $(BUILD_STATIC_LIBRARY)

