################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../audio.c \
../call.c \
../client.c \
../client_p2p.c \
../client_rsa.c \
../commands.c \
../common.c \
../connect.c \
../dh_keys.c \
../dh_sessions.c \
../dummycallbacks.c \
../fifo.c \
../packets.c \
../public_keys.c \
../queue.c \
../ssl_wrap.c \
../vcrypt_errors.c \
../voice_stuff.c \
../worker.c 

OBJS += \
./audio.o \
./call.o \
./client.o \
./client_p2p.o \
./client_rsa.o \
./commands.o \
./common.o \
./connect.o \
./dh_keys.o \
./dh_sessions.o \
./dummycallbacks.o \
./fifo.o \
./packets.o \
./public_keys.o \
./queue.o \
./ssl_wrap.o \
./vcrypt_errors.o \
./voice_stuff.o \
./worker.o 

C_DEPS += \
./audio.d \
./call.d \
./client.d \
./client_p2p.d \
./client_rsa.d \
./commands.d \
./common.d \
./connect.d \
./dh_keys.d \
./dh_sessions.d \
./dummycallbacks.d \
./fifo.d \
./packets.d \
./public_keys.d \
./queue.d \
./ssl_wrap.d \
./vcrypt_errors.d \
./voice_stuff.d \
./worker.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc $(OTHERFLAGS) -I../../opus-1.1/installed/include -I"../../polarssl-1.2.8/include" -O0 -g3 -Wall -c -fmessage-length=0 -Wuninitialized -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


