################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../auth.c \
../config.c \
../contacts.c \
../database.c \
../offline_events.c \
../public_keys.c \
../server.c \
../workers.c 

OBJS += \
./auth.o \
./config.o \
./contacts.o \
./database.o \
./offline_events.o \
./public_keys.o \
./server.o \
./workers.o 

C_DEPS += \
./auth.d \
./config.d \
./contacts.d \
./database.d \
./offline_events.d \
./public_keys.d \
./server.d \
./workers.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc $(OTHERFLAGS) -I"../../vcrypt_libclient" -I"../../polarssl-1.2.8/include" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

server.o: ../server.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc $(OTHERFLAGS) -I"../../vcrypt_libclient" -I"../../polarssl-1.2.8/include" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"server.d" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


