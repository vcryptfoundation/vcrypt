################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../resampler/resample.c 

OBJS += \
./resampler/resample.o 

C_DEPS += \
./resampler/resample.d 


# Each subdirectory must supply rules for building sources it contributes
resampler/%.o: ../resampler/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc $(OTHERFLAGS) -I../../opus-1.1/installed/include -I"../../polarssl-1.2.8/include" -O0 -g3 -Wall -c -fmessage-length=0 -Wuninitialized -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


