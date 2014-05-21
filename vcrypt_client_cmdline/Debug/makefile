################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: vcrypt_client_cmdline

dependents:
	-cd ../../vcrypt_libclient/Debug && $(MAKE) all

# Tool invocations
vcrypt_client_cmdline: $(OBJS) $(USER_OBJS) ../../vcrypt_libclient/Debug/libvcrypt_libclient.a
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	gcc -L"../../vcrypt_libclient/Debug" -L"../../polarssl-1.2.8/library" -L../../opus-1.1/installed/lib/ -o "vcrypt_client_cmdline" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(OBJS)$(C_DEPS)$(EXECUTABLES) vcrypt_client_cmdline
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:
../../vcrypt_libclient/Debug/libvcrypt_libclient.a:

-include ../makefile.targets
