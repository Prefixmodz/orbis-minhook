#include "orbis.h"

thread* GetByName(const char* name)
{
	auto libkernel = GetModuleAddress(8193);
	if (libkernel == 0)
	{
		printf("Failed to get libkernel address\n");
		return nullptr;
	}

	auto currentThread = *reinterpret_cast<thread**>(GetAbsoluteAddress(0x0058248, libkernel));
	while (currentThread != nullptr)
	{
		char threadName[32];
		if (sceKernelGetThreadName(currentThread->tid, threadName) < 0)
		{
			return nullptr;
		}

		if (strcmp(threadName, name) == 0)
			return currentThread;

		currentThread = currentThread->next;
	}

	return nullptr;
}

thread* GetById(uint32_t id)
{
	auto libkernel = GetModuleAddress(8193);
	if (libkernel == 0)
	{
		printf("Failed to get libkernel address\n");
		return nullptr;
	}

	auto currentThread = *reinterpret_cast<thread**>(GetAbsoluteAddress(0x0058248, libkernel));
	while (currentThread != nullptr)
	{
		if (currentThread->tid == id)
			return currentThread;

		currentThread = currentThread->next;
	}
	return nullptr;
}