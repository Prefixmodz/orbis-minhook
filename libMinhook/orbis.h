#pragma once

#include <stdio.h>
#include <stdint.h>
#include <string>
#include <KernelExt.h>

template<typename T = uintptr_t>
T GetModuleAddress(std::string module)
{
	SceKernelModule handle = sceKernelLoadStartModule(module.data(), 0, nullptr, 0, nullptr, nullptr);
	if (handle > 0)
	{
		SceKernelModuleInfo moduleInfo;
		moduleInfo.size = sizeof(SceKernelModuleInfo);
		if (sceKernelGetModuleInfo(handle, &moduleInfo) == 0)
		{
			return reinterpret_cast<T>(moduleInfo.segmentInfo[0].address);
		}
	}

	return 0;
}

template<typename T = uintptr_t>
T GetModuleAddress(SceKernelModule handle)
{
	SceKernelModuleInfo moduleInfo;
	moduleInfo.size = sizeof(SceKernelModuleInfo);
	if (sceKernelGetModuleInfo(handle, &moduleInfo) == 0)
	{
		return reinterpret_cast<T>(moduleInfo.segmentInfo[0].address);
	}

	return 0;
}

template<typename T = uintptr_t>
T GetAbsoluteAddress(uintptr_t address, uintptr_t base = -1)
{
	return reinterpret_cast<T>((base == -1 ? GetModuleAddress(0) : base) + address);
}

template<typename T = uintptr_t>
T GetRelativeAddress(uintptr_t address, uintptr_t base)
{
	return reinterpret_cast<T>(address - base);
}

template<typename T = uintptr_t>
T GetExport(SceKernelModule handle, std::string symbol)
{
	uint64_t libSymbolAddr;
	if (sceKernelDlsym(handle, symbol.data();, (void**)&libSymbolAddr) == 0)
	{
		return reinterpret_cast<T>(libSymbolAddr);
	}

	return 0;
}

thread* GetByName(const char* name);
thread* GetById(uint32_t id);

#include <Defs/KernelExtDefs.h>