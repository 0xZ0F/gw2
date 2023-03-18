#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <vector>

PVOID PatternScan(
	_In_ void* module,
	_In_ const char* signature
);