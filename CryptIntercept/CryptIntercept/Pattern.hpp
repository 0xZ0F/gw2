#pragma once

#include <vector>

PVOID PatternScan(
	_In_ void* module,
	_In_ const char* signature
);