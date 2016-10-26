// decrypt.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

bool UnobfuscateData (unsigned char* input_buffer_ptr, unsigned input_buffer_size, unsigned char** output_buffer_ptr, size_t *output_buffer_size_ptr)
{
	SIZE_T output_buffer_size; // ST08_4@2
	BYTE* decrypted_buffer; // eax@2
	int rand_seed; // eax@3
	BYTE* moving_input_ptr; // edx@3
	BYTE* moving_output_ptr; // esi@3
	size_t i; // edi@3
	char v14; // cl@4
	char v15; // cl@4
	unsigned int v16; // edi@5
	unsigned int v17; // eax@5
	char v19; // cl@7
	bool result; // eax@8
	int v21; // [sp+8h] [bp-4h]@4

	output_buffer_size = input_buffer_size - 4;
	*output_buffer_size_ptr = output_buffer_size;

	if (input_buffer_size == 4)
	{
		*output_buffer_ptr = nullptr;
		result = true;
	}
	else
	{
		decrypted_buffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, output_buffer_size);
		*output_buffer_ptr = decrypted_buffer;

		if (decrypted_buffer)
		{
			memset(decrypted_buffer, 0, *output_buffer_size_ptr);
			rand_seed = *(int*)input_buffer_ptr;
			moving_input_ptr = (BYTE*)((int*)input_buffer_ptr + 1);
			moving_output_ptr = decrypted_buffer;
			for (i = *output_buffer_size_ptr >> 2; i; --i)
			{
				rand_seed = 214013 * rand_seed + 2531011;
				v14 = rand_seed ^ *(BYTE *)moving_input_ptr;
				v21 = rand_seed;
				*(BYTE *)moving_output_ptr = v14;
				*(BYTE *)(moving_output_ptr + 1) = BYTE1(rand_seed) ^ *(_BYTE *)(moving_input_ptr + 1);
				*(_BYTE *)(moving_output_ptr + 2) = BYTE2(v21) ^ *(_BYTE *)(moving_input_ptr + 2);
				v15 = *(_BYTE *)(moving_input_ptr + 3);
				moving_input_ptr += 4;
				*(_BYTE *)(moving_output_ptr + 3) = BYTE3(v21) ^ v15;
				moving_output_ptr += 4;
			}
			v16 = 0;
			v21 = 214013 * rand_seed + 2531011;
			v17 = *output_buffer_size_ptr & 3;
			if (*output_buffer_size_ptr & 3)
			{
				do
				{
					++moving_input_ptr;
					v19 = *(_BYTE *)(moving_input_ptr - 1) ^ *((_BYTE *)&v21 + v16++);
					*(_BYTE *)(moving_output_ptr - 1) = v19;
				} while (v16 < v17);
			}
			result = true;
		}
		else
		{
			result = false;
		}
	}
	return result;
}

void DumpData(PUCHAR Data, size_t DataLength)
{
	ULONG k, m;

	for (k = 0; k < DataLength / 16; ++k)
	{
		for (m = 0; m < 16; ++m)
		{
			if (isprint(Data[k * 16 + m]))
				printf("%c ", Data[k * 16 + m]);
			else
				printf(". ");
		}

		printf("\n");
	}

	for (k = 0; k < DataLength - (DataLength / 16) * 16; ++k)
	{
		if (isprint(Data[(DataLength / 16) * 16 + k]))
			printf("%c ", Data[(DataLength / 16) * 16 + k]);
		else
			printf(". ");
	}

	printf("\n\n");
}


template<typename T, size_t N>
size_t constexpr array_size(T(&)[N]) noexcept { return N; }

void main()
{
	HKEY hKey = nullptr;
	BYTE* pbDecrypted = nullptr;
	size_t size_of_decrypted = 0;

	/*BYTE Encrypted[] = {0x01, 0x00, 0x00, 0x00, 0xa0, 0x27, 0xe7, 0x98, 0xe2, 0xa7, 0xd7, 0x12, 0x54, 0xf3, 0xe0, 0x07, 0x75, 0xad,
		0x64, 0x82, 0x60, 0xaa, 0x6a, 0x3f, 0x96, 0x2f, 0x55, 0x96, 0xff, 0x2b, 0x90, 0x6c, 0xcd, 0x92, 0x1f, 0x8a, 0x69, 0x4a, 0x20, 0x7d, 0x89, 0x5f, 0xc1,
		0xfb, 0x0c, 0x6c, 0xe4, 0x88, 0x35, 0x62, 0xec, 0x56, 0xd8, 0x2b, 0xe5, 0x9d, 0x85, 0xcb, 0x2b, 0x4a, 0xa9, 0xf7, 0x04, 0xcb, 0x46, 0x50, 0x6b, 0x52,
		0x1e, 0xb2, 0xd6, 0x7f, 0x5c, 0x48, 0x99, 0xca, 0x4d, 0x52, 0x66, 0xe3, 0x20, 0xd0, 0x76, 0x0b, 0x97, 0x81, 0x52, 0xe6, 0x8a, 0xe8, 0xe1, 0x29, 0x0e,
		0x40, 0x4e, 0x33, 0x99, 0x96, 0x61, 0x67, 0xf8, 0x7e, 0xd4, 0x53, 0x92, 0x67, 0x8c, 0x1f, 0x6b, 0xae, 0xd1, 0xb3, 0x5a, 0xb2, 0x79, 0xde};*/

	LONG lResult = RegOpenKeyEx(
		HKEY_CURRENT_USER,
		TEXT("Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\Protected - It is a violation of Windows Policy to modify. See aka.ms/browserpolicy"),
		0,
		KEY_QUERY_VALUE,
		&hKey);

	if (lResult != ERROR_SUCCESS)
	{
		printf("Failed to open Edge registry key. Error code 0x%X\n", lResult);
		return;
	}

	DWORD BufferSize = USN_PAGE_SIZE;
	DWORD cbData;
	DWORD dwRet;

	BYTE* pbEncrypted = (BYTE*)malloc(BufferSize);
	cbData = BufferSize;

	printf("Retrieving the data...\n");

	dwRet = RegQueryValueEx(
		hKey,
		TEXT("ProtectedHomepages"),
		NULL,
		NULL,
		(LPBYTE)pbEncrypted,
		&cbData);

	while (dwRet == ERROR_MORE_DATA)
	{
		// Get a buffer that is big enough.

		BufferSize += USN_PAGE_SIZE;
		pbEncrypted = (BYTE*)realloc(pbEncrypted, BufferSize);
		cbData = BufferSize;

		printf(".");
		dwRet = RegQueryValueEx(
			hKey,
			TEXT("ProtectedHomepages"),
			NULL,
			NULL,
			(LPBYTE)pbEncrypted,
			&cbData);
	}

	if (dwRet == ERROR_SUCCESS)
		printf("Have read %d bytes from the value\n", cbData);
	else
	{
		printf("RegQueryValueEx failed (%d)\n", dwRet);
		RegCloseKey(hKey);
		return;
	}

	if (UnobfuscateData(pbEncrypted + 4, cbData - 4, (unsigned char**)&pbDecrypted, &size_of_decrypted))
	{
		printf("Succesfully decrypted Edge ProtectedHomepages value (%d)\n", dwRet);

		if (pbDecrypted)
		{
			DumpData(pbDecrypted, size_of_decrypted);
			HeapFree(GetProcessHeap(), 0, pbDecrypted);
		}
	}
	else
		printf("UnobfuscateData failed (%d)\n", dwRet);

	RegCloseKey(hKey);
	int ch = getchar();
} 
