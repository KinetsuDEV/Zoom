namespace Zoom
{
    using GameHelper;
    using GameHelper.Plugin;
    using Newtonsoft.Json;
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Runtime.InteropServices;

    public sealed class Zoom : PCore<ZoomSettings>
    {
        private string SettingPathname => Path.Join(this.DllDirectory, "config", "settings.txt");

        public override void OnDisable()
        {
        }

        public override void OnEnable(bool isGameOpened)
        {
            if (File.Exists(this.SettingPathname))
            {
                var content = File.ReadAllText(this.SettingPathname);
                var serializerSettings = new JsonSerializerSettings() { ObjectCreationHandling = ObjectCreationHandling.Replace };
                this.Settings = JsonConvert.DeserializeObject<ZoomSettings>(content, serializerSettings);
            }
        }

        public override void SaveSettings()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(this.SettingPathname));
            var settingsData = JsonConvert.SerializeObject(this.Settings, Formatting.Indented);
            File.WriteAllText(this.SettingPathname, settingsData);
        }

        public override void DrawSettings()
        {
        }

        public override void DrawUI()
        {
            if (baseAddress == IntPtr.Zero && Core.Process.Pid != 0)
            {
                InitializeProcess();
                ApplyZoomPatch();
            }
        }

        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint MEM_FREE = 0x00010000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint PAGE_NOACCESS = 0x01;

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint size, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        IntPtr baseAddress = IntPtr.Zero;
        IntPtr baseAllocation = IntPtr.Zero;
        nint processHandle = 0;
        SigScanSharp SigScan;
        Process process;

        private void InitializeProcess()
        {
            process = Process.GetProcessById((int)Core.Process.Pid);

            baseAddress = process.Modules[0].BaseAddress;
            processHandle = OpenProcess(0x1F0FFF, false, process.Id);

            baseAllocation = AllocateMemory(baseAddress, 0x1000);

            SigScan = new SigScanSharp(processHandle);
            SigScan.SelectModule(process.Modules[0]);
        }

        private IntPtr AllocateMemory(IntPtr baseAddress, uint size)
        {
            IntPtr freeRegion = FindNextFreeMemoryRegion(baseAddress, size);
            if (freeRegion == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            return VirtualAllocEx(processHandle, freeRegion, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }

        IntPtr FindNextFreeMemoryRegion(IntPtr startAddress, uint size)
        {
            MEMORY_BASIC_INFORMATION mbi;
            IntPtr address = startAddress - 0x10000;

            while (VirtualQueryEx(processHandle, address, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != IntPtr.Zero)
            {
                if (mbi.State == MEM_FREE && mbi.RegionSize.ToInt64() >= size)
                {
                    return mbi.BaseAddress;
                }

                address = IntPtr.Add(mbi.BaseAddress, (int)mbi.RegionSize);
            }

            return IntPtr.Zero;
        }

        IntPtr FindUnusedSection(IntPtr startAddress, int maxBytesToCheck, int count)
        {
            const int bufferSize = 4096;
            byte[] buffer = new byte[bufferSize];
            IntPtr address = startAddress;
            int bytesRead;

            while (maxBytesToCheck > 0)
            {
                int bytesToRead = Math.Min(bufferSize, maxBytesToCheck);

                if (!ReadProcessMemory(processHandle, address, buffer, (uint)bytesToRead, out bytesRead))
                {
                    break;
                }

                int zeroCount = 0;

                for (int i = 0; i < bytesRead; i++)
                {
                    if (buffer[i] == 0x00)
                    {
                        zeroCount++;
                        if (zeroCount == count)
                        {
                            return IntPtr.Add(address, i - count + 1);
                        }
                    }
                    else
                    {
                        zeroCount = 0;
                    }
                }

                address = IntPtr.Add(address, bytesRead);
                maxBytesToCheck -= bytesRead;
            }

            return IntPtr.Zero;
        }

        private bool WriteValueToMemory(IntPtr address, float value)
        {
            byte[] valueBytes = BitConverter.GetBytes(value);
            if (!WriteProcessMemory(processHandle, address, valueBytes, (uint)valueBytes.Length, out _))
            {
                return false;
            }

            return true;
        }

        private bool WriteJumpToMemory(IntPtr originalAddress, long jumpOffset, int nopSize, bool useCustomNOP)
        {
            Span<byte> jumpInstruction = stackalloc byte[5];
            jumpInstruction[0] = 0xE9;
            BitConverter.TryWriteBytes(jumpInstruction.Slice(1, 4), (int)jumpOffset);

            Span<byte> nopInstruction = stackalloc byte[nopSize];
            if (useCustomNOP)
            {

                if (nopSize == 4)
                {
                    nopInstruction[0] = 0x0F;
                    nopInstruction[1] = 0x1F;
                    nopInstruction[2] = 0x40;
                    nopInstruction[3] = 0x00;
                }
                else if (nopSize == 3)
                {
                    nopInstruction[0] = 0x0F;
                    nopInstruction[1] = 0x1F;
                    nopInstruction[2] = 0x00;
                }
            }
            else
            {
                for (int i = 0; i < nopSize; i++)
                {
                    nopInstruction[i] = 0x90;
                }
            }

            if (!WriteProcessMemory(processHandle, originalAddress, jumpInstruction.ToArray(), (uint)jumpInstruction.Length, out _))
            {
                return false;
            }

            if (!WriteProcessMemory(processHandle, IntPtr.Add(originalAddress, jumpInstruction.Length), nopInstruction.ToArray(), (uint)nopInstruction.Length, out _))
            {
                return false;
            }

            return true;
        }

        private bool WriteMinssInstruction(IntPtr baseAddress, IntPtr patchAddress, IntPtr origAddress)
        {
            long relativeValueAddr = baseAddress.ToInt64() - IntPtr.Add(patchAddress, 8).ToInt64();
            long relativeJumpBackAddr = origAddress.ToInt64() + 3 - IntPtr.Add(patchAddress, 8).ToInt64();

            Span<byte> newCode = stackalloc byte[14];
            newCode[0] = 0xF3;
            newCode[1] = 0x0F;
            newCode[2] = 0x5D;
            newCode[3] = 0x0D;

            BitConverter.TryWriteBytes(newCode.Slice(4, 4), (int)relativeValueAddr);

            newCode[8] = 0xE9;
            BitConverter.TryWriteBytes(newCode.Slice(9, 4), (int)relativeJumpBackAddr);

            newCode[13] = 0xC3;

            return WriteProcessMemory(processHandle, patchAddress, newCode.ToArray(), (uint)newCode.Length, out _);
        }

        private void ApplyZoomPatch()
        {
            IntPtr zoomMemoryAllocation = FindUnusedSection(baseAddress - 0x10000, 1000, 10);
            if (zoomMemoryAllocation == IntPtr.Zero) return;

            if (!WriteValueToMemory(zoomMemoryAllocation, 30.0f)) return;

            IntPtr zoomPatchAddress = IntPtr.Add(zoomMemoryAllocation, sizeof(float) + 2);

            IntPtr patchAddress = (nint)SigScan.FindPattern("F3 0F 5D ? ? ? ? ? F3 0F 11 ? ? ? ? ? C6", out _);
            if (patchAddress == IntPtr.Zero)
            {
                return;
            }

            long relativeAddress = zoomPatchAddress.ToInt64() - IntPtr.Add(patchAddress, 5).ToInt64();

            if (!WriteJumpToMemory(patchAddress, relativeAddress, 3, false)) return;

            IntPtr afterMinssAddress = IntPtr.Add(zoomPatchAddress, 5 + 3);
            long zoomH1RelativeAddress = zoomMemoryAllocation.ToInt64() - afterMinssAddress.ToInt64();

            if (!WriteMinssInstruction(zoomMemoryAllocation, zoomPatchAddress, patchAddress)) return;
        }
    }
}
