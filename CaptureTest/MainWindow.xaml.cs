using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CaptureTest
{
    /// <summary>
    /// https://docs.microsoft.com/ko-kr/windows/win32/gdi/capturing-an-image
    /// </summary>
    /// 

    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        delegate bool EnumThreadDelegate(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        static extern bool EnumThreadWindows(int dwThreadId, EnumThreadDelegate lpfn, IntPtr lParam);

        public enum TernaryRasterOperations : uint
        {
            SRCCOPY = 0x00CC0020,
            SRCPAINT = 0x00EE0086,
            SRCAND = 0x008800C6,
            SRCINVERT = 0x00660046,
            SRCERASE = 0x00440328,
            NOTSRCCOPY = 0x00330008,
            NOTSRCERASE = 0x001100A6,
            MERGECOPY = 0x00C000CA,
            MERGEPAINT = 0x00BB0226,
            PATCOPY = 0x00F00021,
            PATPAINT = 0x00FB0A09,
            PATINVERT = 0x005A0049,
            DSTINVERT = 0x00550009,
            BLACKNESS = 0x00000042,
            WHITENESS = 0x00FF0062,
            CAPTUREBLT = 0x40000000 //only if WinVer >= 5.0.0 (see wingdi.h)
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public int left;
            public int top;
            public int right;
            public int bottom;

            public override string ToString()
            {
                return string.Format("RECT - Left({0:d}) / Right({1:d}) / Top({2:d}) / Bottom({3:d}) / Width({4:d}) / Height({5:d}))", left, right, top, bottom, getWidth(), getHeight());
            }

            public int getWidth()
            {
                return right - left;
            }

            public int getHeight()
            {
                return bottom - top;
            }
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct BITMAP
        {
            public int bmType;
            public int bmWidth;
            public int bmHeight;
            public int bmWidthBytes;
            public short bmPlanes;
            public short bmBitsPixel;
            public byte[] bmBits;

            public static int getSize()
            {
                return 4 * 4 + 2 * 2 + 4;
            }
        }


        [StructLayout(LayoutKind.Sequential, Pack = 2)]
        public struct BITMAPFILEHEADER
        {
            public short bfType;
            public int bfSize;
            public short bfReserved1;
            public short bfReserved2;
            public int bfOffBits;

            public static int getSize()
            {
                return 14; // 6 + 8 = 14?
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 2)]
        public struct BITMAPINFOHEADER
        {
            public int biSize;
            public int biWidth;
            public int biHeight;
            public short biPlanes;
            public short biBitCount;
            public int biCompression;
            public int biSizeImage;
            public int biXPelsPerMeter;
            public int biYPelsPerMeter;
            public int biClrUsed;
            public int biClrImportant;

            public static int getSize()
            {
                return 4 * 9 + 2 * 2;
            }
        }

        [DllImport("user32.dll")]
        static extern bool GetWindowRect(int hWnd, ref RECT lpRect);

        [DllImport("user32.dll")]
        static extern bool SetWindowPos(int hWnd, int hWndInsertAfter, int x, int y, int cx, int cy, UInt32 uFlags);

        [DllImport("user32.dll")]
        static extern int GetDC(int hWnd);

        [DllImport("user32.dll")]
        static extern int GetSystemMetrics(int nIndex);

        [DllImport("user32.dll")]
        static extern int ReleaseDC(int hWnd, int hDC);

        [DllImport("user32.dll")]
        static extern bool GetClientRect(int hWnd, ref RECT lpRect);

        [DllImport("Gdi32.dll")]
        static extern int CreateCompatibleDC(int hWnd);

        [DllImport("Gdi32.dll")]
        static extern int SetStretchBltMode(int hdc, int mode);

        [DllImport("Gdi32.dll")]
        static extern bool StretchBlt(
            int hdcDest, // HDC
            int xDest,
            int yDest,
            int wDest,
            int hDest,
            int hdcSrc, // HDC
            int xSrc,
            int ySrc,
            int wSrc,
            int hSrc,
            uint rop); // DWORD

        [DllImport("Gdi32.dll")]
        static extern bool BitBlt(
            int hdc, // HDC
            int x,
            int y,
            int cx,
            int cy,
            int hdcSrc,// HDC
            int x1,
            int y1,
            uint rop); // DWORD

        [DllImport("Gdi32.dll")]
        static extern int CreateCompatibleBitmap(int hdc, int cx, int cy);

        [DllImport("Gdi32.dll")]
        static extern int GetObject(int h, int c, out BITMAP pv);

        [DllImport("Gdi32.dll")]
        static extern int GetDIBits(
        int hdc,
        int hbm,
        UInt32 start,
        UInt32 cLines,
        IntPtr lpvBits,
        ref BITMAPINFOHEADER lpbmi,
        UInt32 usage
        );

        [DllImport("Gdi32.dll")]
        static extern bool DeleteObject(int ho);

        [DllImport("Gdi32.dll")]
        static extern int SelectObject(int hdc, int h);

        [DllImport("kernel32.dll")]
        static extern int GlobalAlloc(int uFlags, int dwBytes);

        [DllImport("kernel32.dll")]
        static extern IntPtr GlobalLock(int hMem);

        [DllImport("kernel32.dll")]
        static extern int CreateFileA(
            string lpFileName,
            int dwDesiredAccess,
            int dwShareMode,
            IntPtr lpSecurityAttributes,
            int dwCreationDisposition,
            int dwFlagsAndAttributes,
            int hTemplateFile
        );

        [DllImport("kernel32.dll", EntryPoint = "WriteFile", SetLastError = true)]
        static extern bool WriteFile(
            int hFile,
            byte[] lpBuffer,
            int nNumberOfBytesToWrite,
            ref int lpNumberOfBytesWritten,
            IntPtr lpOverlapped
        );
        
        [DllImport("kernel32.dll")]
        static extern bool GlobalUnlock(int hMem);

        [DllImport("kernel32.dll")]
        static extern int GlobalFree(int hMem);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(int hObject);
        
        byte[] getBytes(BITMAPFILEHEADER str)
        {
            int size = Marshal.SizeOf(str);
            byte[] arr = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(str, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        byte[] getBytes(BITMAPINFOHEADER str)
        {
            int size = Marshal.SizeOf(str);
            byte[] arr = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(str, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        byte[] getBytes(IntPtr ptr, int size)
        {
            byte[] arr = new byte[size];
            Marshal.Copy(ptr, arr, 0, size);
            return arr;
        }

        [DllImport("kernel32.dll")]
        static extern UInt32 GetLastError();

        public void capture(int hWnd)
        {
            unsafe
            {
                int hdcScreen = GetDC(0);
                int hdcWindow = GetDC(hWnd);

                int hdcMemDC = CreateCompatibleDC(hdcWindow);

                if (hdcMemDC == 0)
                {
                    Debug.WriteLine("ERROR : hdcMemDC is null");
                    DeleteObject(hdcMemDC);
                    ReleaseDC(0, hdcScreen);
                    ReleaseDC(hWnd, hdcWindow);
                    return;
                }

                RECT rect = new RECT();
                GetClientRect(hWnd, ref rect);

                SetStretchBltMode(hdcWindow, 4/*HALFTONE*/);

                bool bResult = StretchBlt(hdcWindow, 0, 0,
                    rect.right, rect.bottom,
                    hdcScreen,
                    0,0,
                    GetSystemMetrics(0/*SM_CXSCREEN*/),
                    GetSystemMetrics(1/*SM_CYSCREEN*/),
                    (uint)TernaryRasterOperations.SRCCOPY/*SRCCOPY*/);

                if (!bResult)
                {
                    Debug.WriteLine("ERROR -> hdcMemDC is null");
                    DeleteObject(hdcMemDC);
                    ReleaseDC(0, hdcScreen);
                    ReleaseDC(hWnd, hdcWindow);
                    return;
                }

                int hbmScreen = CreateCompatibleBitmap(hdcWindow, rect.getWidth(), rect.getHeight());

                if(hbmScreen == 0)
                {
                    Debug.WriteLine("ERROR : hbmScreen is null");
                    DeleteObject(hbmScreen);
                    DeleteObject(hdcMemDC);
                    ReleaseDC(0, hdcScreen);
                    ReleaseDC(hWnd, hdcWindow);
                    return;
                }

                SelectObject(hdcMemDC, hbmScreen);

                bResult = BitBlt(hdcMemDC, 0, 0,
                    rect.getWidth(), rect.getHeight(),
                    hdcWindow, 0, 0, (uint)TernaryRasterOperations.SRCCOPY);

                if (!bResult)
                {
                    Debug.WriteLine("ERROR : BitBlt failed(" + GetLastError() + ")");
                    DeleteObject(hbmScreen);
                    DeleteObject(hdcMemDC);
                    ReleaseDC(0, hdcScreen);
                    ReleaseDC(hWnd, hdcWindow);
                    return;
                }
                GetObject(hbmScreen, BITMAP.getSize(), out BITMAP bmpScreen);
                //BITMAP bmpScreen = new BITMAP();
                //GetObject(hbmScreen, BITMAP.getSize(), ref bmpScreen);

                BITMAPFILEHEADER bitmapFileHeader;
                BITMAPINFOHEADER bitmapInforHeader;

                bitmapInforHeader.biSize = BITMAPINFOHEADER.getSize();
                bitmapInforHeader.biWidth = bmpScreen.bmWidth;
                bitmapInforHeader.biHeight = bmpScreen.bmHeight;
                bitmapInforHeader.biPlanes = 1;
                bitmapInforHeader.biBitCount = 32;
                bitmapInforHeader.biCompression = 0;// BI_RGB
                bitmapInforHeader.biSizeImage = 0;
                bitmapInforHeader.biXPelsPerMeter = 0;
                bitmapInforHeader.biYPelsPerMeter = 0;
                bitmapInforHeader.biClrUsed = 0;
                bitmapInforHeader.biClrImportant = 0;

                int dwBmpSize = ((bmpScreen.bmWidth * bitmapInforHeader.biBitCount + 31) / 32) * 4 * bmpScreen.bmHeight;
                int hDIB = GlobalAlloc(0x42/*GHND*/, dwBmpSize);
                IntPtr lpbitmap = GlobalLock(hDIB);

                GetDIBits(hdcWindow, hbmScreen, 0,
                    (UInt32)bmpScreen.bmHeight,
                    lpbitmap,
                    ref bitmapInforHeader, 0/*DIB_RGB_COLORS*/);

                int hFile = CreateFileA("capture.bmp", 0x40000000/*GENERIC_WRITE*/, 0, IntPtr.Zero,
                    2/*CREATE_ALWAYS*/, 128/*FILE_ATTRIBUTE_NORMAL*/, 0/*NULL*/);

                int dwSizeofDIB = dwBmpSize + BITMAPFILEHEADER.getSize() + BITMAPINFOHEADER.getSize();

                // Offset to where the actual bitmap bits start.
                bitmapFileHeader.bfOffBits = BITMAPFILEHEADER.getSize() + BITMAPINFOHEADER.getSize();

                bitmapFileHeader.bfSize = dwSizeofDIB;

                // bfType must always be BM for Bitmaps.
                bitmapFileHeader.bfType = 0x4D42; // BM.
                bitmapFileHeader.bfReserved1 = 0;
                bitmapFileHeader.bfReserved2 = 0;

                int dwBytesWritten = 0;
                WriteFile(hFile, getBytes(bitmapFileHeader), Marshal.SizeOf(bitmapFileHeader), ref dwBytesWritten, IntPtr.Zero);
                WriteFile(hFile, getBytes(bitmapInforHeader), Marshal.SizeOf(bitmapInforHeader), ref dwBytesWritten, IntPtr.Zero);
                WriteFile(hFile, getBytes(lpbitmap, dwBmpSize), dwBmpSize, ref dwBytesWritten, IntPtr.Zero);

                // Unlock and Free the DIB from the heap.
                GlobalUnlock(hDIB);
                GlobalFree(hDIB);

                // Close the handle for the file that was created.
                CloseHandle(hFile);

                DeleteObject(hbmScreen);
                DeleteObject(hdcMemDC);
                ReleaseDC(0, hdcScreen);
                ReleaseDC(hWnd, hdcWindow);
            }
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            Process[] processes = Process.GetProcessesByName("notepad");

            if (processes.Length == 0)
            {
                return;
            }

            foreach (Process p in processes )
            {
                Debug.WriteLine("=Process name : "+ p.ProcessName + ", MainHandle : " + p.MainWindowHandle.ToInt32());
                RECT rect = new RECT();
                bool ret = GetWindowRect(p.MainWindowHandle.ToInt32(), ref rect);

                if(ret == false)
                {
                    Debug.WriteLine("Failed getting window rect");
                    return;
                }

                Debug.WriteLine("=GetWindowRect" + rect.ToString());

                capture(p.MainWindowHandle.ToInt32());
            }
        }
    }
}
