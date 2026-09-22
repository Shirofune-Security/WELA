// Disposable feasibility checkpoint: acquires only a newly owned in-memory certificate key.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
namespace Wela.Capi2KeyCheckpoint {
 public sealed class Result { public uint Flags,KeySpec; public bool CallerFree,Success; }
 public static class Native {
  public const uint Flags=0x40049; // CNG only, silent, no healing, cache on owned certificate only
  [DllImport("crypt32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
  static extern bool CryptAcquireCertificatePrivateKey(IntPtr certificate,uint flags,IntPtr parameters,out IntPtr key,out uint spec,[MarshalAs(UnmanagedType.Bool)]out bool callerFree);
  [DllImport("ncrypt.dll",ExactSpelling=true)] static extern int NCryptFreeObject(IntPtr key);
  public static Result Acquire(X509Certificate2 certificate) {
   if(certificate==null || !certificate.HasPrivateKey)throw new ArgumentException("Owned certificate with ephemeral private key required.");
   IntPtr key=IntPtr.Zero;uint spec=0;bool free=false;
   try {
    bool ok=CryptAcquireCertificatePrivateKey(certificate.Handle,Flags,IntPtr.Zero,out key,out spec,out free);
    int error=Marshal.GetLastWin32Error();GC.KeepAlive(certificate);
    if(!ok)throw new Win32Exception(error);
    if(key==IntPtr.Zero || spec!=0xffffffff)throw new InvalidOperationException("Unexpected acquired CNG key handle.");
    return new Result {Flags=Flags,KeySpec=spec,CallerFree=free,Success=ok};
   } finally {if(free && key!=IntPtr.Zero && spec==0xffffffff){int status=NCryptFreeObject(key);if(status!=0)throw new Win32Exception(status);}}
  }
 }
}
