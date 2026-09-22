// Disposable feasibility checkpoint: acquires only a newly owned in-memory certificate key.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
namespace Wela.Capi2KeyCheckpoint {
 public sealed class Result { public uint Flags,KeySpec; public bool CallerFree,Success; }
 public static class Native {
  [DllImport("crypt32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
  static extern bool CertSetCertificateContextProperty(IntPtr certificate,uint property,uint flags,ref IntPtr key);
  public static X509Certificate2 AttachOwnedKey(X509Certificate2 publicCertificate,CngKey ephemeralKey) {
   if(publicCertificate==null || publicCertificate.HasPrivateKey || ephemeralKey==null || !ephemeralKey.IsEphemeral || !String.IsNullOrEmpty(ephemeralKey.KeyName))throw new ArgumentException("Owned public certificate and unnamed ephemeral key required.");
   X509Certificate2 attached=new X509Certificate2(publicCertificate.RawData);
   try {
    // Same ownership contract used by dotnet CertificateHelpers.CopyWithEphemeralKey.
    // CngKey.Handle returns a duplicate; successful property78 transfers it to this new certificate.
    using(SafeNCryptKeyHandle duplicate=ephemeralKey.Handle) {
     IntPtr value=duplicate.DangerousGetHandle();
     if(!CertSetCertificateContextProperty(attached.Handle,78,0x40000000,ref value))throw new Win32Exception(Marshal.GetLastWin32Error());
     duplicate.SetHandleAsInvalid();
    }
    return attached;
   } catch {attached.Dispose();throw;}
  }
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
