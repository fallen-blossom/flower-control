using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;

// Installer-only protected root creation and recovery metadata repair. Never
// touches version images or journal contents. Existing protected labels and
// effective access must survive.
public static class FlowerRecoveryProtection
{
    // Replaced only while sealing a prepared script, never from environment.
    private const string PreparedProgramRoot = "@@PREPARED_PROGRAM_ROOT@@";
    static string RecoveryRoot { get { return PreparedProgramRoot[0] == '@'
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FlowerControl", "HighHelper", "recovery")
        : Path.Combine(PreparedProgramRoot, "recovery"); } }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint GetNamedSecurityInfoW(string p, int type, uint info, out IntPtr o, out IntPtr g, out IntPtr d, out IntPtr s, out IntPtr sd);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint SetNamedSecurityInfoW(string p, int type, uint info, IntPtr o, IntPtr g, IntPtr d, IntPtr s);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr sd, out uint size);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetSecurityDescriptorSacl(IntPtr sd, out bool present, out IntPtr sacl, out bool defaulted);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr sd);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
    [StructLayout(LayoutKind.Sequential)] struct Attributes { public uint Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateDirectoryW(string path, ref Attributes attrs);
    sealed class Entry { public string Path, Access, RawAccess, Label, Hash; public bool Directory; }
    public sealed class Result { public int Directories, Files, NormalizedAclFlags; public bool BytesUnchanged = true, EffectiveAccessUnchanged = true; }
    static string Root(string path)
    {
        string expected = RecoveryRoot;
        if (!String.Equals(path, expected, StringComparison.OrdinalIgnoreCase)) throw new IOException("recovery_scope_rejected");
        for (string part=path; part!=null; part=Path.GetDirectoryName(part))
            if (Directory.Exists(part) && (File.GetAttributes(part)&FileAttributes.ReparsePoint)!=0) throw new IOException("recovery_link_rejected");
        return path;
    }
    static RawSecurityDescriptor Read(string path)
    {
        IntPtr o,g,d,s,sd; uint result=GetNamedSecurityInfoW(path,1,0x17,out o,out g,out d,out s,out sd);
        if(result!=0) throw new Win32Exception((int)result,"recovery_security_unreadable");
        try { byte[] bytes=new byte[GetSecurityDescriptorLength(sd)]; Marshal.Copy(sd,bytes,0,bytes.Length); return new RawSecurityDescriptor(bytes,0); } finally { LocalFree(sd); }
    }
    static string Access(RawSecurityDescriptor sd)
    {
        if(sd.Owner==null || (sd.Owner.Value!="S-1-5-32-544" && sd.Owner.Value!="S-1-5-18") || sd.Group==null || sd.DiscretionaryAcl==null)
            throw new IOException("recovery_access_unprotected");
        var text=new StringBuilder(sd.Owner.Value+"|"+sd.Group.Value+"|"+(int)(sd.ControlFlags&ControlFlags.DiscretionaryAclProtected));
        foreach(GenericAce raw in sd.DiscretionaryAcl) {
            var ace=raw as CommonAce;
            if(ace==null || ace.IsCallback || (ace.AceQualifier!=AceQualifier.AccessAllowed && ace.AceQualifier!=AceQualifier.AccessDenied)) throw new IOException("recovery_access_unsupported");
            if(ace.AceQualifier==AceQualifier.AccessAllowed && (ace.AccessMask&0x500D0156)!=0 && ace.SecurityIdentifier.Value!="S-1-5-18" && ace.SecurityIdentifier.Value!="S-1-5-32-544") throw new IOException("recovery_access_unprotected");
            text.Append("|"+(int)ace.AceQualifier+":"+ace.SecurityIdentifier.Value+":"+ace.AccessMask+":"+(int)(ace.AceFlags&~AceFlags.Inherited));
        }
        return text.ToString();
    }
    static string Label(RawSecurityDescriptor sd, bool required, bool inherit)
    {
        var sacl=sd.SystemAcl;
        if(sacl==null || sacl.Count==0) { if(required) throw new IOException("recovery_high_label_missing"); return ""; }
        if(sacl.Count!=1 || (int)sacl[0].AceType!=17) throw new IOException("recovery_label_unsupported");
        var ace=sacl[0]; byte[] bytes=new byte[ace.BinaryLength]; ace.GetBinaryForm(bytes,0);
        var sid=new System.Security.Principal.SecurityIdentifier(bytes,8);
        if(bytes.Length!=8+sid.BinaryLength || BitConverter.ToUInt32(bytes,4)!=1 || sid.Value!="S-1-16-12288" || (ace.AceFlags&AceFlags.InheritOnly)!=0)
            throw new IOException("recovery_high_label_rejected");
        if(inherit && (ace.AceFlags&(AceFlags.ObjectInherit|AceFlags.ContainerInherit))!=(AceFlags.ObjectInherit|AceFlags.ContainerInherit)) throw new IOException("recovery_inheritance_missing");
        // Framework SDDL serialization with Audit omits mandatory-label
        // CustomAces. Retain the actual ACE bytes and SACL protection bit.
        return Convert.ToBase64String(bytes)+":"+(int)(sd.ControlFlags&ControlFlags.SystemAclProtected);
    }
    static SortedDictionary<string,Entry> Inventory(string root, List<FileStream> pins)
    {
        var result=new SortedDictionary<string,Entry>(StringComparer.OrdinalIgnoreCase); var pending=new Stack<string>(); pending.Push(root);
        while(pending.Count!=0) {
            string path=pending.Pop(); var attrs=File.GetAttributes(path);
            if((attrs&FileAttributes.ReparsePoint)!=0 || result.Count>=4096) throw new IOException("recovery_inventory_rejected");
            bool dir=(attrs&FileAttributes.Directory)!=0;
            if(!dir && Array.IndexOf(new[]{".exe",".dll",".com",".scr"},Path.GetExtension(path).ToLowerInvariant())>=0) throw new IOException("recovery_image_rejected");
            var sd=Read(path); string hash=null;
            if(!dir) { var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read); pins.Add(file); using(var sha=SHA256.Create()) hash=Convert.ToBase64String(sha.ComputeHash(file)); }
            result.Add(path,new Entry{Path=path,Directory=dir,Access=Access(sd),RawAccess=sd.GetSddlForm(AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access),Label=Label(sd,false,false),Hash=hash});
            if(dir) foreach(string child in Directory.GetFileSystemEntries(path)) pending.Push(child);
        }
        return result;
    }
    static void SetLabel(string root, bool directory)
    {
        IntPtr sd; uint size;
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(directory ? "S:(ML;OICI;NW;;;HI)" : "S:(ML;;NW;;;HI)",1,out sd,out size)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { bool present,defaulted; IntPtr sacl;
            if(!GetSecurityDescriptorSacl(sd,out present,out sacl,out defaulted)||!present) throw new IOException("recovery_label_descriptor_rejected");
            uint result=SetNamedSecurityInfoW(root,1,0x10,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,sacl);
            if(result!=0) throw new Win32Exception((int)result,"recovery_label_not_applied");
        } finally { LocalFree(sd); }
    }
    public static Result TightenStopped(string path)
    {
        Root(path); var pins=new List<FileStream>();
        try {
            var before=Inventory(path,pins); SetLabel(path,true);
            // Protected, non-inheriting legacy ancestors can block root
            // propagation. Tighten only still-unlabelled snapshot members;
            // never replace an existing child label or its protected parent.
            foreach(var pair in before) {
                if(pair.Value.Label=="" && Label(Read(pair.Key),false,false)=="") SetLabel(pair.Key,pair.Value.Directory);
            }
            var after=Inventory(path,pins); var report=new Result();
            if(before.Count!=after.Count) throw new IOException("recovery_inventory_changed");
            foreach(var pair in before) { Entry a;
                if(!after.TryGetValue(pair.Key,out a) || pair.Value.Directory!=a.Directory || pair.Value.Access!=a.Access || pair.Value.Hash!=a.Hash) throw new IOException("recovery_data_or_access_changed");
                var sd=Read(pair.Key);
                try { Label(sd,true,pair.Key==path); } catch(Exception error) { throw new IOException(error.Message+":"+pair.Key,error); }
                if(pair.Key!=path && pair.Value.Label!="" && pair.Value.Label!=a.Label) throw new IOException("recovery_existing_label_changed");
                if(pair.Value.RawAccess!=a.RawAccess) report.NormalizedAclFlags++;
                if(a.Directory) report.Directories++; else report.Files++;
            }
            return report;
        } finally { foreach(var pin in pins) pin.Dispose(); }
    }
    public static void Ensure(string path)
    {
        Root(path);
        if(!Directory.Exists(path)) {
            IntPtr sd; uint size;
            if(!ConvertStringSecurityDescriptorToSecurityDescriptorW("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)S:(ML;OICI;NW;;;HI)",1,out sd,out size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try { var attrs=new Attributes{Length=(uint)Marshal.SizeOf(typeof(Attributes)),Descriptor=sd}; if(!CreateDirectoryW(path,ref attrs)) throw new Win32Exception(Marshal.GetLastWin32Error()); } finally { LocalFree(sd); }
        }
        var actual=Read(path); Access(actual); Label(actual,true,true);
    }
    public static void CreateInstallRoot(string path)
    {
        if(PreparedProgramRoot[0]=='@' || Path.GetFileName(PreparedProgramRoot)!="Program" ||
            path!=Path.GetFullPath(path) || !String.Equals(path,Path.GetDirectoryName(PreparedProgramRoot),StringComparison.OrdinalIgnoreCase))
            throw new IOException("installation_root_creation_scope_rejected");
        IntPtr sd; uint size;
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)",1,out sd,out size))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try { var attrs=new Attributes{Length=(uint)Marshal.SizeOf(typeof(Attributes)),Descriptor=sd};
            if(!CreateDirectoryW(path,ref attrs)) throw new Win32Exception(Marshal.GetLastWin32Error(),"installation_root_creation_failed"); }
        finally { LocalFree(sd); }
        Access(Read(path));
    }
    public static void RequireProtectedFile(string path)
    {
        string root=Root(RecoveryRoot);
        if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase) || !File.Exists(path)) throw new IOException("recovery_receipt_path_rejected");
        for(string part=path; part!=root; part=Path.GetDirectoryName(part)) {
            if((File.GetAttributes(part)&FileAttributes.ReparsePoint)!=0) throw new IOException("recovery_link_rejected");
            var sd=Read(part); Access(sd); Label(sd,true,false);
        }
    }
}
