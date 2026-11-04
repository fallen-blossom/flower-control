using System.Security.Principal;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

// Installation-only read-only validation. An explicit path never changes the
// running installation, user policy, Stop, work authority or recovery records.
internal static class RetainedInstallationMetadata
{
    private static readonly string[] Folders = ["permissions", "privacy", "work-authority", "audit", "execution-bindings", "recovery"];
    internal static bool KnownFile(string folder, string relative, string sid)
    {
        string[] parts=relative.Split(Path.DirectorySeparatorChar);
        if(folder=="recovery")
        {
            // Records remain opaque: unknown/Stop is never decoded as a new
            // authority. Only existing state families and data extensions fit.
            if(parts.Length<2 || !(parts[0] is "stop" or "computer-pause" or "ordinary-stop" or "program-launch" or "uac" or "qualification"
                || Regex.IsMatch(parts[0],"\\Ainstallation-[a-f0-9]{32}\\z"))) return false;
            return Path.GetExtension(relative).ToLowerInvariant() is ".json" or ".jsonl" or ".txt" or ".log" or ".bin" or ".tmp" or ".pending" or ".lock" or ".xml";
        }
        if(folder is "permissions" or "privacy")
        {
            if(parts.Length!=1) return false;
            if(Regex.IsMatch(relative,"\\A[a-f0-9]{32}\\.(tmp|recovery)\\z")) return true;
            return folder=="permissions" ? relative==sid+".json" || relative==sid+".uac.json" : relative=="sensitive-words.txt";
        }
        if(parts.Length!=2 || !Regex.IsMatch(parts[0],"\\A[a-f0-9]{64}\\z")) return false;
        string name=parts[1];
        if(Regex.IsMatch(name,"\\A\\.writing\\.[a-f0-9]{32}\\z")) return true;
        if(folder=="work-authority") return name=="writer.lock"
            || Regex.IsMatch(name,"\\A[a-f0-9]{32}\\.(?:owner\\.json|revoked|closed|index\\.json(?:\\.[a-f0-9]{32}\\.pending)?)\\z");
        if(folder=="execution-bindings") return Regex.IsMatch(name,
            "\\A[a-zA-Z0-9_-]{1,128}\\.json(?:\\.closed|\\.blocked(?:\\.head\\.[a-f0-9]{32})?)?\\z");
        return folder=="audit" && (name is "writer.lock" or "key.bin" or "checkpoint.json" or "bootstrap.json"
            || Regex.IsMatch(name,"\\A(?:checkpoint\\.[a-f0-9]{32}\\.pending|[0-9]{8}\\.jsonl(?:\\.[a-f0-9]{32}\\.pending|\\.quarantine\\.[a-f0-9]{32}(?:\\.recovery\\.json)?|\\.repair\\.[a-f0-9]{32}\\.pending)?)\\z"));
    }
    internal static object Inspect(string programRoot)
    {
        if(!Path.IsPathFullyQualified(programRoot) || programRoot!=Path.GetFullPath(programRoot)
            || Path.GetFileName(programRoot)!="Program") throw new Boundary("retained_installation_root_rejected");
        InstallationLocation.RequireProtectedPath(programRoot);
        string sid=WindowsIdentity.GetCurrent().User!.Value;
        int files=0;
        foreach(string folder in Folders)
        {
            string root=Path.Combine(programRoot,folder);
            if(!Directory.Exists(root)) continue;
            var pending=new Stack<string>();pending.Push(root);
            while(pending.Count!=0)
            {
                string current=pending.Pop();
                if(Directory.Exists(current))
                {
                    InstallationLocation.RequireProtectedPath(current);
                    UserPermissions.CheckProtection(current);
                    foreach(string child in Directory.EnumerateFileSystemEntries(current)) pending.Push(child);
                }
                else
                {
                    if(!KnownFile(folder,Path.GetRelativePath(root,current),sid)) throw new Boundary("retained_installation_unknown_metadata");
                    if(folder=="recovery" && Path.GetRelativePath(root,current).StartsWith("ordinary-stop"+Path.DirectorySeparatorChar,StringComparison.Ordinal)
                        && current.EndsWith(".bin",StringComparison.Ordinal)) OrdinaryStopJournal.ValidateRetained(current,sid);
                    else {InstallationLocation.RequireProtectedPath(current);UserPermissions.CheckProtection(current);}
                    if(folder=="audit" && Path.GetFileName(current)=="key.bin" && new FileInfo(current).Length!=32)
                        throw new Boundary("execution_audit_key_invalid");
                    ++files;
                }
            }
        }
        UserPermissions.ValidateRetainedInstallationProfile(programRoot,sid);
        return new {schema=1,valid=true,files,AuthorityGranted=false,InputDispatched=false,StateChanged=false};
    }
    internal static object SelfTest()
    {
        const string sid="S-1-5-21-1-2-3-1001";
        string owner=new('a',64),operation=new('b',32);
        (string Folder,string Relative,bool Expected)[] rows=[
            ("permissions",sid+".json",true),("permissions",sid+".uac.json",true),
            ("permissions","S-1-5-21-1-2-3-9999.json",false),("permissions","extra.dll",false),
            ("privacy","sensitive-words.txt",true),("privacy","extra.txt",false),
            ("work-authority",owner+"\\"+operation+".owner.json",true),
            ("work-authority",owner+"\\"+operation+".index.json."+operation+".pending",true),
            ("audit",owner+"\\00000001.jsonl.quarantine."+operation+".recovery.json",true),
            ("audit",owner+"\\key.bin",true),("audit",owner+"\\unknown.bin",false),
            ("execution-bindings",owner+"\\request.json.blocked.head."+operation,true),
            ("execution-bindings",owner+"\\request.exe",false),
            ("recovery","ordinary-stop\\"+sid+".1.global.bin",true),
            ("recovery","installation-"+operation+"\\resume-anchor.json",true),
            ("recovery","uac\\versions\\old\\unknown.json",true),
            ("recovery","uac\\unknown.exe",false),("recovery","unknown\\extra.json",false)];
        foreach(var row in rows) if(KnownFile(row.Folder,row.Relative,sid)!=row.Expected)
            throw new Boundary("retained_installation_contract_failed");
        return new {assertions=rows.Length,AuthorityGranted=false,InputDispatched=false,StateChanged=false};
    }
}

internal static partial class UserPermissions
{
    internal static void ValidateRetainedInstallationProfile(string programRoot,string sid)
    {
        string permissions=Path.Combine(programRoot,"permissions");
        if(Directory.Exists(permissions))
        {
            var snapshot=ReadStorage(Path.Combine(permissions,sid+".json"),sid,false);
            if(snapshot.Settings.UacPolicyError is not null) throw new Boundary("retained_installation_policy_invalid");
        }
        string words=Path.Combine(programRoot,"privacy","sensitive-words.txt");
        if(File.Exists(words)) ValidateSettingsWords(ReadSettingsWordsAt(words,false).Text);
    }
}
