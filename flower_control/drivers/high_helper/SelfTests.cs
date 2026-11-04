using System.Text;
using System.Text.Json;

namespace Flower.HighHelper;

internal static class SelfTests
{
    internal static object Run()
    {
        int assertions = 0;
        void Require(bool value) { ++assertions; if (!value) throw new Boundary("selftest_failed_" + assertions); }
        string absent = Path.Combine(Path.GetTempPath(), "flower-absent-" + Guid.NewGuid().ToString("N") + ".json");
        try { BrokerPolicy.RejectLinks(absent); Require(false); }
        catch (FileNotFoundException) { Require(true); }
        BrokerPolicy.RejectLinks(Path.GetTempPath()); Require(true);
        for (int tier = 0; tier < 3; tier++)
        {
            Require(TrayStateIcons.Select(tier, true, false) == tier + 1);
            Require(TrayStateIcons.DisplayName(TrayStateIcons.Select(tier, true, false)) == new[] { "02-normal", "03-admin-window", "04-admin-launch" }[tier]);
            Require(TrayStateIcons.Select(tier, false, false) == 5);
            Require(TrayStateIcons.Select(tier, true, true) == 5);
        }
        Require(TrayStateIcons.Select(-1, true, false) == 4);
        Require(TrayStateIcons.Select(3, true, false) == 5);
        Require(TrayStateIcons.Select(-1, true, true) == 5);
        for (int index = 0; index < 4; index++)
        {
            Require(AuthorityPresentation.ButtonTier(index) == index - 1);
            Require(AuthorityPresentation.Label(index - 1).StartsWith((index + 1).ToString("00") + " "));
        }
        Require(!AuthorityPresentation.Selectable(3));
        Require(AuthorityPresentation.Label(3).Contains("冻结"));
        Require(AuthorityPresentation.FlowerState(-1) == -1);
        Require(AuthorityPresentation.FlowerState(0) == 0 && AuthorityPresentation.FlowerState(1) == 1);
        Require(AuthorityPresentation.FlowerState(2) == 3);
        Require(AuthorityPresentation.Ink(-1) == 0xF2F2F2 && AuthorityPresentation.Ink(0) == 0xFFB778
            && AuthorityPresentation.Ink(1) == 0x5CB1FF && AuthorityPresentation.Ink(2) == 0x6B6BFF);
        Require(TrayStateIcons.Select(9, true, false) == 5);
        for (int index = 0; index < 6; index++) Require(TrayStateIcons.Load(index, 24, 24) != IntPtr.Zero);
        TrayStateIcons.Release();
        var permissionRoot = new IntPtr(101); var ownedFileDialog = new IntPtr(102); var ordinaryRoot = new IntPtr(103);
        IntPtr Owner(IntPtr value) => value == ownedFileDialog ? permissionRoot : IntPtr.Zero;
        Require(Native.ProtectedOwnerChain(permissionRoot, value => value == permissionRoot, Owner));
        Require(Native.ProtectedOwnerChain(ownedFileDialog, value => value == permissionRoot, Owner));
        Require(!Native.ProtectedOwnerChain(ordinaryRoot, value => value == permissionRoot, Owner));
        Require(!Native.ProtectedOwnerChain(IntPtr.Zero, _ => true, Owner));
        Require(!Native.ProtectedOwnerChain(ordinaryRoot, _ => false, value => value)); // A cyclic owner cannot hang input cleanup.
        Require(InputActivityLatch.OwnTag.ToUInt64() is > 0 and <= uint.MaxValue);
        var defaultSettings = new UserPermissionSettings { UserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value };
        // Semantic tiers grant execution as a whole, so the policy must still
        // refuse the effects nobody asked for and honour every blacklist.
        var semantic = UserPermissions.Effective(defaultSettings with { AuthorityTier = 2, AdminLaunchMode = "semantic" });
        void SemanticRejects(string path, string arguments = "", string? expected = null)
        {
            try { SemanticLaunchPolicy.RequireAllowed(semantic, path, arguments); Require(false); }
            catch (Boundary error) { Require(expected is null || error.Code == expected); }
        }
        SemanticLaunchPolicy.RequireAllowed(semantic, @"C:\Work\tool.exe", "");
        SemanticLaunchPolicy.RequireAllowed(semantic, @"C:\Program Files\Python\python.exe", "script.py --flag");
        SemanticRejects(@"C:\Program Files\Huorong\Sysdiag\huorong.exe", "", "program_launch_security_software_blocked");
        SemanticRejects(@"C:\Windows\System32\runas.exe", "", "program_launch_cross_user_blocked");
        SemanticRejects(@"C:\Tools\mimikatz.exe", "", "program_launch_credential_tool_blocked");
        SemanticRejects(@"C:\Windows\System32\reg.exe", "add HKLM\\SOFTWARE\\x /v EnableLUA /d 0",
            "program_launch_uac_policy_change_blocked");
        SemanticRejects("tool.exe");
        SemanticRejects(@"C:\Work\tool.exe", "a\nb");
        var denied = semantic with { DeniedAdminLaunchApplications = [new(@"C:\Work\tool.exe", "sha256", new string('a', 64), "x")] };
        try { SemanticLaunchPolicy.RequireAllowed(denied, @"C:\Work\tool.exe", ""); Require(false); }
        catch (Boundary error) { Require(error.Code == "window_disabled_by_user"); }
        try { SemanticLaunchPolicy.RequireAllowed(UserPermissions.Effective(defaultSettings with { AuthorityTier = 1 }), @"C:\Work\tool.exe", ""); Require(false); }
        catch (Boundary error) { Require(error.Code == "program_launch_disabled"); }
        var serializedSettings = JsonSerializer.Serialize(defaultSettings);
        Require((UserPermissions.PolicyMutationRights & (int)System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles) != 0);
        Require(PermissionSettingsWindow.LayoutScale(192, 3840) == 2);
        Require(PermissionSettingsWindow.LayoutScale(96, 1920) == 1);
        // Narrow work areas reflow controls instead of shrinking readable text.
        Require(PermissionSettingsWindow.LayoutScale(192, 1024) == 2);
        UserPermissions.RequireCurrentRevision("absent", "absent"); Require(true);
        UserPermissions.RequireCurrentRevision("current", "current"); Require(true);
        try { UserPermissions.RequireCurrentRevision("before-tray-revoke", "revoked"); Require(false); }
        catch (Boundary e) { Require(e.Code == "user_policy_changed_reopen_settings"); }
        foreach (var label in new[] { "S:(ML;;NW;;;HI)", "S:(ML;;NW;;;SI)",
            "S:PAI(ML;;NW;;;HI)", "S:P(ML;OICI;NW;;;HI)", "S:AI(ML;ID;NW;;;HI)" })
        { SecurityLabel.RequireHigh(label); Require(true); }
        foreach (var label in new[] { "", "S:", "S:AINO_ACCESS_CONTROL", "S:PAINO_ACCESS_CONTROL" })
        { SecurityLabel.RequireUnlabelledExecutable(label); Require(true); }
        {
            var name = "Flower.Uac.OwnDuplexTest." + Guid.NewGuid().ToString("N");
            using var server = new System.IO.Pipes.NamedPipeServerStream(name, System.IO.Pipes.PipeDirection.InOut,
                1, System.IO.Pipes.PipeTransmissionMode.Byte, System.IO.Pipes.PipeOptions.Asynchronous);
            using var client = UacSystemPipe.OpenClient(name);
            var connected = server.WaitForConnectionAsync(); client.Connect(2000); connected.GetAwaiter().GetResult();
            Require(client.IsAsync);
            var read = client.ReadAsync(new byte[1]).AsTask();
            var received = new byte[1]; var serverRead = server.ReadAsync(received).AsTask();
            var write = client.WriteAsync(new byte[] { 42 }).AsTask();
            Require(write.Wait(2000) && !read.IsCompleted);
            server.Write([17]);
            Require(read.Wait(2000) && serverRead.Wait(2000) && received[0] == 42);
        }
        var originalQueryAcl = new System.Security.AccessControl.RawSecurityDescriptor("D:(A;;GA;;;SY)(A;;GA;;;BA)").DiscretionaryAcl!;
        foreach (var queryRights in new[] { 0x1000, 8 })
        {
            var augmented = UacPeerReadAccess.QueryAcl(originalQueryAcl, "S-1-5-21-1-2-3-1001", queryRights);
            Require(originalQueryAcl.Count == 2 && augmented.Count == 3);
            for (int i = 0; i < 2; i++) Require(originalQueryAcl[i].Equals(augmented[i]));
            Require(((System.Security.AccessControl.CommonAce)augmented[2]).AccessMask == queryRights);
        }
        try { UacPeerReadAccess.QueryAcl(originalQueryAcl, "S-1-5-21-1-2-3-1001", 0x1fffff); Require(false); }
        catch (Boundary e) { Require(e.Code == "uac_peer_query_acl_rejected"); }
        foreach (var label in new[] { "S:(ML;;NW;;;HI)", "S:(ML;ID;NW;;;HI)", "S:(ML;;NW;;;ME)" })
        { try { SecurityLabel.RequireUnlabelledExecutable(label); Require(false); } catch (Boundary e) { Require(e.Code == "uac_image_label_would_demote_system"); } }
        foreach (var label in new[] { "S:", "S:(ML;;NW;;;ME)", "S:(ML;;NR;;;HI)",
            "S:PAI(ML;IO;NW;;;HI)", "S:(ML;OICIIO;NW;;;HI)",
            "S:(ML;;NW;;;HI)(ML;;NW;;;SI)" })
        { try { SecurityLabel.RequireHigh(label); Require(false); } catch (Boundary e) { Require(e.Code == "user_policy_unprotected"); } }
        try { UserPermissions.RequirePasswordFocus([new Step(new Native.Input { Type = 1 })], new([], null, true), false); Require(false); }
        catch (Boundary e) { Require(e.Code == "privacy_keyboard_focus_unverified"); }
        using (var full = JsonDocument.Parse(serializedSettings)) { UserPermissions.Validate(UserPermissions.Decode(full)); Require(true); }
        foreach (var key in new[] { "Schema", "Revision", "UserSid", "AdminWindows", "AdminScope", "UacMode", "JevEnabled",
                                   "DeniedApplications", "AllowedAdminApplications", "Masks", "SmoothPointer", "HudCompact", "HudPosition" })
        {
            var value = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(serializedSettings)!;
            value.Remove(key);
            using var missing = JsonDocument.Parse(JsonSerializer.Serialize(value));
            try { UserPermissions.Decode(missing); Require(false); }
            catch (Boundary error) { Require(error.Code == "user_policy_invalid"); }
        }
        Require(BrokerPolicy.ConnectionHostImageAllowed("Cursor.exe"));
        Require(BrokerPolicy.ConnectionHostImageAllowed("Code - Insiders.exe"));
        Require(BrokerPolicy.ConnectionHostImageAllowed("opencode.exe"));
        Require(BrokerHost.AdministrativeChannel("flower-app"));
        foreach (var channel in new string?[] { null, "", "flower-web", "flower-computer", "flower-admin", "fixture" })
            Require(!BrokerHost.AdministrativeChannel(channel));
        using (var wgcPolicy = JsonDocument.Parse("{\"WgcWorkerHashes\":{\"Flower.ComputerWgc.dll\":\"" + new string('a',64) + "\"}}"))
        {
            var decoded = Protocol.Decode<BrokerPolicy>(wgcPolicy);
            Require(decoded.WgcWorkerHashes.Count == 1);
            Require(decoded.WgcWorkerHashes["Flower.ComputerWgc.dll"] == new string('a',64));
        }
        using (var oldPolicy = JsonDocument.Parse("{}")) Require(Protocol.Decode<BrokerPolicy>(oldPolicy).WgcWorkerHashes.Count == 0);
        using (var unknownPolicy = JsonDocument.Parse("{\"WgcWorkerHash\":{}}"))
        {
            try { Protocol.Decode<BrokerPolicy>(unknownPolicy); Require(false); }
            catch (JsonException) { Require(true); }
        }
        foreach (var image in new[] { "node.exe", "python.exe", "pwsh.exe", "powershell.exe", "cmd.exe", "unknown.exe" })
            Require(!BrokerPolicy.ConnectionHostImageAllowed(image));
        long waitElapsed = 1999;
        int waitChecks = 0, waitSleeps = 0;
        foreach (long crossed in new long[] { 2001, 2002 })
        {
            waitElapsed = 1999; waitChecks = 0; waitSleeps = 0;
            ComputerPlans.WaitForOffset(2000, () => waitElapsed,
                () => { ++waitChecks; waitElapsed = crossed; },
                delay => { ++waitSleeps; Require(delay > 0 && delay <= 20); waitElapsed += delay; });
            Require(waitChecks == 1 && waitSleeps == 0);
        }
        waitElapsed = 0; waitChecks = 0; waitSleeps = 0;
        ComputerPlans.WaitForOffset(45, () => waitElapsed, () => ++waitChecks,
            delay => { ++waitSleeps; Require(delay > 0 && delay <= 20); waitElapsed += delay; });
        Require(waitElapsed == 45 && waitChecks == 3 && waitSleeps == 3);
        waitElapsed = 0; waitSleeps = 0;
        try {
            ComputerPlans.WaitForOffset(2000, () => waitElapsed,
                () => throw new Boundary("input_stopped"), delay => ++waitSleeps);
            Require(false);
        } catch (Boundary error) { Require(error.Code == "input_stopped" && waitSleeps == 0); }
        waitElapsed = 2000; waitChecks = 0;
        ComputerPlans.WaitForOffset(2000, () => waitElapsed, () => ++waitChecks, delay => ++waitSleeps);
        Require(waitChecks == 0 && waitSleeps == 0);
        waitElapsed = 1999; waitChecks = 0;
        ComputerPlans.WaitForOffset(2000, () => waitElapsed,
            () => { ++waitChecks; waitElapsed = 2000; }, delay => ++waitSleeps);
        Require(waitChecks == 1 && waitSleeps == 0);
        Require(!Executor.InitialGeometryRequired(new Operation("computer_input_plan", RestoreMinimized: true), true));
        Require(Executor.InitialGeometryRequired(new Operation("computer_input_plan", RestoreMinimized: true), false));
        Require(Executor.InitialGeometryRequired(new Operation("computer_input_plan"), true));
        Require(!Executor.InitialGeometryRequired(new Operation("activate", RestoreMinimized: true), true));
        var down = new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse { Flags = 2 } } };
        var up = new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse { Flags = 4 } } };
        Step[] pair = [new Step(down, "mouse:left", true, up), new Step(up, "mouse:left")];
        var calls = new List<Native.Input[]>();
        var partial = new InputLedger(inputs => { calls.Add(inputs); return 1; });
        var result = new Receipt();
        try { partial.Send(pair, result); Require(false); } catch (Boundary error) { Require(error.Code == "input_partial"); }
        Require(partial.State == "release_pending");
        partial.Release(result);
        Require(partial.State == "released" && result.SentEvents == 1 && result.ReleaseEvents == 1);
        Require(calls.Count == 2 && calls[1].Length == 1 && calls[1][0].Data.Mouse.Flags == 4);

        int count = 0;
        var failedRelease = new InputLedger(inputs => ++count == 1 ? 1U : 0U);
        result = new Receipt();
        try { failedRelease.Send(pair, result); } catch (Boundary) { }
        try { failedRelease.Release(result); Require(false); } catch (Boundary error) { Require(error.Code == "release_partial"); }
        Require(failedRelease.State == "release_pending");

        var unknown = new InputLedger(inputs => throw new IOException());
        try { unknown.Send(pair, new Receipt()); } catch (IOException) { }
        Require(unknown.State == "unknown");
        unknown.Release(new Receipt());
        Require(unknown.State == "unknown");

        var balanced = new InputLedger(inputs => (uint)inputs.Length);
        result = new Receipt(); balanced.Send(pair, result); balanced.Release(result);
        Require(balanced.State == "released" && result.SentEvents == 2 && result.ReleaseEvents == 0);
        var dispatchOrder = new List<string>(); long lastReceiver = 10;
        var guardedSegment = new InputLedger(inputs => { dispatchOrder.Add("send"); return (uint)inputs.Length; });
        guardedSegment.PrivacyCheck = _ => { dispatchOrder.Add("privacy"); lastReceiver = 20; };
        result = new Receipt();
        var actualReceiver = ComputerPlans.DispatchSegment(pair, guardedSegment, result, () => {
            dispatchOrder.Add("final"); return lastReceiver;
        });
        Require(actualReceiver == 20 && dispatchOrder.SequenceEqual(new[] { "privacy", "final", "send" }));
        Require(result.BusinessEvents == 2 && guardedSegment.State == "released");
        using (var isolatedStop = new SharedWriteGate("segment_" + Guid.NewGuid().ToString("N")))
        {
            int finalChecks = 0, sendsAfterStop = 0;
            var stoppedDuringPrivacy = new InputLedger(inputs => { sendsAfterStop++; return (uint)inputs.Length; }, isolatedStop);
            stoppedDuringPrivacy.PrivacyCheck = _ => isolatedStop.Stop();
            result = new Receipt();
            try { ComputerPlans.DispatchSegment(pair, stoppedDuringPrivacy, result, () => { finalChecks++; return 10; }); Require(false); }
            catch (Boundary error) { Require(error.Code == "global_write_stopped"); }
            Require(finalChecks == 0 && sendsAfterStop == 0 && result.RequestedEvents == 0 && stoppedDuringPrivacy.State == "released");
        }
        foreach (var failure in new[] { "input_stopped", "target_identity_changed", "geometry_changed", "input_context_changed" })
        {
            bool becameInvalid = false; int physicalSends = 0;
            var guardedFailure = new InputLedger(inputs => { physicalSends++; return (uint)inputs.Length; });
            guardedFailure.PrivacyCheck = _ => becameInvalid = true;
            result = new Receipt();
            try {
                ComputerPlans.DispatchSegment(pair, guardedFailure, result, () => {
                    if (becameInvalid) throw new Boundary(failure); return 10;
                });
                Require(false);
            }
            catch (Boundary error) { Require(error.Code == failure); }
            Require(physicalSends == 0 && !result.BusinessAttempted && result.RequestedEvents == 0 && guardedFailure.State == "released");
        }
        Require(System.Runtime.InteropServices.Marshal.SizeOf<Native.Input>() == (IntPtr.Size == 8 ? 40 : 28));
        Require(ResourceLocks.Name("desktop-foreground-input-v1") == "Local\\FlowerControl.Resource.v1.b6918b905f1abda1b0a99f406ff6e6ecbe11115e12b0330c5d0e5bf4bb9fe65c");

        using (var bytes = new MemoryStream(Encoding.UTF8.GetBytes("{\"Phase\":\"go\",\"Phase\":\"stop\"}\n")))
        {
            try { Protocol.Read(bytes, 100); Require(false); } catch (Boundary error) { Require(error.Code == "schema_rejected"); }
        }
        using (var bytes = new MemoryStream(Encoding.UTF8.GetBytes(new string('a', Protocol.Limit))))
        {
            try { Protocol.Read(bytes, 100); Require(false); } catch (Boundary error) { Require(error.Code == "message_too_large"); }
        }
        using (var bytes = new MemoryStream(Encoding.UTF8.GetBytes("{\"Phase\":\"stop\",\"LedgerIdentity\":\"old\"}\n{\"Phase\":\"go\",\"LedgerIdentity\":\"new\"}\n")))
        {
            using var first = Protocol.Read(bytes, 100);
            using var second = Protocol.Read(bytes, 100);
            Require(first is not null && Protocol.Signal(first, "stop", "old") && !Protocol.Signal(first, "stop", "new"));
            Require(second is not null && Protocol.Signal(second, "go", "new"));
        }
        var state = new BrokerState();
        var negotiating = new BrokerState();
        var pendingInput = new BrokerRequest();
        negotiating.Requests["pending"] = pendingInput;
        var negotiationRevision = negotiating.Revision;
        Require(HostWindow.EndSessionMessage(negotiating, 0x11, false) == new IntPtr(1));
        Require(!negotiating.Shutdown.IsCancellationRequested && !pendingInput.Stop.IsCancellationRequested);
        Require(HostWindow.EndSessionMessage(negotiating, 0x16, false) == IntPtr.Zero);
        Require(!negotiating.Shutdown.IsCancellationRequested && !negotiating.IsPaused && negotiating.Revision == negotiationRevision);
        negotiating.Check(negotiationRevision);
        Require(HostWindow.EndSessionMessage(negotiating, 0x16, true) == IntPtr.Zero);
        Require(negotiating.Shutdown.IsCancellationRequested && pendingInput.Stop.IsCancellationRequested);
        Require(HostWindow.EndSessionMessage(new BrokerState(), 0x113, false) is null);
        var observed = state.Revision;
        var firstRequest = new BrokerRequest(); var secondRequest = new BrokerRequest();
        state.Requests["one"] = firstRequest; state.Requests["two"] = secondRequest;
        firstRequest.Cancel("client_disconnected");
        Require(firstRequest.Stop.IsCancellationRequested && !secondRequest.Stop.IsCancellationRequested && !state.Shutdown.IsCancellationRequested);
        state.Pause(true);
        Require(secondRequest.Stop.IsCancellationRequested && state.Revision > observed);
        state.Pause(false);
        try { state.Check(observed); Require(false); } catch (Boundary error) { Require(error.Code == "fresh_broker_observation_required"); }
        state.Check(state.Revision);
        Require(firstRequest.Stop.IsCancellationRequested && secondRequest.Stop.IsCancellationRequested);
        observed = state.Revision; state.Desktop(false, "desktop_locked"); state.Desktop(true);
        Require(state.Revision > observed);
        state.Fault(); state.Pause(false);
        try { state.Check(state.Revision); Require(false); } catch (Boundary error) { Require(error.Code == "broker_release_fault"); }

        var planObject = new { kind = "computer_input_plan", schema_version = 1, command = "key",
            binding = new { task_id = "fixture", action_id = "fixture:computer:action", observation_id = "observation",
                generation = new string('g', 260), sequence_step = (int?)null }, desktop = (object?)null,
            plans = new[] { new { duration_ms = 0, segments = new[] { new { offset_ms = 0,
                events = new[] { new { kind = "virtual_key", code = 65, down = true }, new { kind = "virtual_key", code = 65, down = false } } } } } } };
        var planElement = JsonSerializer.SerializeToElement(planObject);
        var parsed = ComputerPlans.Parse(planElement);
        Require(parsed.Binding.Generation?.Length == 260 && parsed.Plans[0].Segments[0].Steps.Length == 2);
        Require(!parsed.SuppressPointerApproach);
        foreach (bool suppress in new[] { false, true })
        {
            var desktopPlan = JsonSerializer.SerializeToNode(planObject)!.AsObject();
            desktopPlan["suppress_pointer_approach"] = suppress;
            Require(ComputerPlans.Parse(JsonSerializer.SerializeToElement(desktopPlan)).SuppressPointerApproach == suppress);
        }
        foreach (var invalid in new object?[] { 1, "true", null })
        {
            var malformedFlag = JsonSerializer.SerializeToNode(planObject)!.AsObject();
            malformedFlag["suppress_pointer_approach"] = JsonSerializer.SerializeToNode(invalid);
            try { ComputerPlans.Parse(JsonSerializer.SerializeToElement(malformedFlag)); Require(false); }
            catch (Boundary error) { Require(error.Code == "input_plan_rejected"); }
        }
        for (int index = 0; index < 8; index++)
        {
            var sequencePlan = JsonSerializer.SerializeToElement(new { planObject.kind, planObject.schema_version,
                planObject.command, binding = new { planObject.binding.task_id, planObject.binding.action_id,
                    planObject.binding.observation_id, planObject.binding.generation, sequence_step = index },
                planObject.desktop, planObject.plans });
            Require(ComputerPlans.Parse(sequencePlan).Binding.SequenceStep == index);
        }
        foreach (int index in new[] { -1, 8 })
        {
            var invalidSequence = JsonSerializer.SerializeToElement(new { planObject.kind, planObject.schema_version,
                planObject.command, binding = new { planObject.binding.task_id, planObject.binding.action_id,
                    planObject.binding.observation_id, planObject.binding.generation, sequence_step = index },
                planObject.desktop, planObject.plans });
            try { ComputerPlans.Parse(invalidSequence); Require(false); }
            catch (Boundary error) { Require(error.Code == "input_plan_rejected"); }
        }
        object Segment(int offset, params object[] events) => new { offset_ms = offset, events };
        ComputerPlan EventPlan(string command, int duration, params object[] segments) => ComputerPlans.Parse(JsonSerializer.SerializeToElement(new {
            kind = "computer_input_plan", schema_version = 1, command, planObject.binding,
            desktop = new { left = 0, top = 0, width = 1920, height = 1080 },
            plans = new[] { new { duration_ms = duration, segments } } }));
        object[] ChordEvents(int count)
        {
            var keys = new[] { 17, 16, 18, 91, 65, 66 }.Take(count).ToArray();
            return keys.Select(code => (object)new { kind = "virtual_key", code, down = true })
                .Concat(keys.Reverse().Select(code => (object)new { kind = "virtual_key", code, down = false })).ToArray();
        }
        Require(EventPlan("key", 0, Segment(0, ChordEvents(5))).Plans[0].Segments[0].Steps.Length == 10);
        try { EventPlan("key", 0, Segment(0, ChordEvents(6))); Require(false); }
        catch (Boundary error) { Require(error.Code == "input_plan_rejected"); }
        try { EventPlan("key", 0, Segment(0, ChordEvents(5)[..^1])); Require(false); }
        catch (Boundary error) { Require(error.Code == "input_plan_unbalanced"); }
        var mouseDown = new { kind = "mouse_button", button = "left", down = true };
        var mouseUp = new { kind = "mouse_button", button = "left", down = false };
        var absolute = new { kind = "mouse_absolute", nx = 32767, ny = 32767 };
        var relative = new { kind = "mouse_relative", dx = 1, dy = 0 };
        object[] DragSegments(int count) => Enumerable.Range(0, count).Select(index =>
            index == 0 ? Segment(0, absolute, mouseDown) : index == count - 1
                ? Segment(index, absolute, mouseUp) : Segment(index, absolute)).ToArray();
        var longDrag = EventPlan("drag", 63, DragSegments(64));
        Require(longDrag.Plans[0].Segments.Length == 64);
        Require(longDrag.Plans[0].Segments.Sum(segment => segment.Steps.Length) == 66);
        var fullBatch = ComputerPlans.Parse(JsonSerializer.SerializeToElement(new {
            kind = "computer_input_plan", schema_version = 1, command = "batch", planObject.binding,
            desktop = new { left = 0, top = 0, width = 1920, height = 1080 },
            plans = Enumerable.Range(0, 100).Select(_ => new { duration_ms = 30, segments = DragSegments(31) }).ToArray()
        }));
        Require(fullBatch.Plans.Sum(batch => batch.Segments.Length) == 3100);
        Require(fullBatch.Plans.Sum(batch => batch.DurationMs) == 3000);
        try { EventPlan("drag", 64, DragSegments(65)); Require(false); }
        catch (Boundary error) { Require(error.Code == "input_plan_rejected"); }

        var keyDown = new { kind = "virtual_key", code = 17, down = true };
        var keyUp = new { kind = "virtual_key", code = 17, down = false };
        foreach (int duration in new[] { 2001, 2500, 3000 })
            Require(EventPlan("key", duration, Segment(0, keyDown), Segment(duration, keyUp)).Plans[0].DurationMs == duration);
        try { EventPlan("key", 3001, Segment(0, keyDown), Segment(3001, keyUp)); Require(false); }
        catch (Boundary error) { Require(error.Code == "input_plan_rejected"); }
        object HoldBatch(int duration) => new { duration_ms = duration,
            segments = new[] { Segment(0, keyDown), Segment(duration, keyUp) } };
        foreach (int second in new[] { 1500, 1501 })
        {
            var holdBatch = JsonSerializer.SerializeToElement(new { kind = "computer_input_plan", schema_version = 1,
                command = "batch", planObject.binding, desktop = (object?)null,
                plans = new[] { HoldBatch(1500), HoldBatch(second) } });
            if (second == 1500) Require(ComputerPlans.Parse(holdBatch).Plans.Sum(p => p.DurationMs) == 3000);
            else
            { try { ComputerPlans.Parse(holdBatch); Require(false); } catch (Boundary error) { Require(error.Code == "input_plan_rejected"); } }
        }
        foreach (var mousePlan in new[] {
            EventPlan("click", 0, Segment(0, absolute, mouseDown, mouseUp)),
            EventPlan("double_click", 0, Segment(0, absolute, mouseDown, mouseUp, mouseDown, mouseUp)),
            EventPlan("scroll", 0, Segment(0, absolute, new { kind = "mouse_wheel", axis = "vertical", delta = 120 })),
            EventPlan("drag", 10, Segment(0, absolute, mouseDown), Segment(10, relative, mouseUp)),
            EventPlan("move_relative", 0, Segment(0, relative)),
            EventPlan("mouse_hold", 10, Segment(0, absolute, mouseDown), Segment(10, mouseUp)) })
            Require(!ComputerPlans.HasKeyboardEvents(mousePlan));
        Require(ComputerPlans.HasKeyboardEvents(parsed));
        Require(ComputerPlans.HasKeyboardEvents(EventPlan("text", 0, Segment(0,
            new { kind = "unicode_key", unit = 97, down = true }, new { kind = "unicode_key", unit = 97, down = false }))));
        Require(ComputerPlans.HasKeyboardEvents(EventPlan("key_mouse", 10,
            Segment(0, keyDown, mouseDown, relative), Segment(10, mouseUp, keyUp))));
        Require(!ComputerPlans.HasKeyboardEvents(EventPlan("key_mouse", 10,
            Segment(0, mouseDown, relative), Segment(10, mouseUp))));
        Require(ComputerPlans.HasKeyboardEvents(EventPlan("drag", 10,
            Segment(0, mouseDown), Segment(5, keyDown, relative), Segment(10, keyUp, mouseUp))));
        Require(ComputerPlans.HasKeyboardEvents(EventPlan("click", 0, Segment(0, keyDown, keyUp))));
        var keyboardContext = new InputContext(10, 20, "inactive");
        Require(InputContext.MergeComposition("unknown", true) == "active");
        Require(InputContext.MergeComposition("inactive", true) == "active");
        Require(InputContext.MergeComposition("unknown", false) == "inactive");
        Require(InputContext.MergeComposition("unknown", null) == "unknown");
        Require(InputContext.MergeComposition("active", false) == "active");
        var activeIme = keyboardContext with { Composition = "active" };
        int escapes = 0, reads = 0;
        var prepared = InputContext.PrepareCore(() => ++reads < 3 ? activeIme : keyboardContext,
            () => { }, () => ++escapes, _ => { });
        Require(prepared == keyboardContext && escapes == 1 && reads == 3);
        reads = escapes = 0;
        prepared = InputContext.PrepareCore(() => ++reads == 1 ? activeIme : keyboardContext,
            () => { }, () => ++escapes, _ => { });
        Require(prepared == keyboardContext && escapes == 0);
        foreach (var changed in new[] { activeIme with { Focus = 30 }, activeIme with { Layout = 40 }, activeIme with { Composition = "unknown" } })
        {
            reads = escapes = 0;
            try { InputContext.PrepareCore(() => ++reads == 1 ? activeIme : changed, () => { }, () => ++escapes, _ => { }); Require(false); }
            catch (Boundary error) { Require(error.Code == "input_context_changed" && escapes == 0); }
        }
        try { InputContext.PrepareCore(() => activeIme, () => throw new Boundary("broker_paused"), () => ++escapes, _ => { }); Require(false); }
        catch (Boundary error) { Require(error.Code == "broker_paused" && escapes == 0); }
        var mouseContext = new InputContextGuard(keyboardContext, false);
        var changedMouseContext = new InputContext(30, 40, "active");
        mouseContext.Recheck(changedMouseContext, 120);
        Require(mouseContext.Baseline == changedMouseContext);
        mouseContext.Recheck(new(null, null, "unknown"), 140);
        Require(mouseContext.Baseline == new InputContext(null, null, "unknown"));
        int contextReads = 0;
        mouseContext.RecheckCurrent(() => { ++contextReads; throw new Exception("unused_mouse_ime_read"); }, 160);
        Require(contextReads == 0);
        var keyboardRead = new InputContextGuard(keyboardContext, true);
        keyboardRead.RecheckCurrent(() => { ++contextReads; return keyboardContext; }, 160);
        Require(contextReads == 1);
        try { keyboardRead.RecheckCurrent(() => keyboardContext with { Composition = "active" }, 170); Require(false); }
        catch (Boundary error) { Require(error.Code == "input_context_changed"); }
        void ContextRejected(InputContextGuard guard, InputContext current, long now)
        { try { guard.Recheck(current, now); Require(false); } catch (Boundary error) { Require(error.Code == "input_context_changed"); } }
        ContextRejected(new(keyboardContext, true), keyboardContext with { Focus = 30 }, 20);
        var ownClick = new InputContextGuard(keyboardContext, true);
        ownClick.MouseDispatched(30, 10);
        ownClick.Recheck(keyboardContext, 40); // Focus can arrive asynchronously while the hold is supervised.
        ownClick.Recheck(keyboardContext with { Focus = 30 }, 120);
        Require(ownClick.Baseline == keyboardContext with { Focus = 30 });
        ContextRejected(ownClick, keyboardContext with { Focus = 10 }, 130); // The permission was consumed.
        InputContextGuard PendingClick()
        { var guard = new InputContextGuard(keyboardContext, true); guard.MouseDispatched(30, 10); return guard; }
        ContextRejected(PendingClick(), keyboardContext with { Focus = 31 }, 20);
        ContextRejected(PendingClick(), keyboardContext with { Focus = 30 }, 161);
        ContextRejected(PendingClick(), keyboardContext with { Focus = 30, Layout = 21 }, 20);
        ContextRejected(PendingClick(), keyboardContext with { Focus = 30, Composition = "active" }, 20);
        ContextRejected(PendingClick(), keyboardContext with { Focus = null }, 20);
        var unknownReceiver = PendingClick(); unknownReceiver.MouseDispatched(null, 15);
        ContextRejected(unknownReceiver, keyboardContext with { Focus = 30 }, 20);
        var unknownContext = new InputContextGuard(new(10, null, "unknown"), true);
        unknownContext.MouseDispatched(30, 10); unknownContext.Recheck(new(30, 20, "inactive"), 20);
        Require(unknownContext.Baseline == new InputContext(30, null, "unknown"));
        long settleTime = 10; int settleChecks = 0;
        var asyncClick = PendingClick();
        asyncClick.SettlePending(() => keyboardContext with { Focus = settleTime < 40 ? 10 : 30 }, () => settleTime,
            () => ++settleChecks, delay => settleTime += delay);
        Require(settleTime == 40 && settleChecks == 4 && asyncClick.Baseline.Focus == 30);
        asyncClick.Recheck(keyboardContext with { Focus = 30 }, 571); // Own metadata work does not expire a consumed transition.
        ContextRejected(asyncClick, keyboardContext with { Focus = 31 }, 572);
        var settledTraversal = new InputContextGuard(keyboardContext, true); settledTraversal.TraversalDispatched(10); settleTime = 10;
        try { settledTraversal.SettlePending(() => keyboardContext, () => settleTime, () => { }, delay => settleTime += delay); Require(false); }
        catch (Boundary error) { Require(error.Code == "input_focus_transition_unconfirmed"); }
        Require(settleTime == 160 && settledTraversal.Baseline == keyboardContext);
        ContextRejected(settledTraversal, keyboardContext with { Focus = 30 }, 161); // Never accept a change during a later scan.
        foreach (var textValue in new[] { "a\tb", "a\nb", "a\r\nb", "a\rb" })
        {
            var navigationText = ComputerPlans.TextBatches(textValue);
            Require(navigationText.Length == 3 && navigationText[1].Segments[0].Steps.Length == 2);
            Require(navigationText[1].Segments[0].Steps[0].Token == (textValue.Contains('\t') ? "vk:9" : "vk:13"));
        }
        Require(ComputerPlans.TextBatches(new string('\t', 8192)).Length == 8192);
        var initialPoint = new Native.Point { X = 9, Y = 8 };
        Require(InputContext.FocusPoint(pair, null, initialPoint) is { X: 9, Y: 8 });
        var mouseAbsoluteStep = new Step(new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse { Dx = 65535, Dy = 0, Flags = 0xc001 } } });
        var mouseRelativeStep = new Step(new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse { Dx = 1, Dy = 0, Flags = 1 } } });
        var desktop = new DesktopShape(-100, -50, 1000, 500);
        Require(InputContext.FocusPoint([mouseAbsoluteStep, pair[0]], desktop, initialPoint) is { X: 899, Y: -50 });
        Require(InputContext.FocusPoint([mouseRelativeStep, pair[0]], desktop, initialPoint) is null);
        Require(InputContext.FocusPoint([pair[0], mouseRelativeStep], desktop, initialPoint) is { X: 9, Y: 8 });
        Require(InputContext.FocusPoint([mouseRelativeStep, mouseAbsoluteStep, pair[0]], desktop, initialPoint) is { X: 899, Y: -50 });
        Require(InputContext.FocusPoint([pair[0], mouseRelativeStep, pair[0]], desktop, initialPoint) is null);
        Require(InputContext.FocusPoint([mouseAbsoluteStep, pair[1]], desktop, initialPoint) is null);
        Require(InputContext.MouseDown(pair[0]) && !InputContext.MouseDown(pair[1]) && !InputContext.MouseDown(parsed.Plans[0].Segments[0].Steps[0]));
        using (var malformed = JsonDocument.Parse(planElement.GetRawText().Replace("\"down\":false", "\"down\":true")))
        { try { ComputerPlans.Parse(malformed.RootElement); Require(false); } catch (Boundary error) { Require(error.Code == "input_plan_unbalanced"); } }
        using (var malformed = JsonDocument.Parse(planElement.GetRawText().Replace("\"code\":65", "\"code\":true")))
        { try { ComputerPlans.Parse(malformed.RootElement); Require(false); } catch (Boundary error) { Require(error.Code == "input_plan_rejected"); } }
        int prefixCalls = 0;
        var prefixUnknown = new InputLedger(inputs => ++prefixCalls == 2 ? throw new IOException() : (uint)inputs.Length);
        result = new Receipt(); prefixUnknown.Send([pair[0]], result);
        try { prefixUnknown.Send([pair[1]], result); Require(false); } catch (IOException) { Require(!prefixUnknown.CountKnown); }
        prefixUnknown.Release(result);
        Require(prefixUnknown.State == "unknown" && result.BusinessEvents == 1 && result.ReleaseEvents == 1);
        var prepareOnly = new InputLedger(inputs => (uint)inputs.Length);
        result = new Receipt(); prepareOnly.Send(pair, result, activation: true); prepareOnly.Send(pair, result, preparation: true);
        Require(!result.BusinessAttempted && result.BusinessEvents == 0 && result.ActivationEvents == 2 && result.ImeEvents == 2);
        var owner = new Peer(10, 20, 1, "fixture", new string('a', 64), 8192);
        result = new Receipt { LedgerIdentity = new string('b', 64), TaskId = "task", ConnectionId = new string('c', 32),
            InputRelease = "released", MutexReleased = true };
        state.Completed(owner, result);
        var released = JsonSerializer.SerializeToElement(state.RequestStatus(owner, "task", new string('c', 32), new string('b', 64)));
        Require(released.GetProperty("State").GetString() == "finished" && released.GetProperty("MutexReleased").GetBoolean());
        var unrelated = JsonSerializer.SerializeToElement(state.RequestStatus(owner with { Created = 21 }, "task", new string('c', 32), new string('b', 64)));
        Require(unrelated.GetProperty("State").GetString() == "unknown" && !unrelated.GetProperty("MutexReleased").GetBoolean());
        var source = owner with { Pid = 99, Created = 100 };
        var helper = owner with { Pid = 55, Created = 133000000000000001 };
        var recoveryLedger = new string('d', 64);
        var recoveryReceipt = new Receipt { LedgerIdentity = recoveryLedger, TaskId = "task", ConnectionId = new string('c', 32),
            InputRelease = "released", MutexReleased = true, NativeCountKnown = true };
        state.Completed(owner, recoveryReceipt, source, helper, "task:action");
        for (int i = 0; i < 257; ++i)
            state.Completed(owner, new Receipt { LedgerIdentity = i.ToString("x64"), TaskId = "task", ConnectionId = new string('c', 32),
                InputRelease = "released", MutexReleased = true }, source, helper, "task:other");
        var recovered = JsonSerializer.SerializeToElement(state.RecoverRelease(source, "task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger));
        Require(recovered.GetProperty("State").GetString() == "finished" && recovered.GetProperty("NativeCountKnown").GetBoolean());
        var newCodex = JsonSerializer.SerializeToElement(state.RecoverRelease(source with { Pid = 100, Created = 101 }, "task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger));
        Require(newCodex.GetProperty("State").GetString() == "finished");
        foreach (var wrongSource in new[] { source with { User = "other-user" }, source with { Session = 2 } })
        {
            var wrong = JsonSerializer.SerializeToElement(state.RecoverRelease(wrongSource, "task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger));
            Require(wrong.GetProperty("State").GetString() == "unknown");
        }
        var wrongTask = JsonSerializer.SerializeToElement(state.RecoverRelease(source, "other-task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger));
        Require(wrongTask.GetProperty("State").GetString() == "unknown");
        var journalRoot = Path.Combine(Path.GetTempPath(), "flower-broker-journal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(journalRoot);
        var journal = Path.Combine(journalRoot, "pending.json");
        var durable = new BrokerState(journal);
        durable.Completed(owner, recoveryReceipt, source, helper, "task:action");
        var reopened = new BrokerState(journal);
        var persisted = JsonSerializer.SerializeToElement(reopened.RecoverRelease(source, "task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger));
        Require(persisted.GetProperty("State").GetString() == "finished" && persisted.GetProperty("InputRelease").GetString() == "released");
        reopened.AcknowledgeRecovery(source, "task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger);
        var acknowledged = JsonSerializer.SerializeToElement(new BrokerState(journal).RecoverRelease(source, "task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger));
        Require(acknowledged.GetProperty("State").GetString() == "unknown");
        var readArguments = new { target = new { pid = 10, hwnd = 30L, process_start_filetime = 20L, root_runtime_id = Array.Empty<int>() },
            limits = new { max_nodes = 16, max_depth = 2 }, privacy = "structure_only", privacy_scope = "" };
        var readPlan = JsonSerializer.SerializeToElement(new { schema_version = 1, command = "observe", arguments = readArguments,
            binding = new { task_id = "task", action_id = "task:app:read", observation_id = "observation", generation = "geometry", sequence_step = (int?)null } });
        var readOperation = new Operation("app_request", Plan: readPlan);
        var readTarget = new Target(30, 10, 20, 1, new string('a', 64), 8192, 1, [0, 0, 100, 100]);
        var readPrepare = new Prepare("prepare", owner, readTarget, readOperation, ["physical-window-v1:10:20:30"], 3000, "task", new string('c', 32), 1);
        Protocol.Validate(readPrepare, true);
        Require(!Protocol.NeedsForeground(readOperation) && !Protocol.UsesPhysicalInput(readOperation));
        var backgroundPlan = JsonSerializer.SerializeToElement(new { schema_version = 1, command = "set_value",
            arguments = new { target = readArguments.target, reference = new { }, observation = new { },
                privacy = "structure_only", privacy_scope = "", value = "test", execution_mode = "must_background" },
            binding = new { task_id = "task", action_id = "task:app:background", observation_id = "observation", generation = "generation", sequence_step = (int?)null } });
        var backgroundOperation = new Operation("app_request", Plan: backgroundPlan);
        Protocol.Validate(readPrepare with { Operation = backgroundOperation }, true);
        Require(!Protocol.NeedsForeground(backgroundOperation) && !Protocol.ReadOnly(backgroundOperation));
        Require(Protocol.NeedsForeground(backgroundOperation with { Activate = true }));
        var initial = JsonSerializer.SerializeToElement(new { schema_version = 1, command = "observe", arguments = readArguments,
            binding = new { task_id = "task", action_id = "initial", observation_id = (string?)null, generation = (string?)null, sequence_step = (int?)null } });
        Require(AppExecutor.Parse(initial, readTarget).Binding.ObservationId is null);
        var noObservedWrite = JsonSerializer.SerializeToElement(new { schema_version = 1, command = "invoke",
            arguments = new { target = readArguments.target, reference = new { }, observation = new { }, privacy = "structure_only", privacy_scope = "" },
            binding = new { task_id = "task", action_id = "write", observation_id = (string?)null, generation = (string?)null, sequence_step = (int?)null } });
        try { AppExecutor.Parse(noObservedWrite, readTarget); Require(false); }
        catch (Boundary error) { Require(error.Code == "app_binding_rejected"); }
        Protocol.Validate(readPrepare with { Operation = new Operation("bind") }, true);
        Require(!Protocol.NeedsForeground(new Operation("bind")));
        try { Protocol.Validate(readPrepare with { Operation = new Operation("activate") }, true); Require(false); }
        catch (Boundary error) { Require(error.Code == "resources_rejected"); }
        int adds = 0, modifies = 0, removes = 0;
        bool shell = false;
        var tray = new TrayRegistration(() => { ++adds; return shell; }, () => { ++modifies; return shell; }, () => ++removes);
        tray.Tick(0, "running");
        Require(!tray.Registered && adds == 1);
        tray.Tick(999, "running");
        Require(!tray.Registered && adds == 1);
        shell = true; tray.Tick(1000, "running");
        Require(tray.Registered && adds == 2);
        shell = false; tray.Tick(2000, "running");
        Require(!tray.Registered && modifies == 1);
        shell = true; tray.ExplorerRestarted(2001); tray.Tick(2001, "running");
        Require(tray.Registered && adds == 4);
        tray.Close(); Require(!tray.Registered && removes == 1);
        using var emptyAck = JsonDocument.Parse("{\"Phase\":\"ack\",\"LedgerIdentity\":\"ledger\",\"TaskId\":\"task\",\"ConnectionId\":\"connection\",\"DesktopRevision\":1,\"ActionId\":\"\"}");
        var unclaimed = readPrepare with { Operation = new Operation("bind"), ConnectionId = "connection" };
        Require(Protocol.Signal(emptyAck, "ack", "ledger", unclaimed, ""));
        Require(!Protocol.Signal(emptyAck, "go", "ledger", unclaimed));
        JsonDocument Signal(string phase, string action, string ledger, Prepare prepare) => JsonDocument.Parse(JsonSerializer.Serialize(new {
            Phase = phase, ActionId = action, LedgerIdentity = ledger, prepare.TaskId, prepare.ConnectionId, prepare.DesktopRevision }));
        var stopJournal = Path.Combine(journalRoot, "pre-go-stop-pending.json");
        var stopState = new BrokerState(stopJournal);
        int stopCase = 100;
        foreach (var kind in new[] { "bind", "activate", "click", "text" })
        {
            var raw = unclaimed with { Operation = new Operation(kind) };
            var stoppedRequest = new BrokerRequest();
            var stopLedger = (++stopCase).ToString("x64");
            var action = "task:" + kind + ":stopped";
            using var stop = Signal("stop", action, stopLedger, raw);
            Require(Program.AcceptPreGoStop(stop, stopLedger, raw, stoppedRequest));
            Require(stoppedRequest.ActionId == action && stoppedRequest.Stop.IsCancellationRequested && stoppedRequest.Reason == "input_stopped");
            stopState.Completed(owner, new Receipt { LedgerIdentity = stopLedger, TaskId = raw.TaskId, ConnectionId = raw.ConnectionId,
                InputRelease = "released", MutexReleased = true, NativeCountKnown = true }, source, helper, stoppedRequest.ActionId);
            var boundStop = JsonSerializer.SerializeToElement(new BrokerState(stopJournal).RecoverRelease(source, raw.TaskId, action, BrokerState.ExecutorIdentity(helper), stopLedger));
            Require(boundStop.GetProperty("State").GetString() == "finished");
            using var ack = Signal("ack", action, stopLedger, raw);
            Require(Protocol.Signal(ack, "ack", stopLedger, raw, stoppedRequest.ActionId));
            using var wrongAck = Signal("ack", action + ":wrong", stopLedger, raw);
            Require(!Protocol.Signal(wrongAck, "ack", stopLedger, raw, stoppedRequest.ActionId));
            stopState.Acknowledge(owner, stopLedger);
            using var pending = JsonDocument.Parse(File.ReadAllText(stopJournal));
            Require(pending.RootElement.GetProperty("Pending").GetArrayLength() == 0);
        }
        foreach (var phase in new[] { "go", "stop" })
        {
            using var empty = Signal(phase, "", "ledger", unclaimed);
            Require(!Protocol.Signal(empty, phase, "ledger", unclaimed));
            var rejectedRequest = new BrokerRequest();
            Require(!Program.AcceptPreGoStop(empty, "ledger", unclaimed, rejectedRequest));
            Require(rejectedRequest.ActionId == "" && !rejectedRequest.Stop.IsCancellationRequested);
        }
        foreach (var typed in new[] { readPrepare, readPrepare with { TaskId = "fixture", Operation = new Operation("computer_input_plan", Plan: planElement) } })
        {
            var expectedAction = typed.Operation.Kind == "app_request" ? "task:app:read" : "fixture:computer:action";
            var typedRequest = new BrokerRequest { ActionId = expectedAction };
            using var wrongStop = Signal("stop", expectedAction + ":wrong", "ledger", typed);
            Require(!Program.AcceptPreGoStop(wrongStop, "ledger", typed, typedRequest));
            Require(typedRequest.ActionId == expectedAction && !typedRequest.Stop.IsCancellationRequested);
            using var typedStop = Signal("stop", expectedAction, "ledger", typed);
            Require(Program.AcceptPreGoStop(typedStop, "ledger", typed, typedRequest));
            using var typedAck = Signal("ack", expectedAction, "ledger", typed);
            Require(Protocol.Signal(typedAck, "ack", "ledger", typed, typedRequest.ActionId));
        }
        using var mismatchedStop = Signal("stop", "task:bind:stopped", "other-ledger", unclaimed);
        var mismatchedRequest = new BrokerRequest();
        Require(!Program.AcceptPreGoStop(mismatchedStop, "ledger", unclaimed, mismatchedRequest));
        Require(mismatchedRequest.ActionId == "" && !mismatchedRequest.Stop.IsCancellationRequested);
        assertions += BrokerLifecycleTests.Run();
        assertions += SettingsUiPreferenceTests.Run();
        assertions += UacQualificationLeaseStore.RunFixtureTests();
        assertions += WindowLayoutTests.Run();
        assertions += NativePhaseTests.Run();
        var planningClock = System.Diagnostics.Stopwatch.StartNew();
        Native.Point[] curve;
        try { curve = PointerPath.Points(new() { X = -500, Y = 300 }, new() { X = 600, Y = 80 }); }
        catch (Boundary error) when (error.Code == "pointer_planning_budget_exceeded")
        {
            // This is a fixed, synthetic geometry, never a user target. Keep
            // timing failures visible instead of retrying or warming the path.
            Console.Error.WriteLine(JsonSerializer.Serialize(new { selftest = "fixed_pointer_curve", start = new[] { -500, 300 }, end = new[] { 600, 80 },
                stage = error.Data["PointerStage"], work = error.Data["PointerWork"], elapsed_ms = error.Data["PointerElapsedMs"] }));
            throw;
        }
        double pointerPlanningMs = planningClock.Elapsed.TotalMilliseconds;
        Require(curve.Length == 5 && curve[0].X > -500 && curve[^1].X < 600);
        Require(PointerPath.Points(new() { X = 0, Y = 0 }, new() { X = 5, Y = 5 }).Length == 0);
        var preparedDesktop = new DesktopShape(0, 0, 1000, 800);
        Step[] preparedBusiness = [new(new Native.Input { Data = new Native.Union {
            Mouse = new Native.Mouse { Dx = 6554, Dy = 8192, Flags = 0xc001 } } })];
        var preparedApproachFixture = new PointerPath.PreparedApproach(new() { X = 20, Y = 30 }, new() { X = 100, Y = 100 },
            preparedDesktop, new PointerGeometry.Motion(0, []), null, 12);
        Require(PointerPath.ApproachReusable(preparedApproachFixture, preparedBusiness, preparedDesktop, null, new() { X = 20, Y = 30 }));
        Require(!PointerPath.ApproachReusable(preparedApproachFixture, preparedBusiness, preparedDesktop, null, new() { X = 21, Y = 30 }));
        Require(!PointerPath.ApproachReusable(preparedApproachFixture, preparedBusiness,
            preparedDesktop with { Width = 1001 }, null, new() { X = 20, Y = 30 }));
        Require(!PointerPath.ApproachReusable(preparedApproachFixture, preparedBusiness, preparedDesktop,
            PointerGeometry.Constraints.Empty, new() { X = 20, Y = 30 }));
        var pointerLedger = new InputLedger(events => (uint)events.Length);
        var pointerReceipt = new Receipt();
        pointerLedger.Send([new Step(new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse { Flags = 0xc001 } } })], pointerReceipt, pointer: true);
        Require(pointerReceipt.PointerEvents == 1 && pointerReceipt.BusinessEvents == 0 && !pointerReceipt.BusinessAttempted);
        return new { assertions, pointerPlanningMs, nativeInputExecuted = false, mutexAcquired = false, highVerified = false, journalFixture = journalRoot };
    }
}
