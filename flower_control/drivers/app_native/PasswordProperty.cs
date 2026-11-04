using FlaUI.Core.AutomationElements;
using FlaUI.Core.Exceptions;

// UIA_IsPassword has the documented default FALSE. A provider that explicitly
// does not support it is different from one that failed to answer the query.
internal static class PasswordProperty
{
    internal static bool Read(Func<(bool Supported, bool Value)> query) =>
        ProviderReads.Required("IsPassword", () =>
        {
            try
            {
                var (supported, value) = query();
                return supported && value;
            }
            catch (PropertyNotSupportedException) { return false; }
        });

    internal static bool Read(AutomationElement element) => Read(() =>
    {
        bool supported = element.Properties.IsPassword.TryGetValue(out bool value);
        return (supported, value);
    });
}
