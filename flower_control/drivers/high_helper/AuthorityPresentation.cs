namespace Flower.HighHelper;

// Display numbers are not persisted policy values. Keep old policy/receipt
// values and independent lists intact, including frozen legacy UAC records.
internal static class AuthorityPresentation
{
    internal static int ButtonTier(int index) => index is >= 0 and < 4 ? index - 1
        : throw new Boundary("settings_tier_selection_invalid");
    internal static bool Selectable(int tier) => tier is >= -1 and <= 2;
    internal static string Name(int tier) => tier switch {
        -1 => UiText.Get("完全停止"), 0 => UiText.Get("普通控制"), 1 => UiText.Get("管理员窗口"), 2 => UiText.Get("管理员执行"),
        3 => UiText.Get("旧系统接管（已冻结）"), _ => UiText.Get("权限状态异常") };
    internal static string Label(int tier) => Selectable(tier) ? (tier + 2).ToString("00") + " " + Name(tier) : Name(tier);
    // GDI COLORREF (BGR): white, blue, orange, red. These are presentation
    // colors only; persisted tiers and permissions retain their old values.
    internal static uint Ink(int tier) => tier switch {
        -1 => 0xF2F2F2u, 0 => 0xFFB778u, 1 => 0x5CB1FFu, 2 => 0x6B6BFFu, _ => 0xC1B9B8u };
    internal static int FlowerState(int tier) => tier == 2 ? 3 : tier;
    internal static string FrozenNotice => UiText.Get("UAC 已冻结：不能可靠确认提示由目标程序触发，不再推进或提供启用入口。已有结果保留，火绒等提示兼容列为欠债。");
}
