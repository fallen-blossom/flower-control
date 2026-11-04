namespace Flower.HighHelper;

// Layout coordinates are device-independent. Font size follows DPI, never the
// monitor width. This mirrors the accepted prototype
// (docs/design/prototypes/flower-control-settings-directions-2026-10-17.html):
// a hero band plus status chips on the overview page, setting rows that pair a
// name/description column with a switch on the right, warning banners and
// collapsible explanations on the permission pages.
internal static class PermissionPageLayout
{
    internal readonly record struct Box(int X, int Y, int W, int H);
    internal sealed record Result(Dictionary<int, Box> Controls, (int Top, int Height)[] Sections,
        (int Top, int Height)[] Banners, (int Top, int Height)[] Heroes,
        (int Left, int Top, int Width, int Height)[] Chips,
        (int Top, int Left, int Right)[] Separators, int Height);
    internal const int NavigationThreshold = 880;
    internal const int HeroHeight = 98, ChipsHeight = 46, BannerHeight = 62;
    internal static Result Build(int page, int width, Func<int, int, int> height, bool details = false, string detailMode = "help",
        bool explanationOpen = false)
    {
        var boxes = new Dictionary<int, Box>(); var sections = new List<(int, int)>();
        var banners = new List<(int, int)>(); var heroes = new List<(int, int)>(); var chips = new List<(int, int, int, int)>();
        var separators = new List<(int, int, int)>();
        int cardTop = 0;
        int y = 0, inner = Math.Max(200, width - 40);
        int H(int id, int w) => Math.Max(22, height(id, w));
        void Full(int id) { int h = H(id, inner); boxes[id] = new(20, y, inner, h); y += h + 12; }
        void Divider()
        {
            // Mirrors .row + .row in the prototype: a hairline only between
            // rows inside a card, never before the first row.
            if (y > cardTop + 18) separators.Add((y - 6, 20, 20 + inner));
        }
        void Row(params int[] ids)
        {
            Divider();
            int min = ids.Any(id => id is 30 or 67 or 68 or 72 or 310 or 311) ? 216 : 170;
            if (inner < ids.Length * min + (ids.Length - 1) * 12) { foreach (int id in ids) Full(id); return; }
            int w = (inner - (ids.Length - 1) * 12) / ids.Length, h = ids.Max(id => H(id, w));
            for (int i = 0; i < ids.Length; i++) boxes[ids[i]] = new(20 + i * (w + 12), y, w, h);
            y += h + 12;
        }
        // One prototype "row": the name and its explanation share a column on
        // the left, and the switch keeps its intrinsic 46x26 size on the right.
        // A switch keeps its own label so the native control still owns the
        // accessible name, mnemonic and ToggleState; the description sits under
        // it and stops short of the switch column, exactly like the prototype.
        void Setting(int descId, int switchId)
        {
            Divider();
            int nameHeight = H(switchId, inner);
            int descHeight = descId == 0 ? 0 : H(descId, inner - 62);
            boxes[switchId] = new(20, y, inner, nameHeight);
            if (descId != 0) boxes[descId] = new(20, y + nameHeight + 2, Math.Max(160, inner - 62), descHeight);
            y += nameHeight + (descHeight == 0 ? 0 : descHeight + 2) + 12;
        }
        // Card rows whose action is a normal button rather than a switch.
        void Link(int nameId, int descId, int buttonId)
        {
            Divider();
            int buttonWidth = 108;
            int textWidth = Math.Max(160, inner - buttonWidth - 16);
            int nameHeight = H(nameId, textWidth);
            int descHeight = descId == 0 ? 0 : H(descId, textWidth);
            int buttonHeight = Math.Max(34, H(buttonId, buttonWidth));
            boxes[nameId] = new(20, y, textWidth, nameHeight);
            if (descId != 0) boxes[descId] = new(20, y + nameHeight + 2, textWidth, descHeight);
            boxes[buttonId] = new(20 + inner - buttonWidth, y, buttonWidth, buttonHeight);
            y += Math.Max(nameHeight + (descHeight == 0 ? 0 : descHeight + 2), buttonHeight) + 14;
        }
        // A labelled field whose control has a fixed intrinsic width (the HUD
        // position combo). Keeping the label and description on the left is
        // the same hierarchy as a setting row, without pretending a dropdown
        // is a toggle.
        void Field(int nameId, int descId, int controlId, int controlWidth)
        {
            Divider();
            int buttonWidth = Math.Max(96, controlWidth);
            int textWidth = Math.Max(160, inner - buttonWidth - 16);
            int nameHeight = H(nameId, textWidth);
            int descHeight = descId == 0 ? 0 : H(descId, textWidth);
            boxes[nameId] = new(20, y, textWidth, nameHeight);
            if (descId != 0) boxes[descId] = new(20, y + nameHeight + 2, textWidth, descHeight);
            boxes[controlId] = new(20 + inner - buttonWidth, y + Math.Max(0, (nameHeight - 34) / 2), buttonWidth, 34);
            y += nameHeight + (descHeight == 0 ? 0 : descHeight + 2) + 12;
        }
        void Card(Action content, int? fixedHeight = null)
        {
            int top = y; y += 16; cardTop = top; content(); y += 4;
            sections.Add((top, y - top)); y += 12;
        }
        void Banner(int id, int minHeight = BannerHeight)
        {
            int h = Math.Max(minHeight, H(id, inner - 56));
            boxes[id] = new(48, y + 18, inner - 32, h);
            banners.Add((y, h + 20));
            y += h + 32;
        }
        void Hero(int titleId, int leadId)
        {
            heroes.Add((y, HeroHeight));
            boxes[titleId] = new(28, y + 32, inner - 16, 30);
            boxes[leadId] = new(28, y + 62, inner - 16, 24);
            y += HeroHeight + 12;
        }
        void Chips(params int[] ids)
        {
            int gap = 10, outer = inner + 32, w = (outer - gap * (ids.Length - 1)) / ids.Length;
            for (int i = 0; i < ids.Length; i++)
            {
                boxes[ids[i]] = new(4 + i * (w + gap) + 28, y + 6, w - 34, ChipsHeight - 12);
                chips.Add((4 + i * (w + gap), y, w, ChipsHeight));
            }
            y += ChipsHeight + 16;
        }
        if (details) Card(() => { Full(1091); Full(92); if (detailMode == "close") Row(95, 98, 99);
            else if (detailMode == "reload") Row(100, 99); else if (detailMode == "candidate") Row(96, 97); else Full(93); });
        switch (page)
        {
            case 6: // 状态总览
                Hero(3000, 3001);
                Chips(3002, 3003, 3004);
                Card(() => { Full(3010); Link(3011, 3012, 3015); Link(3013, 3014, 3016); });
                Banner(3020, 52);
                Card(() => { Full(3021); Full(3022); });
                break;
            case 0:
                Card(() => { Full(2020); Setting(2021, 6); Field(1002, 2023, 7, 200); });
                Card(() => Setting(2022, 4)); break;
            case 1:
                Card(() => { Row(3301, 3302); Row(3303, 3304); Full(2001); Full(2034); Full(2040); });
                Banner(3030);
                Card(() => { Full(3033); Row(310, 311); });
                Card(() => { Full(3401); Full(3404); Full(3402); Full(3403); });
                Card(() => { Full(3031); if (explanationOpen) Full(3032); });
                Card(() => Full(2009)); break;
            case 2:
                Card(() => { Full(3331); Row(3311, 3312); Full(2035); });
                Card(() => Full(2006));
                Card(() => { Row(63, 76, 77); Full(2100); });
                Card(() => { Row(1005, 62); Full(66); Full(2008); Row(64, 65); Full(2101); });
                Card(() => Full(2007));
                Card(() => { Full(3411); Full(3412); Row(3413, 3414, 3415); Full(3416); }); break;
            case 3:
                Card(() => { Full(3332); Row(3321, 3322); Full(2036); });
                Banner(3040);
                Card(() => Full(2106));
                Card(() => { Full(2032); Full(81); });
                Card(() => { Row(1008, 162); Row(163, 176, 177); Full(2211); Full(166); Full(2108); Row(164, 165); Full(2033); });
                Card(() => { Full(3421); Full(3422); Row(3423, 3424, 3425); Full(3426); });
                Card(() => { Full(3041); if (explanationOpen) Full(3042); }); break;
            case 4:
                Card(() => { Row(1003, 13); Full(2003); Full(11); });
                Card(() => {
                    Full(1004); Full(20); Full(21); Full(2004);
                    int columns = inner >= 480 ? 4 : 2, cell = (inner - (columns - 1) * 12) / columns;
                    for (int start = 0; start < 4; start += columns)
                    {
                        for (int i = start; i < Math.Min(4, start + columns); i++)
                        { boxes[2010 + i] = new(20 + (i - start) * (cell + 12), y, cell, 22);
                            boxes[22 + i] = new(20 + (i - start) * (cell + 12), y + 28, cell, 34); }
                        y += 74;
                    }
                    Row(26, 27); Full(28); Full(2005);
                }); break;
            default:
                Card(() => { Full(1006); Full(2102); Row(67, 68); Full(2212); });
                Card(() => { Row(69, 72); Full(2103); });
                Card(() => { Full(73); Full(2104); }); Card(() => { Full(74); Full(2105); }); break;
        }
        return new(boxes, sections.ToArray(), banners.ToArray(), heroes.ToArray(), chips.ToArray(), separators.ToArray(), y);
    }
}
