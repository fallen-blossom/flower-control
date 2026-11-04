// Deterministic local geometry only. Never reads policy or dispatches input.
namespace Flower.HighHelper;

internal static class PointerGeometry
{
    internal const string Spec = "bezier-distance-v1";
    internal const int MaxObstacles = 16, MaxVertices = 192, MaxVisibilityVertices = 96, MaxSpans = 2048, MaxSamples = 112;
    // One second is a best-effort user budget; motion limits are authoritative.
    private const int MinSampleIntervalMs = 5, TargetSampleIntervalMs = 12;
    private const double MaxFreeBendPx = 96.0;
    private const double Q1 = 15.0 / 8, RoutingRoom = 12;
    private const double ClearanceComfort = 24.0, MaxGapCorridor = 240.0;
    private static readonly double Q2 = 10 * Math.Sqrt(3) / 3;
    internal readonly record struct V(double X, double Y)
    {
        public static V operator +(V a, V b) => new(a.X + b.X, a.Y + b.Y);
        public static V operator -(V a, V b) => new(a.X - b.X, a.Y - b.Y);
        public static V operator *(V a, double k) => new(a.X * k, a.Y * k);
        internal double Norm => double.Hypot(X, Y);
        internal static double Dot(V a, V b) => a.X * b.X + a.Y * b.Y;
        internal static double Cross(V a, V b) => a.X * b.Y - a.Y * b.X;
        internal static V Lerp(V a, V b, double t) => new(a.X + (b.X - a.X) * t, a.Y + (b.Y - a.Y) * t);
        internal Native.Point Pixel => new() { X = checked((int)Math.Round(X)), Y = checked((int)Math.Round(Y)) };
        internal static V Of(Native.Point p) => new(p.X, p.Y);
    }
    internal readonly record struct Box(double Left, double Top, double Right, double Bottom)
    {
        internal bool Contains(V p) => Left <= p.X && p.X <= Right && Top <= p.Y && p.Y <= Bottom;
        internal Box Inflate(double m) => new(Left - m, Top - m, Right + m, Bottom + m);
    }
    internal sealed record Constraints(Box[] Obstacles, Box Footprint, int UncertaintyPx = 4)
    {
        internal double Margin => 20 + Math.Max(4, UncertaintyPx);
        internal static Constraints Empty => new([], new(0, 0, 0, 0));
        internal void Validate()
        {
            if (Obstacles.Length > MaxObstacles) throw new Boundary("pointer_obstacle_limit");
            foreach (var r in Obstacles)
                if (!ValidRect(r)) throw new Boundary("invalid_pointer_bounds");
            var f = Footprint;
            if (new[] { f.Left, f.Top, f.Right, f.Bottom }.Any(n => !double.IsFinite(n) || n != Math.Truncate(n) || Math.Abs(n) > 10000)
                || !(f.Left <= 0 && f.Right >= 0 && f.Top <= 0 && f.Bottom >= 0))
                throw new Boundary("invalid_pointer_footprint");
            if (UncertaintyPx is < 0 or > 256) throw new Boundary("invalid_pointer_uncertainty");
        }
        internal Box[] Expanded() => Obstacles.Select(r => new Box(r.Left - Footprint.Right - Margin,
            r.Top - Footprint.Bottom - Margin, r.Right - Footprint.Left + Margin, r.Bottom - Footprint.Top + Margin)).ToArray();
    }
    internal sealed record Limits(double Speed = 3000, double Acceleration = 300000, double Jerk = 100000000, double Utilization = .8)
    {
        internal double WorkingSpeed => Speed * Utilization;
        internal double TangentialAcceleration => Acceleration * Utilization * .45;
        internal double NormalAcceleration => Acceleration * Utilization * .45;
        internal double TangentialJerk => Jerk * Utilization * .28;
        internal double GeometricJerk => Jerk * Utilization * .28;
        internal double CrossJerk => Jerk * Utilization * .28;
        internal void Validate()
        {
            if (new[] { Speed, Acceleration, Jerk, Utilization }.Any(x => !double.IsFinite(x) || x <= 0) || Utilization > .8)
                throw new Boundary("invalid_pointer_limits");
        }
    }
    internal sealed class Budget
    {
        private long work, next = 128;
        private readonly Action? checkpoint;
        internal Budget(Action? checkpoint = null) { this.checkpoint = checkpoint; }
        internal string Stage { get; set; } = "geometry";
        internal void Tick(int units = 1, bool final = false)
        {
            work += units;
            bool check = final || work >= next;
            if (check)
            {
                next = work + 128;
                checkpoint?.Invoke();
            }
        }
    }
    internal sealed record Cubic(V P0, V P1, V P2, V P3)
    {
        internal V[] Controls => [P0, P1, P2, P3];
        internal V Point(double t)
        {
            V a = V.Lerp(P0, P1, t), b = V.Lerp(P1, P2, t), c = V.Lerp(P2, P3, t);
            return V.Lerp(V.Lerp(a, b, t), V.Lerp(b, c, t), t);
        }
        internal V Derivative(double t)
        {
            V d0 = (P1 - P0) * 3, d1 = (P2 - P1) * 3, d2 = (P3 - P2) * 3;
            return V.Lerp(V.Lerp(d0, d1, t), V.Lerp(d1, d2, t), t);
        }
        internal (Cubic A, Cubic B) Split(double t = .5)
        {
            V a = V.Lerp(P0, P1, t), b = V.Lerp(P1, P2, t), c = V.Lerp(P2, P3, t);
            V d = V.Lerp(a, b, t), e = V.Lerp(b, c, t), f = V.Lerp(d, e, t);
            return (new(P0, a, d, f), new(f, e, c, P3));
        }
    }
    internal sealed record ArcSpan(int CurveIndex, double T0, double T1, double S0, double S1, double Curvature, double CurvatureSlope);
    internal sealed record RequiredPoint(double Distance, V Point);
    internal sealed record Route(Cubic[] Curves, Box[] Obstacles, Box? Bounds, ArcSpan[] Spans, double[] Ends,
        double Length, RequiredPoint[] Required, double[] Sharp);
    internal sealed record Motion(int DurationMs, PointerPath.Sample[] Samples, Route? Route = null, Profile? Profile = null, bool Automatic = false);

    private static bool ValidRect(Box r) => new[] { r.Left, r.Top, r.Right, r.Bottom }
        .All(n => double.IsFinite(n) && n == Math.Truncate(n) && n >= int.MinValue && n <= int.MaxValue)
        && r.Left < r.Right && r.Top < r.Bottom;
    private static bool Inside(V p, Box? bounds) => bounds is null || bounds.Value.Contains(p);
    private static Cubic Line(V a, V b) => new(a, V.Lerp(a, b, 1.0 / 3), V.Lerp(a, b, 2.0 / 3), b);
    internal static bool SegmentClear(V a, V b, Box[] obstacles)
    {
        V d = b - a;
        foreach (var r in obstacles)
        {
            double lo = 0, hi = 1;
            foreach (var axis in new[] { (a.X, d.X, r.Left, r.Right), (a.Y, d.Y, r.Top, r.Bottom) })
            {
                var (origin, delta, lower, upper) = axis;
                if (Math.Abs(delta) < 1e-15)
                {
                    if (origin < lower || origin > upper) { lo = 1; hi = 0; break; }
                }
                else
                {
                    double enter = (lower - origin) / delta, leave = (upper - origin) / delta;
                    if (enter > leave) (enter, leave) = (leave, enter);
                    lo = Math.Max(lo, enter); hi = Math.Min(hi, leave);
                }
            }
            if (lo <= hi) return false;
        }
        return true;
    }
    private static double RectDistance(V p, Box r)
    {
        double dx = Math.Max(Math.Max(r.Left - p.X, 0), p.X - r.Right);
        double dy = Math.Max(Math.Max(r.Top - p.Y, 0), p.Y - r.Bottom);
        return Math.Sqrt(dx * dx + dy * dy);
    }
    private static double SegmentClearance(V a, V b, Box[] obstacles)
    {
        if (obstacles.Length == 0) return double.PositiveInfinity;
        double clearance = double.PositiveInfinity;
        // This is only a routing preference. Exact safety remains SegmentClear
        // and CurveClear, so a coarse sample keeps dense-plan latency bounded.
        for (int i = 0; i <= 4; ++i)
        {
            V sample = V.Lerp(a, b, i / 4.0);
            foreach (var obstacle in obstacles)
                clearance = Math.Min(clearance, RectDistance(sample, obstacle));
        }
        return clearance;
    }
    private static double EdgeCost(V a, V b, Box[] obstacles)
    {
        double length = (b - a).Norm;
        double clearance = SegmentClearance(a, b, obstacles);
        double deficit = Math.Max(0, ClearanceComfort - clearance);
        // Visibility-graph shortest paths naturally graze obstacle corners.
        // Keep length dominant but charge for narrow-corridor clearance.
        return length + 1.8 * deficit * deficit / ClearanceComfort + 3 / (clearance + 1);
    }
    private static IEnumerable<V> GapCandidates(Box[] obstacles)
    {
        for (int i = 0; i < obstacles.Length; ++i)
            for (int j = i + 1; j < obstacles.Length; ++j)
            {
                Box a = obstacles[i], b = obstacles[j];
                double horizontal = a.Right <= b.Left ? b.Left - a.Right : b.Right <= a.Left ? a.Left - b.Right : 0;
                if (horizontal > 0 && horizontal <= MaxGapCorridor)
                {
                    double top = Math.Max(a.Top, b.Top), bottom = Math.Min(a.Bottom, b.Bottom);
                    if (top < bottom)
                    {
                        double x = a.Right <= b.Left ? (a.Right + b.Left) / 2 : (b.Right + a.Left) / 2;
                        foreach (double fraction in new[] { .25, .5, .75 }) yield return new V(x, top + (bottom - top) * fraction);
                    }
                }
                double vertical = a.Bottom <= b.Top ? b.Top - a.Bottom : b.Bottom <= a.Top ? a.Top - b.Bottom : 0;
                if (vertical > 0 && vertical <= MaxGapCorridor)
                {
                    double left = Math.Max(a.Left, b.Left), right = Math.Min(a.Right, b.Right);
                    if (left < right)
                    {
                        double y = a.Bottom <= b.Top ? (a.Bottom + b.Top) / 2 : (b.Bottom + a.Top) / 2;
                        foreach (double fraction in new[] { .25, .5, .75 }) yield return new V(left + (right - left) * fraction, y);
                    }
                }
            }
    }
    private static V[] Hull(V[] input)
    {
        var points = input.Distinct().OrderBy(p => p.X).ThenBy(p => p.Y).ToArray();
        if (points.Length < 3) return points;
        static List<V> Half(IEnumerable<V> items)
        {
            var values = new List<V>();
            foreach (var p in items)
            {
                while (values.Count >= 2 && V.Cross(values[^1] - values[^2], p - values[^1]) <= 0) values.RemoveAt(values.Count - 1);
                values.Add(p);
            }
            return values;
        }
        return Half(points).SkipLast(1).Concat(Half(points.Reverse()).SkipLast(1)).ToArray();
    }
    private static bool HullDisjoint(V[] hull, Box r)
    {
        V[] box = [new(r.Left, r.Top), new(r.Right, r.Top), new(r.Right, r.Bottom), new(r.Left, r.Bottom)];
        var axes = new List<V> { new(1, 0), new(0, 1) };
        if (hull.Length > 1)
            for (int i = 0; i < hull.Length; ++i)
            {
                V d = hull[(i + 1) % hull.Length] - hull[i]; axes.Add(new(-d.Y, d.X));
            }
        foreach (V axis in axes)
        {
            if (axis == new V(0, 0)) continue;
            var a = hull.Select(p => V.Dot(p, axis)).ToArray();
            var b = box.Select(p => V.Dot(p, axis)).ToArray();
            if (a.Max() < b.Min() - 1e-9 || b.Max() < a.Min() - 1e-9) return true;
        }
        return false;
    }
    private static bool CurveClear(Cubic curve, Box[] obstacles, Box? bounds, Budget budget, int depth = 0)
    {
        budget.Tick();
        if (!curve.Controls.All(p => Inside(p, bounds))) return false;
        var hull = Hull(curve.Controls);
        var remaining = obstacles.Where(r => !HullDisjoint(hull, r)).ToArray();
        if (remaining.Length == 0) return true;
        if (depth >= 12) return false;
        var (a, b) = curve.Split();
        return CurveClear(a, remaining, bounds, budget, depth + 1) && CurveClear(b, remaining, bounds, budget, depth + 1);
    }
    private static V[] VisibleRoute(V start, V end, Box[] obstacles, Box? bounds, Budget budget)
    {
        // A slightly larger routing envelope prevents smoothing and integer
        // sampling from shaving the normal obstacle margin back to a graze.
        var routing = obstacles.Select(r => r.Inflate(8)).ToArray();
        if (SegmentClear(start, end, routing)) return [start, end];
        var support = routing.Select(r => r.Inflate(RoutingRoom)).ToArray();
        var candidates = new List<V>();
        foreach (var r in support)
            candidates.AddRange([new(r.Left, r.Top), new(r.Right, r.Top), new(r.Right, r.Bottom), new(r.Left, r.Bottom)]);
        for (int i = 0; i < support.Length; ++i)
            foreach (var b in support.Skip(i + 1))
            {
                var a = support[i];
                foreach (double x in new[] { a.Left, a.Right })
                    foreach (double y in new[] { b.Top, b.Bottom })
                        if (b.Left <= x && x <= b.Right && a.Top <= y && y <= a.Bottom) candidates.Add(new(x, y));
                foreach (double x in new[] { b.Left, b.Right })
                    foreach (double y in new[] { a.Top, a.Bottom })
                        if (a.Left <= x && x <= a.Right && b.Top <= y && y <= b.Bottom) candidates.Add(new(x, y));
            }
        candidates = candidates.Distinct().ToList();
        int candidateLimit = Math.Min(MaxVertices - 2, MaxVisibilityVertices - 2);
        int gapRoom = Math.Max(0, candidateLimit - candidates.Count);
        candidates.AddRange(GapCandidates(routing).Where(p => !candidates.Contains(p)).Distinct().Take(gapRoom));
        var valid = candidates.Where(p => Inside(p, bounds) && SegmentClear(p, p, routing) && p != start && p != end)
            .Distinct().OrderBy(p => p.X).ThenBy(p => p.Y).ToArray();
        if (valid.Length > candidateLimit) throw new Boundary("pointer_vertex_limit");
        V[] nodes = [start, end, .. valid];
        var best = new Dictionary<int, double> { [0] = 0 };
        var previous = new Dictionary<int, int>(); var visited = new HashSet<int>();
        var queue = new PriorityQueue<(double Priority, double Cost, int Index), (double Priority, double Cost, int Index)>();
        const double heuristicWeight = 1.5;
        double startPriority = heuristicWeight * (end - start).Norm;
        queue.Enqueue((startPriority, 0, 0), (startPriority, 0, 0));
        var visibility = new Dictionary<(int, int), bool>();
        while (queue.TryDequeue(out var item, out _))
        {
            var (_, cost, index) = item;
            if (!visited.Add(index)) continue;
            if (index == 1)
            {
                var path = new List<V> { end };
                while (index != 0) { index = previous[index]; path.Add(nodes[index]); }
                path.Reverse(); return path.ToArray();
            }
            for (int next = 0; next < nodes.Length; ++next)
            {
                if (next == index || visited.Contains(next)) continue;
                var key = (Math.Min(index, next), Math.Max(index, next));
                if (!visibility.TryGetValue(key, out bool clear))
                {
                    budget.Tick(routing.Length); clear = SegmentClear(nodes[index], nodes[next], routing); visibility[key] = clear;
                }
                if (!clear) continue;
                double value = cost + EdgeCost(nodes[index], nodes[next], routing);
                if (value < best.GetValueOrDefault(next, double.PositiveInfinity))
                {
                    best[next] = value; previous[next] = index;
                    // Every cost term is non-negative, so Euclidean remainder
                    // is admissible and bounded A* avoids exhausting the graph.
                    double priority = value + heuristicWeight * (end - nodes[next]).Norm;
                    queue.Enqueue((priority, value, next), (priority, value, next));
                }
            }
        }
        throw new Boundary("pointer_no_route_with_normal_margin");
    }
    private static Cubic[] RoundRoute(V[] points, Box[] obstacles, Box? bounds, Budget budget)
    {
        var curves = new List<Cubic>(); V current = points[0];
        for (int i = 1; i < points.Length - 1; ++i)
        {
            V incoming = points[i] - points[i - 1], outgoing = points[i + 1] - points[i];
            double n1 = incoming.Norm, n2 = outgoing.Norm;
            if (n1 < 1e-9 || n2 < 1e-9) throw new Boundary("pointer_degenerate_route");
            V e1 = incoming * (1 / n1), e2 = outgoing * (1 / n2), corner = points[i];
            if (Math.Abs(V.Cross(e1, e2)) < 1e-10 && V.Dot(e1, e2) > 0) continue;
            double trim = Math.Min(n1, n2) * .24; Cubic? rounded = null;
            for (int attempt = 0; attempt < 12; ++attempt)
            {
                V p = corner - e1 * trim, q = corner + e2 * trim;
                var candidate = new Cubic(p, corner, corner, q);
                if (CurveClear(Line(current, p), obstacles, bounds, budget) && CurveClear(candidate, obstacles, bounds, budget))
                { rounded = candidate; break; }
                trim *= .5;
            }
            if (rounded is null) throw new Boundary("pointer_no_round_route_with_normal_margin");
            if ((rounded.P0 - current).Norm > 1e-8) curves.Add(Line(current, rounded.P0));
            curves.Add(rounded); current = rounded.P3;
        }
        if ((points[^1] - current).Norm > 1e-8) curves.Add(Line(current, points[^1]));
        if (!curves.All(c => CurveClear(c, obstacles, bounds, budget))) throw new Boundary("pointer_route_not_certified");
        return curves.ToArray();
    }
    private static Cubic[] SmoothWaypoints(V[] points, Box[] obstacles, Box? bounds, Budget budget)
    {
        if (points.Length < 3) return [Line(points[0], points[^1])];
        var tangents = new V[points.Length];
        for (int i = 0; i < points.Length; ++i)
        {
            V direction;
            if (i == 0) direction = points[1] - points[0];
            else if (i == points.Length - 1) direction = points[^1] - points[^2];
            else
            {
                V incoming = points[i] - points[i - 1], outgoing = points[i + 1] - points[i];
                double ni = incoming.Norm, no = outgoing.Norm;
                if (ni < 1e-9 || no < 1e-9) throw new Boundary("pointer_degenerate_route");
                direction = incoming * (1 / ni) + outgoing * (1 / no);
                if (direction.Norm < 1e-9) direction = outgoing;
            }
            if (direction.Norm < 1e-9) throw new Boundary("pointer_degenerate_route");
            tangents[i] = direction * (1 / direction.Norm);
        }
        var spans = Enumerable.Range(0, points.Length - 1).Select(i => (points[i + 1] - points[i]).Norm).ToArray();
        var radii = new double[points.Length];
        for (int i = 0; i < points.Length; ++i)
            radii[i] = i == 0 ? spans[0] : i == points.Length - 1 ? spans[^1] : Math.Min(spans[i - 1], spans[i]);
        foreach (double tension in new[] { 1.0 / 3, 1.0 / 4, 1.0 / 6, 1.0 / 10, 1.0 / 20, 1.0 / 50 })
        {
            var curves = new Cubic[points.Length - 1];
            for (int i = 0; i < curves.Length; ++i)
            {
                V p0 = points[i], p3 = points[i + 1];
                V p1 = p0 + tangents[i] * (radii[i] * tension);
                V p2 = p3 - tangents[i + 1] * (radii[i + 1] * tension);
                curves[i] = new(p0, p1, p2, p3);
            }
            if (curves.All(c => CurveClear(c, obstacles, bounds, budget))) return curves;
        }
        throw new Boundary("pointer_smoothed_path_not_certified");
    }
    private static readonly double[] GaussX = [0, -.5384693101056831, .5384693101056831, -.906179845938664, .906179845938664];
    private static readonly double[] GaussW = [.5688888888888889, .4786286704993665, .4786286704993665, .2369268850561891, .2369268850561891];
    private static double Length(Cubic curve, double lo, double hi)
    {
        double mid = (lo + hi) / 2, half = (hi - lo) / 2, sum = 0;
        for (int i = 0; i < 5; ++i) sum += GaussW[i] * curve.Derivative(mid + half * GaussX[i]).Norm;
        return half * sum;
    }
    private static (V[] A, V[] B) SplitControls(V[] values, double t)
    {
        int count = values.Length;
        var row = (V[])values.Clone(); var a = new V[count]; var b = new V[count];
        a[0] = row[0]; b[count - 1] = row[count - 1];
        for (int width = count - 1; width > 0; --width)
        {
            for (int i = 0; i < width; ++i) row[i] = V.Lerp(row[i], row[i + 1], t);
            a[count - width] = row[0]; b[width - 1] = row[width - 1];
        }
        return (a, b);
    }
    private static V[] Restrict(V[] points, double lo, double hi)
    {
        if (hi < 1) points = SplitControls(points, hi).A;
        if (lo > 0) points = SplitControls(points, lo / hi).B;
        return points;
    }
    private static int Comb(int n, int k)
    {
        int value = 1;
        for (int i = 1; i <= k; ++i) value = value * (n - i + 1) / i;
        return value;
    }
    private static double ProductBound(V[] a, V[] b, Func<V, V, double> product)
    {
        int m = a.Length - 1, n = b.Length - 1; double maximum = 0;
        for (int k = 0; k <= m + n; ++k)
        {
            double value = 0;
            for (int i = Math.Max(0, k - n); i <= Math.Min(m, k); ++i)
                value += Comb(m, i) * (double)Comb(n, k - i) / Comb(m + n, k) * product(a[i], b[k - i]);
            maximum = Math.Max(maximum, Math.Abs(value));
        }
        return maximum;
    }
    private static (double K, double Slope) CurvatureBounds(Cubic curve, double lo, double hi)
    {
        if (curve.P1 == V.Lerp(curve.P0, curve.P3, 1.0 / 3)
            && curve.P2 == V.Lerp(curve.P0, curve.P3, 2.0 / 3)) return (0, 0);
        V[] d1 = [(curve.P1 - curve.P0) * 3, (curve.P2 - curve.P1) * 3, (curve.P3 - curve.P2) * 3];
        V[] d2 = [(d1[1] - d1[0]) * 2, (d1[2] - d1[1]) * 2];
        V[] d3 = [d2[1] - d2[0]];
        var a = Restrict(d1, lo, hi); var b = Restrict(d2, lo, hi); var c = d3;
        V middle = curve.Derivative((lo + hi) / 2); double speed = middle.Norm;
        if (speed < 1e-10) throw new Boundary("pointer_degenerate_derivative");
        V direction = middle * (1 / speed); double lower = a.Min(x => V.Dot(x, direction));
        if (lower <= 1e-9) throw new Boundary("pointer_derivative_bound_unresolved");
        double cross12 = ProductBound(a, b, V.Cross);
        if (cross12 < 1e-9 && c.Max(x => x.Norm) < 1e-8) return (0, 0);
        double cross13 = ProductBound(a, c, V.Cross), dot12 = ProductBound(a, b, V.Dot);
        return (cross12 / Math.Pow(lower, 3), cross13 / Math.Pow(lower, 4) + 3 * cross12 * dot12 / Math.Pow(lower, 6));
    }
    private static Route MakeRoute(Cubic[] curves, Box[] obstacles, Box? bounds, V[] requiredPoints, Budget budget)
    {
        var spans = new List<ArcSpan>(); double total = 0;
        var required = new List<RequiredPoint> { new(0, curves[0].P0) }; var sharp = new List<double>();
        for (int index = 0; index < curves.Length; ++index)
        {
            var curve = curves[index];
            if (index > 0)
            {
                V a = curves[index - 1].Derivative(1), b = curve.Derivative(0);
                if (V.Dot(a, b) <= 0 || Math.Abs(V.Cross(a, b)) > 1e-8 * a.Norm * b.Norm) sharp.Add(total);
                if (requiredPoints.Contains(curve.P0)) required.Add(new(total, curve.P0));
            }
            void Visit(Cubic piece, double t0, double t1, double tolerance, int depth)
            {
                budget.Tick();
                if (spans.Count >= MaxSpans) throw new Boundary("pointer_arc_table_limit");
                double polygon = (piece.P1 - piece.P0).Norm;
                polygon += (piece.P2 - piece.P1).Norm;
                polygon += (piece.P3 - piece.P2).Norm;
                double chord = (piece.P3 - piece.P0).Norm;
                (double K, double Slope)? local = null;
                try { local = CurvatureBounds(curve, t0, t1); }
                catch (Boundary) { if (depth >= 14) throw; }
                if (depth >= 14 && (polygon - chord > tolerance || local is null))
                    throw new Boundary("pointer_arc_precision_unresolved");
                if (t1 - t0 > .5 || polygon > 24 || polygon - chord > tolerance || local is null)
                {
                    var (a, b) = piece.Split(); double mid = (t0 + t1) / 2;
                    Visit(a, t0, mid, tolerance / 2, depth + 1); Visit(b, mid, t1, tolerance / 2, depth + 1);
                }
                else
                {
                    double length = Length(curve, t0, t1);
                    if (length <= 1e-10) throw new Boundary("pointer_zero_arc_span");
                    spans.Add(new(index, t0, t1, total, total + length, local.Value.K, local.Value.Slope)); total += length;
                }
            }
            Visit(curve, 0, 1, .025, 0);
        }
        required.Add(new(total, curves[^1].P3));
        return new(curves, obstacles, bounds, spans.ToArray(), spans.Select(s => s.S1).ToArray(), total, required.ToArray(), sharp.ToArray());
    }
    internal static Route PlanGeometry(V start, V end, Box? bounds = null, Constraints? constraints = null, bool curved = true, V[]? waypoints = null, Budget? budget = null)
    {
        constraints ??= Constraints.Empty; constraints.Validate();
        Box? area = null;
        if (bounds is { } r)
        {
            if (!ValidRect(r)) throw new Boundary("invalid_pointer_bounds");
            var f = constraints.Footprint;
            area = new(r.Left - f.Left, r.Top - f.Top, r.Right - 1 - f.Right, r.Bottom - 1 - f.Bottom);
            if (!Inside(start, area) || !Inside(end, area)) throw new Boundary("pointer_point_outside_bounds");
        }
        var obstacles = constraints.Expanded();
        if (!SegmentClear(start, start, obstacles) || !SegmentClear(end, end, obstacles)) throw new Boundary("pointer_point_in_obstacle_margin");
        if (start == end && waypoints is null) throw new Boundary("pointer_zero_route");
        budget ??= new Budget(); Cubic[] curves; V[] required = [];
        if (waypoints is not null)
        {
            if (waypoints.Length is < 2 or > 64 || waypoints[0] != start || waypoints[^1] != end)
                throw new Boundary("invalid_pointer_waypoints");
            for (int i = 0; i < waypoints.Length; ++i)
            {
                if (!Inside(waypoints[i], area)) throw new Boundary("pointer_point_outside_bounds");
                if (i > 0 && (waypoints[i] == waypoints[i - 1] || !SegmentClear(waypoints[i - 1], waypoints[i], obstacles)))
                    throw new Boundary("pointer_path_intersects_obstacle_margin");
            }
            curves = curved ? SmoothWaypoints(waypoints, obstacles, area, budget)
                : Enumerable.Range(1, waypoints.Length - 1).Select(i => Line(waypoints[i - 1], waypoints[i])).ToArray();
            required = waypoints;
        }
        else if (SegmentClear(start, end, obstacles))
        {
            Cubic? candidate = null;
            if (curved)
            {
                V delta = end - start, normal = new(-delta.Y / delta.Norm, delta.X / delta.Norm);
                foreach (double factor in new[] { 1.0, -1.0, .5, -.5, .25, -.25 })
                {
                    double bend = Math.Min(delta.Norm * .12, MaxFreeBendPx) * factor;
                    var value = new Cubic(start, V.Lerp(start, end, 1.0 / 3) + normal * bend, V.Lerp(start, end, 2.0 / 3) + normal * bend, end);
                    if (CurveClear(value, obstacles, area, budget)) { candidate = value; break; }
                }
            }
            curves = [candidate ?? Line(start, end)];
        }
        else curves = RoundRoute(VisibleRoute(start, end, obstacles, area, budget), obstacles, area, budget);
        var route = MakeRoute(curves, obstacles, area, required, budget);
        budget.Tick(final: true);
        return route;
    }
    private static int UpperBound(double[] values, double value)
    {
        int lo = 0, hi = values.Length;
        while (lo < hi) { int mid = (lo + hi) / 2; if (values[mid] <= value) lo = mid + 1; else hi = mid; }
        return lo;
    }
    internal static V PointAtDistance(Route route, double distance)
    {
        if (distance <= 0) return route.Curves[0].P0;
        if (distance >= route.Length) return route.Curves[^1].P3;
        var span = route.Spans[Math.Min(route.Spans.Length - 1, UpperBound(route.Ends, distance))];
        var curve = route.Curves[span.CurveIndex];
        double target = distance - span.S0, lower = span.T0, upper = span.T1;
        double t = lower + (upper - lower) * target / (span.S1 - span.S0);
        for (int i = 0; i < 7; ++i)
        {
            double error = Length(curve, span.T0, t) - target;
            if (Math.Abs(error) < 1e-5) return curve.Point(t);
            if (error > 0) upper = t; else lower = t;
            double speed = curve.Derivative(t).Norm;
            double next = speed > 1e-10 ? t - error / speed : (lower + upper) / 2;
            t = lower < next && next < upper ? next : (lower + upper) / 2;
        }
        if (Math.Abs(Length(curve, span.T0, t) - target) > .001) throw new Boundary("pointer_arc_inverse_unresolved");
        return curve.Point(t);
    }
    internal sealed record VelocityInterval(double S0, double S1, double V0, double V1, double Duration, double StartTime)
    {
        internal double MaxAcceleration => Q1 * Math.Abs(V1 - V0) / Duration;
        internal double MaxJerk => Q2 * Math.Abs(V1 - V0) / (Duration * Duration);
        internal double Distance(double elapsed)
        {
            if (elapsed <= 0) return S0;
            if (elapsed >= Duration) return S1;
            double u = elapsed / Duration, integral = 2.5 * Math.Pow(u, 4) - 3 * Math.Pow(u, 5) + Math.Pow(u, 6);
            return S0 + Duration * (V0 * u + (V1 - V0) * integral);
        }
    }
    internal sealed record Profile(VelocityInterval[] Intervals, double[] Ends, double Duration)
    {
        internal double Distance(double elapsed)
        {
            if (elapsed <= 0) return 0;
            if (elapsed >= Duration) return Intervals[^1].S1;
            var item = Intervals[Math.Min(Intervals.Length - 1, UpperBound(Ends, elapsed))];
            return item.Distance(elapsed - item.StartTime);
        }
        internal double TimeAtDistance(double distance)
        {
            if (distance <= 0) return 0;
            if (distance >= Intervals[^1].S1) return Duration;
            var item = Intervals.First(x => x.S1 >= distance);
            double lo = 0, hi = item.Duration;
            for (int i = 0; i < 36; ++i)
            { double mid = (lo + hi) / 2; if (item.Distance(mid) < distance) lo = mid; else hi = mid; }
            return item.StartTime + (lo + hi) / 2;
        }
    }
    private static double NextVelocity(double previous, double cap, double distance, Limits limits)
    {
        double value = Math.Min(cap, Math.Sqrt(previous * previous + 2 * limits.TangentialAcceleration * distance / Q1));
        bool Allowed(double candidate)
        {
            double dt = 2 * distance / (previous + candidate);
            return Q2 * Math.Abs(candidate - previous) / (dt * dt) <= limits.TangentialJerk;
        }
        if (value <= previous || Allowed(value)) return value;
        double lo = previous, hi = value;
        for (int i = 0; i < 28; ++i)
        { double mid = (lo + hi) / 2; if (Allowed(mid)) lo = mid; else hi = mid; }
        return lo;
    }
    internal static Profile ProfileGeometry(Route route, Limits? limits = null, int? durationMs = null, Budget? budget = null)
    {
        budget ??= new Budget(); limits ??= new(); limits.Validate();
        var velocity = Enumerable.Repeat(limits.WorkingSpeed, route.Spans.Length + 1).ToArray();
        for (int i = 0; i < route.Spans.Length; ++i)
        {
            budget.Tick();
            var span = route.Spans[i]; double k = span.Curvature, kp = span.CurvatureSlope, cap = limits.WorkingSpeed;
            if (k > 1e-12) cap = Math.Min(cap, Math.Min(Math.Sqrt(limits.NormalAcceleration / k), limits.CrossJerk / (3 * k * limits.TangentialAcceleration)));
            if (kp + k * k > 1e-12) cap = Math.Min(cap, Math.Pow(limits.GeometricJerk / (kp + k * k), 1.0 / 3));
            velocity[i] = Math.Min(velocity[i], cap); velocity[i + 1] = Math.Min(velocity[i + 1], cap);
        }
        velocity[0] = velocity[^1] = 0;
        for (int i = 0; i < route.Spans.Length; ++i) if (route.Sharp.Contains(route.Spans[i].S0)) velocity[i] = 0;
        for (int pass = 0; pass < 3; ++pass)
        {
            for (int i = 0; i < route.Spans.Length; ++i)
            { budget.Tick(28); var s = route.Spans[i]; velocity[i + 1] = Math.Min(velocity[i + 1], NextVelocity(velocity[i], velocity[i + 1], s.S1 - s.S0, limits)); }
            for (int i = route.Spans.Length - 1; i >= 0; --i)
            { budget.Tick(28); var s = route.Spans[i]; velocity[i] = Math.Min(velocity[i], NextVelocity(velocity[i + 1], velocity[i], s.S1 - s.S0, limits)); }
        }
        double scale = 1;
        for (int i = 0; i < route.Spans.Length; ++i)
        {
            budget.Tick();
            var s = route.Spans[i]; double v0 = velocity[i], v1 = velocity[i + 1];
            if (v0 + v1 <= 1e-9) throw new Boundary("pointer_velocity_unresolved");
            double dt = 2 * (s.S1 - s.S0) / (v0 + v1), a = Q1 * Math.Abs(v1 - v0) / dt, j = Q2 * Math.Abs(v1 - v0) / (dt * dt);
            if (a > 0) scale = Math.Min(scale, Math.Sqrt(limits.TangentialAcceleration / a));
            if (j > 0) scale = Math.Min(scale, Math.Pow(limits.TangentialJerk / j, 1.0 / 3));
        }
        velocity = velocity.Select(v => v * scale * .999999).ToArray();
        double duration = route.Spans.Select((s, i) => 2 * (s.S1 - s.S0) / (velocity[i] + velocity[i + 1])).Sum();
        if (durationMs is not null && durationMs is < 1 or > 3000) throw new Boundary("invalid_pointer_duration");
        int naturalMs = Math.Max(1, checked((int)Math.Ceiling(duration * 1000)));
        // Explicit duration is a minimum-time budget. It may slow the motion,
        // but it can never compress the constrained profile below its natural
        // velocity/acceleration/jerk envelope.
        int targetMs = durationMs is { } requested ? Math.Max(requested, naturalMs) : naturalMs;
        double adjustment = duration / (targetMs / 1000.0);
        velocity = velocity.Select(v => v * adjustment).ToArray();
        var intervals = new List<VelocityInterval>(); double elapsed = 0;
        for (int i = 0; i < route.Spans.Length; ++i)
        {
            budget.Tick();
            var s = route.Spans[i]; double dt = 2 * (s.S1 - s.S0) / (velocity[i] + velocity[i + 1]);
            intervals.Add(new(s.S0, s.S1, velocity[i], velocity[i + 1], dt, elapsed)); elapsed += dt;
        }
        budget.Tick(final: true);
        return new(intervals.ToArray(), intervals.Select(x => x.StartTime + x.Duration).ToArray(), elapsed);
    }
    private static double DistanceToSegment(V point, V a, V b)
    {
        V ab = b - a; double denominator = V.Dot(ab, ab);
        return denominator < 1e-20 ? (point - a).Norm : (point - V.Lerp(a, b, Math.Clamp(V.Dot(point - a, ab) / denominator, 0, 1))).Norm;
    }
    internal static Motion Plan(Native.Point first, Native.Point last, DesktopShape? desktop = null,
        Constraints? constraints = null, Limits? limits = null, int? durationMs = null, string pathMode = "free",
        Native.Point[]? waypoints = null, bool forceMotion = false, Action? checkpoint = null)
    {
        V start = V.Of(first), end = V.Of(last);
        if (pathMode is not ("free" or "direct" or "preserve")) throw new Boundary("invalid_pointer_path_mode");
        if (durationMs is not null && durationMs is < 0 or > 3000) throw new Boundary("invalid_pointer_duration");
        constraints ??= Constraints.Empty; constraints.Validate(); limits?.Validate();
        Box? bounds = desktop is null ? null : new(desktop.Left, desktop.Top, desktop.Left + (double)desktop.Width, desktop.Top + (double)desktop.Height);
        if (bounds is { } original && !ValidRect(original)) throw new Boundary("invalid_pointer_bounds");
        if (waypoints is null && (start == end || (end - start).Norm < 16 && !forceMotion
            && durationMs is null or 0 && constraints.Obstacles.Length == 0))
        {
            var f = constraints.Footprint;
            if (bounds is { } r && !(new Box(r.Left - f.Left, r.Top - f.Top, r.Right - 1 - f.Right, r.Bottom - 1 - f.Bottom).Contains(start)
                && new Box(r.Left - f.Left, r.Top - f.Top, r.Right - 1 - f.Right, r.Bottom - 1 - f.Bottom).Contains(end)))
                throw new Boundary("pointer_point_outside_bounds");
            var expanded = constraints.Expanded();
            if (!SegmentClear(start, start, expanded) || !SegmentClear(end, end, expanded)) throw new Boundary("pointer_point_in_obstacle_margin");
            int stationaryDuration=durationMs ?? 0;
            return new(stationaryDuration, [new(last, stationaryDuration)]);
        }
        var budget = new Budget(checkpoint);
        var route = PlanGeometry(start, end, bounds, constraints, pathMode == "free", waypoints?.Select(V.Of).ToArray(), budget);
        if (durationMs == 0)
        {
            var values = route.Obstacles.Length > 0 ? route.Spans.Select(s => PointAtDistance(route, s.S1)).ToArray()
                : waypoints is not null ? route.Required.Skip(1).Select(x => x.Point).ToArray() : [end];
            var immediate = new List<PointerPath.Sample>(); V previous = start;
            foreach (V value in values)
            {
                budget.Tick();
                var pixel = value.Pixel; V point = V.Of(pixel);
                if (point == previous) continue;
                if (!SegmentClear(previous, point, route.Obstacles)) throw new Boundary("pointer_sample_chord_not_clear");
                immediate.Add(new(pixel, 0)); previous = point;
            }
            if (immediate.Count > MaxSamples) throw new Boundary("pointer_sample_limit");
            budget.Tick(final: true);
            return new(0, immediate.ToArray(), route);
        }
        budget.Stage = "profile";
        var profile = ProfileGeometry(route, limits, durationMs, budget);
        budget.Stage = "sampling";
        int duration = checked((int)Math.Round(profile.Duration * 1000));
        if (duration > 3000) throw new Boundary("pointer_motion_exceeds_action_budget");
        var required = new Dictionary<int, Native.Point> { [0] = first, [duration] = last };
        foreach (var item in route.Required.Skip(1).SkipLast(1))
        {
            int offset = checked((int)Math.Round(profile.TimeAtDistance(item.Distance) * 1000)); var pixel = item.Point.Pixel;
            if (required.TryGetValue(offset, out var old) && (old.X != pixel.X || old.Y != pixel.Y)) throw new Boundary("pointer_required_point_time_collision");
            required[offset] = pixel;
        }
        int interval = Math.Max(Math.Max(MinSampleIntervalMs, TargetSampleIntervalMs),
            (int)Math.Ceiling(duration / (double)Math.Max(1, MaxSamples - required.Count - 4)));
        var points = new SortedDictionary<int, Native.Point>(required);
        for (int t = interval; t < duration; t += interval)
        {
            budget.Tick();
            if (!points.ContainsKey(t)) points[t] = PointAtDistance(route, profile.Distance(t / 1000.0)).Pixel;
        }
        var times = points.Keys.ToArray(); var pending = new Stack<(int A, int B)>();
        for (int i = 1; i < times.Length; ++i) pending.Push((times[i - 1], times[i]));
        while (pending.TryPop(out var pair))
        {
            budget.Tick();
            var (a, b) = pair; int mid = (a + b) / 2;
            V floatMid = PointAtDistance(route, profile.Distance((a + b) / 2000.0));
            if (!SegmentClear(V.Of(points[a]), V.Of(points[b]), route.Obstacles)
                || DistanceToSegment(floatMid, V.Of(points[a]), V.Of(points[b])) > .8)
            {
                if (mid == a || mid == b) throw new Boundary("pointer_duration_too_short_for_route");
                if (points.Count >= MaxSamples) throw new Boundary("pointer_sample_limit");
                points[mid] = PointAtDistance(route, profile.Distance(mid / 1000.0)).Pixel;
                pending.Push((a, mid)); pending.Push((mid, b));
            }
        }
        var samples = new List<PointerPath.Sample>(); V prev = start;
        foreach (var (offset, pixel) in points)
        {
            if (offset == 0) continue;
            V point = V.Of(pixel);
            if (point == prev && offset != duration) continue;
            if (point == end && offset != duration && waypoints is null) continue;
            if (!SegmentClear(prev, point, route.Obstacles)) throw new Boundary("pointer_sample_chord_not_clear");
            samples.Add(new(pixel, offset)); prev = point;
        }
        if (samples.Count > MaxSamples) throw new Boundary("pointer_sample_limit");
        budget.Tick(final: true);
        return new(duration, samples.ToArray(), route, profile, true);
    }
}
