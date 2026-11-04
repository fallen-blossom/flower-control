"""Deterministic bounded Bezier geometry and distance profiles, without native I/O.

Obstacle hints restrict an already authorized action; they never grant input.
Normal clearance is never relaxed to make a route fit. Limits are working
values, not measured hardware maxima or a claim of foreground acceptance.
"""
from bisect import bisect_right
from dataclasses import dataclass
from functools import cached_property
import heapq
import math

Point = tuple[float, float]
Rect = tuple[float, float, float, float]
MAX_OBSTACLES = 16
MAX_VERTICES = 192
MAX_VISIBILITY_VERTICES = 96
MAX_SPANS = 2048
MAX_SAMPLES = 112
MIN_SAMPLE_INTERVAL_MS = 5
TARGET_SAMPLE_INTERVAL_MS = 12
# Automatic motion aims for the one-second action budget when that remains
# physically feasible. Velocity and acceleration limits are authoritative.
MAX_FREE_BEND_PX = 96.0
NORMAL_BASE_MARGIN = 20
ROUTING_ROOM = 12
CLEARANCE_COMFORT = 24.0
MAX_GAP_CORRIDOR = 240.0
_Q1 = 15 / 8
_Q2 = 10 * math.sqrt(3) / 3


def _point(value):
    if (type(value) not in (tuple, list) or len(value) != 2 or
            any(type(n) is not int or not -(2**31) <= n < 2**31 for n in value)):
        raise ValueError("invalid_pointer_point")
    return tuple(value)


def _rect(value):
    if (type(value) not in (tuple, list) or len(value) != 4 or
            any(type(n) is not int or not -(2**31) <= n < 2**31 for n in value)
            or value[0] >= value[2] or value[1] >= value[3]):
        raise ValueError("invalid_pointer_bounds")
    return tuple(value)


def _sub(a, b): return a[0]-b[0], a[1]-b[1]
def _add(a, b): return a[0]+b[0], a[1]+b[1]
def _mul(a, k): return a[0]*k, a[1]*k
def _norm(a): return math.hypot(*a)
def _dot(a, b): return a[0]*b[0]+a[1]*b[1]
def _cross(a, b): return a[0]*b[1]-a[1]*b[0]
def _lerp(a, b, t): return a[0]+(b[0]-a[0])*t, a[1]+(b[1]-a[1])*t


@dataclass(frozen=True)
class MotionConstraints:
    obstacles: tuple[Rect, ...] = ()
    footprint: Rect = (0, 0, 0, 0)
    uncertainty_px: int = 4

    def __post_init__(self):
        if type(self.obstacles) not in (tuple, list) or len(self.obstacles) > MAX_OBSTACLES:
            raise ValueError("pointer_obstacle_limit")
        object.__setattr__(self, "obstacles", tuple(_rect(r) for r in self.obstacles))
        body = self.footprint
        if (type(body) not in (tuple,list) or len(body)!=4
                or any(type(n) is not int or abs(n)>10000 for n in body)
                or not body[0] <= 0 <= body[2] or not body[1] <= 0 <= body[3]):
            raise ValueError("invalid_pointer_footprint")
        object.__setattr__(self, "footprint", tuple(body))
        if type(self.uncertainty_px) is not int or not 0 <= self.uncertainty_px <= 256:
            raise ValueError("invalid_pointer_uncertainty")

    @property
    def margin(self):
        # 8px base + 1px quantization + 3px execution + 8px comfort,
        # plus at least 4px localization allowance. Public hints may add room.
        return NORMAL_BASE_MARGIN + max(4, self.uncertainty_px)

    def expanded(self):
        l,t,r,b = self.footprint
        m = self.margin
        return tuple((x-r-m,y-b-m,z-l+m,w-t+m) for x,y,z,w in self.obstacles)


@dataclass(frozen=True)
class MotionLimits:
    # Automatic motion aims to finish within one second; physical limits win.
    # Explicit duration_ms is a minimum smoothness budget for precision work.
    speed: float = 3000
    acceleration: float = 300000
    jerk: float = 100000000
    utilization: float = .8

    def __post_init__(self):
        if any(type(x) not in (int,float) or not math.isfinite(x) or x<=0
               for x in (self.speed,self.acceleration,self.jerk,self.utilization)):
            raise ValueError("invalid_pointer_limits")
        if self.utilization > .8:
            raise ValueError("pointer_working_margin_required")

    @property
    def working_speed(self): return self.speed*self.utilization
    @property
    def tangential_acceleration(self): return self.acceleration*self.utilization*.45
    @property
    def normal_acceleration(self): return self.acceleration*self.utilization*.45
    @property
    def tangential_jerk(self): return self.jerk*self.utilization*.28
    @property
    def geometric_jerk(self): return self.jerk*self.utilization*.28
    @property
    def cross_jerk(self): return self.jerk*self.utilization*.28


class _Budget:
    def __init__(self, checkpoint=None):
        self.work = 0
        self.next_check = 128
        self.checkpoint = checkpoint

    def tick(self, units=1, *, final=False):
        self.work += units
        if final or self.work >= self.next_check:
            self.next_check = self.work + 128
            if self.checkpoint is not None:
                self.checkpoint()


@dataclass(frozen=True)
class Cubic:
    p0: Point
    p1: Point
    p2: Point
    p3: Point

    @property
    def controls(self): return self.p0,self.p1,self.p2,self.p3

    @cached_property
    def derivatives(self):
        # Immutable curve data; reuse exactly the same arithmetic for every
        # quadrature/inverse query instead of allocating it at each sample.
        first=tuple(_mul(_sub(b,a),3) for a,b in zip(self.controls,self.controls[1:]))
        second=tuple(_mul(_sub(b,a),2) for a,b in zip(first,first[1:]))
        return first,second,(_sub(second[1],second[0]),)

    @cached_property
    def is_line(self):
        return self.p1==_lerp(self.p0,self.p3,1/3) and self.p2==_lerp(self.p0,self.p3,2/3)

    def point(self,t):
        a,b,c = (_lerp(self.p0,self.p1,t),_lerp(self.p1,self.p2,t),_lerp(self.p2,self.p3,t))
        return _lerp(_lerp(a,b,t),_lerp(b,c,t),t)

    def derivative(self,t):
        p0,p1,p2 = self.derivatives[0]
        # Keep the de Casteljau operation order while avoiding two temporary
        # vectors and three Python calls at every quadrature/inverse sample.
        ax=p0[0]+(p1[0]-p0[0])*t; ay=p0[1]+(p1[1]-p0[1])*t
        bx=p1[0]+(p2[0]-p1[0])*t; by=p1[1]+(p2[1]-p1[1])*t
        return ax+(bx-ax)*t, ay+(by-ay)*t

    def split(self,t=.5):
        a,b,c = (_lerp(self.p0,self.p1,t),_lerp(self.p1,self.p2,t),_lerp(self.p2,self.p3,t))
        d,e = _lerp(a,b,t),_lerp(b,c,t)
        f = _lerp(d,e,t)
        return Cubic(self.p0,a,d,f),Cubic(f,e,c,self.p3)


def _line(a,b):
    return Cubic(a,_lerp(a,b,1/3),_lerp(a,b,2/3),b)


def _inside(point,bounds):
    return bounds is None or bounds[0]<=point[0]<=bounds[2] and bounds[1]<=point[1]<=bounds[3]


def segment_clear(a,b,obstacles):
    """Closed rectangle intersection, independently checked for every chord."""
    dx,dy = _sub(b,a)
    for l,t,r,bot in obstacles:
        lo,hi = 0.0,1.0
        for origin,d,low,high in ((a[0],dx,l,r),(a[1],dy,t,bot)):
            if abs(d)<1e-15:
                if origin<low or origin>high:
                    lo,hi = 1,0
                    break
            else:
                enter,leave = (low-origin)/d,(high-origin)/d
                if enter>leave:enter,leave=leave,enter
                lo,hi=max(lo,enter),min(hi,leave)
        if lo<=hi:return False
    return True


def _rect_distance(point, rect):
    l,t,r,b=rect
    dx=max(l-point[0],0.0,point[0]-r)
    dy=max(t-point[1],0.0,point[1]-b)
    return math.hypot(dx,dy)


def _segment_clearance(a,b,obstacles):
    if not obstacles:return float("inf")
    # This value is only a routing preference; exact safety is still enforced
    # by SegmentClear and CurveClear. A coarse cost sample avoids spending the
    # unnecessary repeated work on dense obstacle fields.
    return min(_rect_distance(_lerp(a,b,index/4),rect)
               for index in range(5) for rect in obstacles)


def _edge_cost(a,b,obstacles):
    length=math.dist(a,b)
    clearance=_segment_clearance(a,b,obstacles)
    deficit=max(0.0,CLEARANCE_COMFORT-clearance)
    # Shortest visibility edges tend to skim obstacle corners. Charge for low
    # corridor clearance, while keeping length dominant for ordinary routes.
    return length+1.8*deficit*deficit/CLEARANCE_COMFORT+3/(clearance+1)


def _gap_candidates(obstacles):
    """Add centre points for narrow horizontal and vertical corridors."""
    points=[]
    for index,(al,at,ar,ab) in enumerate(obstacles):
        for bl,bt,br,bb in obstacles[index+1:]:
            first=(ar,bl) if ar<=bl else (br,al)
            if 0 < first[1]-first[0] <= MAX_GAP_CORRIDOR:
                top,bottom=max(at,bt),min(ab,bb)
                if top<bottom:
                    x=(first[0]+first[1])/2
                    for fraction in (.25,.5,.75):
                        points.append((x,top+(bottom-top)*fraction))
            first=(ab,bt) if ab<=bt else (bb,at)
            if 0 < first[1]-first[0] <= MAX_GAP_CORRIDOR:
                left_overlap,right_overlap=max(al,bl),min(ar,br)
                if left_overlap<right_overlap:
                    y=(first[0]+first[1])/2
                    for fraction in (.25,.5,.75):
                        points.append((left_overlap+(right_overlap-left_overlap)*fraction,y))
    return points


def _hull(points):
    points=sorted(set(points))
    if len(points)<3:return points
    def half(items):
        out=[]
        for p in items:
            while len(out)>=2 and _cross(_sub(out[-1],out[-2]),_sub(p,out[-1]))<=0:out.pop()
            out.append(p)
        return out
    return half(points)[:-1]+half(points[::-1])[:-1]


def _hull_disjoint(hull,rect):
    l,t,r,b=rect
    box=((l,t),(r,t),(r,b),(l,b))
    axes=[(1,0),(0,1)]
    if len(hull)>1:
        axes.extend((-(q[1]-p[1]),q[0]-p[0]) for p,q in zip(hull,hull[1:]+hull[:1]))
    for axis in axes:
        if axis==(0,0):continue
        h=[_dot(p,axis) for p in hull];v=[_dot(p,axis) for p in box]
        if max(h)<min(v)-1e-9 or max(v)<min(h)-1e-9:return True
    return False


def _curve_clear(curve,obstacles,bounds,budget,depth=0):
    budget.tick()
    if not all(_inside(p,bounds) for p in curve.controls):return False
    remaining=tuple(r for r in obstacles if not _hull_disjoint(_hull(curve.controls),r))
    if not remaining:return True
    if depth>=12:return False
    a,b=curve.split()
    return (_curve_clear(a,remaining,bounds,budget,depth+1)
            and _curve_clear(b,remaining,bounds,budget,depth+1))


def _visible_route(start,end,obstacles,bounds,budget):
    # Route against a slightly larger envelope so smoothing and integer
    # sampling cannot shave the requested normal margin back to a graze.
    routing=tuple((l-8,t-8,r+8,b+8) for l,t,r,b in obstacles)
    if segment_clear(start,end,routing):return (start,end)
    support=tuple((l-ROUTING_ROOM,t-ROUTING_ROOM,r+ROUTING_ROOM,b+ROUTING_ROOM)
                  for l,t,r,b in routing)
    candidates=[]
    for l,t,r,b in support:candidates.extend(((l,t),(r,t),(r,b),(l,b)))
    # Union-boundary intersections matter when expanded obstacles overlap.
    for i,(l,t,r,b) in enumerate(support):
        for ll,tt,rr,bb in support[i+1:]:
            for x in (l,r):
                for y in (tt,bb):
                    if ll<=x<=rr and t<=y<=b:candidates.append((x,y))
            for x in (ll,rr):
                for y in (t,b):
                    if l<=x<=r and tt<=y<=bb:candidates.append((x,y))
    candidates=list(set(candidates))
    candidate_limit=min(MAX_VERTICES-2,MAX_VISIBILITY_VERTICES-2)
    gap_candidates=sorted(set(_gap_candidates(routing))-set(candidates))
    candidates.extend(gap_candidates[:max(0,candidate_limit-len(candidates))])
    candidates=sorted(set(p for p in candidates if _inside(p,bounds)
        and segment_clear(p,p,routing) and p not in (start,end)))
    if len(candidates)>candidate_limit:raise ValueError("pointer_vertex_limit")
    nodes=(start,end,*candidates)
    # Slightly weighted A* trades an unobservable few pixels of route optimality
    # for predictable sub-100ms planning in a full obstacle field.
    heuristic_weight=1.5
    best={0:0.0};previous={};queue=[(heuristic_weight*math.dist(start,end),0.0,0)];visited=set();visibility={}
    while queue:
        _priority,cost,index=heapq.heappop(queue)
        if index in visited:continue
        visited.add(index)
        if index==1:
            path=[end]
            while index:
                index=previous[index];path.append(nodes[index])
            return tuple(reversed(path))
        for nxt,point in enumerate(nodes):
            if nxt==index or nxt in visited:continue
            key=tuple(sorted((index,nxt)))
            if key not in visibility:
                budget.tick(len(obstacles))
                visibility[key]=segment_clear(nodes[index],point,routing)
            if not visibility[key]:continue
            value=cost+_edge_cost(nodes[index],point,routing)
            if value<best.get(nxt,float("inf")):
                best[nxt]=value;previous[nxt]=index
                # Length and every clearance term are non-negative, so the
                # straight-line remainder is an admissible A* bound. This
                # avoids exhausting dense multi-obstacle graphs within 100ms.
                priority=value+heuristic_weight*math.dist(point,end)
                heapq.heappush(queue,(priority,value,nxt))
    raise ValueError("pointer_no_route_with_normal_margin")


def _round_route(points,obstacles,bounds,budget):
    curves=[];current=points[0]
    for before,corner,after in zip(points,points[1:],points[2:]):
        incoming,outgoing=_sub(corner,before),_sub(after,corner)
        n1,n2=_norm(incoming),_norm(outgoing)
        if n1<1e-9 or n2<1e-9:raise ValueError("pointer_degenerate_route")
        e1,e2=_mul(incoming,1/n1),_mul(outgoing,1/n2)
        if abs(_cross(e1,e2))<1e-10 and _dot(e1,e2)>0:continue
        trim=min(n1,n2)*.24
        rounded=None
        for _ in range(12):
            p,q=_sub(corner,_mul(e1,trim)),_add(corner,_mul(e2,trim))
            candidate=Cubic(p,corner,corner,q)
            if (_curve_clear(_line(current,p),obstacles,bounds,budget)
                    and _curve_clear(candidate,obstacles,bounds,budget)):
                rounded=candidate;break
            trim*=.5  # Changes corner shape; obstacle clearance never changes.
        if rounded is None:raise ValueError("pointer_no_round_route_with_normal_margin")
        if math.dist(current,rounded.p0)>1e-8:curves.append(_line(current,rounded.p0))
        curves.append(rounded);current=rounded.p3
    if math.dist(current,points[-1])>1e-8:curves.append(_line(current,points[-1]))
    if not all(_curve_clear(c,obstacles,bounds,budget) for c in curves):
        raise ValueError("pointer_route_not_certified")
    return tuple(curves)


def _smooth_waypoints(points,obstacles,bounds,budget):
    """Interpolate all waypoints with tangent-continuous cubic segments.

    The tangent handle at each interior point is limited by the shorter of its
    adjacent chords. Consequently both neighbouring cubic segments use the same
    derivative at the shared point (C1), while every supplied waypoint remains
    an exact endpoint. If a candidate bulges into an obstacle, the handles are
    shortened before the route is rejected; clearance is never relaxed.
    """
    if len(points)<3:return (_line(points[0],points[-1]),)
    tangents=[]
    for index,point in enumerate(points):
        if index==0:direction=_sub(points[1],point)
        elif index==len(points)-1:direction=_sub(point,points[index-1])
        else:
            incoming=_sub(point,points[index-1]);outgoing=_sub(points[index+1],point)
            ni,no=_norm(incoming),_norm(outgoing)
            if ni<1e-9 or no<1e-9:raise ValueError("pointer_degenerate_route")
            direction=_add(_mul(incoming,1/ni),_mul(outgoing,1/no))
            if _norm(direction)<1e-9:direction=outgoing
        length=_norm(direction)
        if length<1e-9:raise ValueError("pointer_degenerate_route")
        tangents.append(_mul(direction,1/length))
    spans=[math.dist(a,b) for a,b in zip(points,points[1:])]
    radii=[]
    for index in range(len(points)):
        if index==0:neighbour=spans[0]
        elif index==len(points)-1:neighbour=spans[-1]
        else:neighbour=min(spans[index-1],spans[index])
        radii.append(neighbour)
    for tension in (1/3,1/4,1/6,1/10,1/20,1/50):
        curves=[]
        for index in range(len(points)-1):
            p0,p3=points[index],points[index+1]
            p1=_add(p0,_mul(tangents[index],radii[index]*tension))
            p2=_sub(p3,_mul(tangents[index+1],radii[index+1]*tension))
            curves.append(Cubic(p0,p1,p2,p3))
        if all(_curve_clear(curve,obstacles,bounds,budget) for curve in curves):
            return tuple(curves)
    raise ValueError("pointer_smoothed_path_not_certified")


_GAUSS_X=(0.0,-.5384693101056831,.5384693101056831,-.906179845938664,.906179845938664)
_GAUSS_W=(.5688888888888889,.4786286704993665,.4786286704993665,.2369268850561891,.2369268850561891)


def _length(curve,t0,t1):
    mid=(t0+t1)/2;half=(t1-t0)/2
    return half*sum(w*_norm(curve.derivative(mid+half*x)) for x,w in zip(_GAUSS_X,_GAUSS_W))


def _split_controls(points,t):
    rows=[tuple(points)]
    while len(rows[-1])>1:rows.append(tuple(_lerp(a,b,t) for a,b in zip(rows[-1],rows[-1][1:])))
    return tuple(row[0] for row in rows),tuple(row[-1] for row in reversed(rows))


def _restrict(points,lo,hi):
    if hi<1:points=_split_controls(points,hi)[0]
    if lo>0:points=_split_controls(points,lo/hi)[1]
    return points


def _product_bound(a,b,product):
    m,n=len(a)-1,len(b)-1
    return max(abs(sum(math.comb(m,i)*math.comb(n,k-i)/math.comb(m+n,k)*product(a[i],b[k-i])
        for i in range(max(0,k-n),min(m,k)+1))) for k in range(m+n+1))


def _curvature_bounds(curve,lo,hi):
    if curve.is_line:return 0.0,0.0
    d1,d2,d3=curve.derivatives
    a,b,c=_restrict(d1,lo,hi),_restrict(d2,lo,hi),d3
    middle=curve.derivative((lo+hi)/2);speed=_norm(middle)
    if speed<1e-10:raise ValueError("pointer_degenerate_derivative")
    direction=_mul(middle,1/speed)
    lower=min(_dot(p,direction) for p in a)
    if lower<=1e-9:raise ValueError("pointer_derivative_bound_unresolved")
    cross12=_product_bound(a,b,_cross)
    if cross12<1e-9 and max(_norm(x) for x in c)<1e-8:return 0.0,0.0
    cross13=_product_bound(a,c,_cross);dot12=_product_bound(a,b,_dot)
    return cross12/lower**3,cross13/lower**4+3*cross12*dot12/lower**6


@dataclass(frozen=True)
class ArcSpan:
    curve_index: int
    t0: float
    t1: float
    s0: float
    s1: float
    curvature: float
    curvature_slope: float


@dataclass(frozen=True)
class GeometryRoute:
    curves: tuple[Cubic,...]
    obstacles: tuple[Rect,...]
    bounds: Rect|None
    spans: tuple[ArcSpan,...]
    ends: tuple[float,...]
    length: float
    required: tuple[tuple[float,Point],...]
    sharp: tuple[float,...]


def _route(curves,obstacles,bounds,required_points,budget):
    spans=[];total=0.0;required=[(0.0,curves[0].p0)];sharp=[]
    for index,curve in enumerate(curves):
        if index:
            a,b=curves[index-1].derivative(1),curve.derivative(0)
            if _dot(a,b)<=0 or abs(_cross(a,b))>1e-8*_norm(a)*_norm(b):sharp.append(total)
            if curve.p0 in required_points:required.append((total,curve.p0))
        def visit(piece,t0,t1,tolerance,depth):
            nonlocal total
            budget.tick()
            if len(spans)>=MAX_SPANS:raise ValueError("pointer_arc_table_limit")
            polygon=sum(math.dist(a,b) for a,b in zip(piece.controls,piece.controls[1:]))
            chord=math.dist(piece.p0,piece.p3)
            try:curvature,slope=_curvature_bounds(curve,t0,t1)
            except ValueError:
                if depth>=14:raise
                curvature=slope=None
            if depth>=14 and (polygon-chord>tolerance or curvature is None):
                raise ValueError("pointer_arc_precision_unresolved")
            if (t1-t0>.5 or polygon>24 or polygon-chord>tolerance or curvature is None):
                a,b=piece.split();mid=(t0+t1)/2
                visit(a,t0,mid,tolerance/2,depth+1);visit(b,mid,t1,tolerance/2,depth+1)
            else:
                length=_length(curve,t0,t1)
                if length<=1e-10:raise ValueError("pointer_zero_arc_span")
                spans.append(ArcSpan(index,t0,t1,total,total+length,curvature,slope));total+=length
        visit(curve,0.0,1.0,.025,0)
    required.append((total,curves[-1].p3))
    return GeometryRoute(curves,obstacles,bounds,tuple(spans),tuple(s.s1 for s in spans),
                         total,tuple(required),tuple(sharp))


def plan_geometry(start,end,bounds=None,*,constraints=None,curved=True,waypoints=None,_budget=None):
    start,end=_point(start),_point(end)
    if type(curved) is not bool:raise ValueError("invalid_pointer_path_mode")
    constraints=MotionConstraints() if constraints is None else constraints
    if type(constraints) is not MotionConstraints:raise ValueError("invalid_pointer_constraints")
    area=None
    if bounds is not None:
        l,t,r,b=_rect(bounds)
        fl,ft,fr,fb=constraints.footprint
        area=(l-fl,t-ft,r-1-fr,b-1-fb)
        if not all(_inside(p,area) for p in (start,end)):raise ValueError("pointer_point_outside_bounds")
    obstacles=constraints.expanded()
    if any(not segment_clear(p,p,obstacles) for p in (start,end)):
        raise ValueError("pointer_point_in_obstacle_margin")
    if start==end and waypoints is None:
        raise ValueError("pointer_zero_route")
    budget=_Budget() if _budget is None else _budget
    required=()
    if waypoints is not None:
        if type(waypoints) not in (tuple,list) or not 2<=len(waypoints)<=64:
            raise ValueError("invalid_pointer_waypoints")
        points=tuple(_point(p) for p in waypoints)
        if points[0]!=start or points[-1]!=end or any(a==b for a,b in zip(points,points[1:])):
            raise ValueError("invalid_pointer_waypoints")
        if not all(_inside(p,area) for p in points):raise ValueError("pointer_point_outside_bounds")
        if not all(segment_clear(a,b,obstacles) for a,b in zip(points,points[1:])):
            raise ValueError("pointer_path_intersects_obstacle_margin")
        curves=(_smooth_waypoints(points,obstacles,area,budget) if curved else
                tuple(_line(a,b) for a,b in zip(points,points[1:])))
        required=points
    elif segment_clear(start,end,obstacles):
        curves=None
        if curved:
            dx,dy=_sub(end,start);distance=math.hypot(dx,dy)
            normal=(-dy/distance,dx/distance)
            for factor in (1,-1,.5,-.5,.25,-.25):
                bend=min(distance*.12,MAX_FREE_BEND_PX)*factor
                candidate=Cubic(start,_add(_lerp(start,end,1/3),_mul(normal,bend)),
                    _add(_lerp(start,end,2/3),_mul(normal,bend)),end)
                if _curve_clear(candidate,obstacles,area,budget):
                    curves=(candidate,);break
        if curves is None:curves=(_line(start,end),)
    else:
        points=_visible_route(start,end,obstacles,area,budget)
        curves=_round_route(points,obstacles,area,budget)
    route=_route(curves,obstacles,area,required,budget)
    budget.tick(final=True)
    return route


def point_at_distance(route,distance):
    if distance<=0:return route.curves[0].p0
    if distance>=route.length:return route.curves[-1].p3
    span=route.spans[min(len(route.spans)-1,bisect_right(route.ends,distance))]
    curve=route.curves[span.curve_index]
    target=distance-span.s0
    lower,upper=span.t0,span.t1
    t=lower+(upper-lower)*target/(span.s1-span.s0)
    for _ in range(7):
        error=_length(curve,span.t0,t)-target
        if abs(error)<1e-5:return curve.point(t)
        if error>0:upper=t
        else:lower=t
        speed=_norm(curve.derivative(t))
        nxt=t-error/speed if speed>1e-10 else (lower+upper)/2
        t=nxt if lower<nxt<upper else (lower+upper)/2
    if abs(_length(curve,span.t0,t)-target)>.001:raise ValueError("pointer_arc_inverse_unresolved")
    return curve.point(t)


@dataclass(frozen=True)
class VelocityInterval:
    s0: float
    s1: float
    v0: float
    v1: float
    duration: float
    start_time: float

    @property
    def max_acceleration(self):return _Q1*abs(self.v1-self.v0)/self.duration
    @property
    def max_jerk(self):return _Q2*abs(self.v1-self.v0)/self.duration**2

    def distance(self,elapsed):
        if elapsed<=0:return self.s0
        if elapsed>=self.duration:return self.s1
        u=elapsed/self.duration
        integral=2.5*u**4-3*u**5+u**6
        return self.s0+self.duration*(self.v0*u+(self.v1-self.v0)*integral)


@dataclass(frozen=True)
class DistanceProfile:
    intervals: tuple[VelocityInterval,...]
    ends: tuple[float,...]
    duration: float

    def distance(self,elapsed):
        if elapsed<=0:return 0.0
        if elapsed>=self.duration:return self.intervals[-1].s1
        item=self.intervals[min(len(self.intervals)-1,bisect_right(self.ends,elapsed))]
        return item.distance(elapsed-item.start_time)

    def time_at_distance(self,distance):
        if distance<=0:return 0.0
        if distance>=self.intervals[-1].s1:return self.duration
        item=next(x for x in self.intervals if x.s1>=distance)
        lo,hi=0.0,item.duration
        for _ in range(36):
            mid=(lo+hi)/2
            if item.distance(mid)<distance:lo=mid
            else:hi=mid
        return item.start_time+(lo+hi)/2


def _next_velocity(previous,cap,distance,limits):
    value=min(cap,math.sqrt(previous**2+2*limits.tangential_acceleration*distance/_Q1))
    def allowed(candidate):
        dt=2*distance/(previous+candidate)
        return _Q2*abs(candidate-previous)/dt**2<=limits.tangential_jerk
    if value<=previous or allowed(value):return value
    lo,hi=previous,value
    for _ in range(28):
        mid=(lo+hi)/2
        if allowed(mid):lo=mid
        else:hi=mid
    return lo


def profile_geometry(route,limits=None,duration_ms=None,*,_budget=None):
    budget=_Budget() if _budget is None else _budget
    limits=MotionLimits() if limits is None else limits
    if type(limits) is not MotionLimits:raise ValueError("invalid_pointer_limits")
    caps=[limits.working_speed]*(len(route.spans)+1)
    for i,span in enumerate(route.spans):
        budget.tick()
        k,kp=span.curvature,span.curvature_slope
        cap=limits.working_speed
        if k>1e-12:
            cap=min(cap,math.sqrt(limits.normal_acceleration/k),
                limits.cross_jerk/(3*k*limits.tangential_acceleration))
        if kp+k*k>1e-12:cap=min(cap,(limits.geometric_jerk/(kp+k*k))**(1/3))
        caps[i]=min(caps[i],cap);caps[i+1]=min(caps[i+1],cap)
    caps[0]=caps[-1]=0.0
    sharp=set(route.sharp)
    for i,span in enumerate(route.spans):
        if span.s0 in sharp:caps[i]=0.0
    velocity=caps[:]
    for _ in range(3):
        for i,span in enumerate(route.spans):
            budget.tick(28)
            velocity[i+1]=min(velocity[i+1],_next_velocity(velocity[i],velocity[i+1],span.s1-span.s0,limits))
        for i in range(len(route.spans)-1,-1,-1):
            budget.tick(28)
            span=route.spans[i]
            velocity[i]=min(velocity[i],_next_velocity(velocity[i+1],velocity[i],span.s1-span.s0,limits))
    scale=1.0
    for i,span in enumerate(route.spans):
        budget.tick()
        v0,v1=velocity[i:i+2];ds=span.s1-span.s0
        if v0+v1<=1e-9:raise ValueError("pointer_velocity_unresolved")
        dt=2*ds/(v0+v1)
        a=_Q1*abs(v1-v0)/dt;j=_Q2*abs(v1-v0)/dt**2
        if a:scale=min(scale,math.sqrt(limits.tangential_acceleration/a))
        if j:scale=min(scale,(limits.tangential_jerk/j)**(1/3))
    velocity=[v*scale*.999999 for v in velocity]
    duration=sum(2*(s.s1-s.s0)/(velocity[i]+velocity[i+1]) for i,s in enumerate(route.spans))
    natural_duration=duration
    natural_duration_ms=max(1,math.ceil(natural_duration*1000))
    if duration_ms is not None:
        if type(duration_ms) is not int or not 1<=duration_ms<=3000:raise ValueError("invalid_pointer_duration")
        # Explicit duration is a minimum-time budget. It may slow the motion,
        # but it can never compress the constrained profile below the natural
        # velocity/acceleration/jerk envelope.
        target_ms=max(duration_ms,natural_duration_ms)
    else:
        target_ms=natural_duration_ms
    adjustment=duration/(target_ms/1000)
    velocity=[v*adjustment for v in velocity]
    intervals=[];elapsed=0.0
    for i,span in enumerate(route.spans):
        budget.tick()
        v0,v1=velocity[i:i+2];dt=2*(span.s1-span.s0)/(v0+v1)
        intervals.append(VelocityInterval(span.s0,span.s1,v0,v1,dt,elapsed));elapsed+=dt
    budget.tick(final=True)
    return DistanceProfile(tuple(intervals),tuple(x.start_time+x.duration for x in intervals),elapsed)


@dataclass(frozen=True)
class PointerSample:
    point: tuple[int,int]
    offset_ms: int


@dataclass(frozen=True)
class PointerMotion:
    duration_ms: int
    samples: tuple[PointerSample,...]
    route: GeometryRoute|None = None
    profile: DistanceProfile|None = None
    automatic: bool = False

    def point_at_ms(self,elapsed_ms):
        if self.route is None or self.profile is None:return self.samples[-1].point
        p=point_at_distance(self.route,self.profile.distance(elapsed_ms/1000))
        return round(p[0]),round(p[1])


def _distance_to_segment(p,a,b):
    ab=_sub(b,a);denominator=_dot(ab,ab)
    if denominator<1e-20:return math.dist(p,a)
    return math.dist(p,_lerp(a,b,max(0,min(1,_dot(_sub(p,a),ab)/denominator))))


def plan_motion(start,end,bounds=None,*,constraints=None,limits=None,duration_ms=None,
                path_mode="free",waypoints=None,force_motion=False,checkpoint=None):
    start,end=_point(start),_point(end)
    if path_mode not in ("free","direct","preserve"):raise ValueError("invalid_pointer_path_mode")
    if duration_ms is not None and (type(duration_ms) is not int or not 0<=duration_ms<=3000):
        raise ValueError("invalid_pointer_duration")
    if constraints is not None and type(constraints) is not MotionConstraints:
        raise ValueError("invalid_pointer_constraints")
    if limits is not None and type(limits) is not MotionLimits:
        raise ValueError("invalid_pointer_limits")
    if type(force_motion) is not bool:
        raise ValueError("invalid_pointer_force_motion")
    if (waypoints is None and (start==end or math.dist(start,end)<16 and not force_motion
            and duration_ms in (None,0) and not (constraints and constraints.obstacles))):
        if bounds is not None:
            l,t,r,b=_rect(bounds)
            fl,ft,fr,fb=constraints.footprint if constraints else (0,0,0,0)
            if any(not(l-fl<=p[0]<r-fr and t-ft<=p[1]<b-fb) for p in (start,end)):
                raise ValueError("pointer_point_outside_bounds")
        if constraints and any(not segment_clear(p,p,constraints.expanded()) for p in (start,end)):
            raise ValueError("pointer_point_in_obstacle_margin")
        duration=duration_ms or 0
        return PointerMotion(duration,(PointerSample(end,duration),))
    budget=_Budget(checkpoint)
    route=plan_geometry(start,end,bounds,constraints=constraints,curved=path_mode=="free",waypoints=waypoints,_budget=budget)
    if duration_ms==0:
        points=[point_at_distance(route,span.s1) for span in route.spans] if route.obstacles else (
            [point for _,point in route.required[1:]] if waypoints is not None else [end])
        samples=[];previous=start
        for point in points:
            budget.tick()
            p=round(point[0]),round(point[1])
            if p!=previous:
                if not segment_clear(previous,p,route.obstacles):raise ValueError("pointer_sample_chord_not_clear")
                samples.append(PointerSample(p,0));previous=p
        if len(samples)>MAX_SAMPLES:raise ValueError("pointer_sample_limit")
        budget.tick(final=True)
        return PointerMotion(0,tuple(samples),route)
    profile=profile_geometry(route,limits,duration_ms,_budget=budget)
    duration=round(profile.duration*1000)
    if duration>3000:raise ValueError("pointer_motion_exceeds_action_budget")
    required={0:start,duration:end}
    for distance,point in route.required[1:-1]:
        offset=round(profile.time_at_distance(distance)*1000)
        p=round(point[0]),round(point[1])
        if offset in required and required[offset]!=p:raise ValueError("pointer_required_point_time_collision")
        required[offset]=p
    interval=max(MIN_SAMPLE_INTERVAL_MS,TARGET_SAMPLE_INTERVAL_MS,
        math.ceil(duration/max(1,MAX_SAMPLES-len(required)-4)))
    times=sorted(set(range(interval,duration,interval))|set(required))
    points={}
    for t in times:
        budget.tick()
        points[t]=required.get(t) or tuple(round(n) for n in point_at_distance(route,profile.distance(t/1000)))
    pending=list(zip(times,times[1:]))
    while pending:
        budget.tick()
        a,b=pending.pop()
        mid=(a+b)//2
        float_mid=point_at_distance(route,profile.distance(((a+b)/2)/1000))
        if (not segment_clear(points[a],points[b],route.obstacles)
                or _distance_to_segment(float_mid,points[a],points[b])>.8):
            if mid in (a,b):raise ValueError("pointer_duration_too_short_for_route")
            if len(points)>=MAX_SAMPLES:raise ValueError("pointer_sample_limit")
            points[mid]=tuple(round(n) for n in point_at_distance(route,profile.distance(mid/1000)))
            pending.extend(((a,mid),(mid,b)))
    samples=[];previous=start
    for offset in sorted(points):
        if offset==0:continue
        point=points[offset]
        if point==previous and offset!=duration:continue
        if point==end and offset!=duration and waypoints is None:continue
        if not segment_clear(previous,point,route.obstacles):raise ValueError("pointer_sample_chord_not_clear")
        samples.append(PointerSample(point,offset));previous=point
    if len(samples)>MAX_SAMPLES:raise ValueError("pointer_sample_limit")
    budget.tick(final=True)
    return PointerMotion(duration,tuple(samples),route,profile,True)
