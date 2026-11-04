"""Pure pointer plans; callers retain authority, freshness and input ownership."""
from .pointer_geometry import PointerSample, PointerMotion, plan_motion


def plan_pointer_motion(start, end, bounds=None, **options):
    """Include the exact endpoint; an approach dispatches only samples[:-1]."""
    return plan_motion(start,end,bounds,**options)


def pointer_points(start,end,bounds=None):
    """Compatibility view for callers that need five interior diagnostic points."""
    motion=plan_pointer_motion(start,end,bounds)
    if not motion.duration_ms:
        return ()
    points=[]
    for index in range(1,6):
        point=motion.point_at_ms(motion.duration_ms*index/6)
        if point not in (tuple(start),tuple(end)) and (not points or point!=points[-1]):
            points.append(point)
    return tuple(points)
