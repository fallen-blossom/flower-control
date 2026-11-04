"""Explicit returned-image points mapped through a trusted presentation view.

Default physical coordinates remain unchanged. View metadata is produced by
the local PNG presentation path, never supplied as input authority by a model.
"""
from dataclasses import dataclass
import math

from .computer_legacy_actions import canonical_batch


IMAGE_SPACES = ('returned_image', 'normalized_1000_image', 'returned_image_pixels')


@dataclass(frozen=True)
class ReturnedImageView:
    original_size: tuple
    box: tuple
    size: tuple

    def __post_init__(self):
        if (any(type(row) is not tuple for row in (self.original_size, self.box, self.size))
                or len(self.original_size) != 2 or len(self.box) != 4 or len(self.size) != 2
                or any(type(n) is not int for row in (self.original_size, self.box, self.size) for n in row)):
            raise ValueError('invalid_returned_image_view')
        width, height = self.original_size
        left, top, right, bottom = self.box
        if (not 1 <= width <= 3840 or not 1 <= height <= 3840
                or not 0 <= left < right <= width or not 0 <= top < bottom <= height
                or not 1 <= self.size[0] <= right-left or not 1 <= self.size[1] <= bottom-top):
            raise ValueError('invalid_returned_image_view')


def map_returned_points(command, arguments, observed, *, _nested=False):
    """Convert a local copy; original request stays bound to origin/action ID."""
    if type(arguments) is not dict:
        return arguments
    if command == 'sequence':
        if (_nested or set(arguments) != {'steps'} or type(arguments['steps']) is not list
                or not 2 <= len(arguments['steps']) <= 8):
            raise ValueError('invalid_input_sequence')
        steps = []
        for row in arguments['steps']:
            if (type(row) is not dict or set(row) != {'command', 'arguments', 'expect'}
                    or type(row['command']) is not str or row['command'] == 'sequence'
                    or row['expect'] not in ('capture_available', 'image_changed', 'image_unchanged')):
                raise ValueError('invalid_input_sequence')
            steps.append(dict(row, arguments=map_returned_points(row['command'], row['arguments'], observed)))
        return dict(arguments, steps=steps)
    if command == 'batch':
        arguments = canonical_batch(arguments)
        if (_nested or set(arguments) != {'steps'} or type(arguments['steps']) is not list
                or not 1 <= len(arguments['steps']) <= 32):
            raise ValueError('invalid_input_batch')
        steps = []
        for row in arguments['steps']:
            if (type(row) is not dict or set(row) != {'command', 'arguments'}
                    or type(row['command']) is not str):
                raise ValueError('invalid_input_batch')
            steps.append(dict(command=row['command'], arguments=map_returned_points(
                row['command'], row['arguments'], observed, _nested=True)))
        return dict(steps=steps)
    space = arguments.get('coordinate_space')
    if space not in IMAGE_SPACES:
        return arguments
    point_command = command in {'move', 'hover', 'click', 'double_click', 'scroll', 'mouse_hold', 'drag'}
    if not point_command and not (command == 'key_mouse' and 'button' in arguments):
        raise ValueError('invalid_input_coordinate_space')
    view = observed.get('returned_image_view')
    if type(view) is not ReturnedImageView:
        raise ValueError('returned_image_view_unavailable')
    bounds = observed['source_bounds']
    if (bounds.width, bounds.height) != view.original_size:
        raise ValueError('returned_image_view_changed')
    origin = observed['geometry'].client_origin
    def point(x, y):
        if space == 'returned_image_pixels':
            # The old Frame.point contract allowed finite subpixel coordinates
            # up to the last pixel center. Keep that opt-in spelling separate
            # from the newer integer-only image and normalized spaces.
            if any(type(n) not in (int, float) for n in (x, y)):
                raise ValueError('invalid_returned_image_point')
            if any(not 0 <= n <= extent - 1 for n, extent in zip((x, y), view.size)):
                raise ValueError('returned_image_point_outside_view')
            if any(type(n) is float and not math.isfinite(n) for n in (x, y)):
                raise ValueError('invalid_returned_image_point')
        elif type(x) is not int or type(y) is not int:
            raise ValueError('invalid_returned_image_point')
        if space == 'normalized_1000_image':
            if not 0 <= x < 1000 or not 0 <= y < 1000:
                raise ValueError('returned_image_point_outside_view')
            x, y = x*view.size[0]//1000, y*view.size[1]//1000
        if not 0 <= x < view.size[0] or not 0 <= y < view.size[1]:
            raise ValueError('returned_image_point_outside_view')
        def offset(value, length, extent):
            # Exact integer arithmetic on every existing path. The legacy
            # subpixel path uses the old positive-coordinate truncation.
            return (int(value * length / extent) if type(value) is float
                    else value * length // extent)
        return (bounds.left + view.box[0] + offset(x, view.box[2]-view.box[0], view.size[0]) - origin[0],
                bounds.top + view.box[1] + offset(y, view.box[3]-view.box[1], view.size[1]) - origin[1])
    result = dict(arguments, coordinate_space='client')
    if 'avoid_rects' in result:
        rectangles=result['avoid_rects']
        if type(rectangles) is not list or len(rectangles)>16:
            raise ValueError('pointer_obstacle_limit')
        mapped=[]
        extents=(1000,1000) if space=='normalized_1000_image' else view.size
        for rect in rectangles:
            if type(rect) not in (tuple,list) or len(rect)!=4:
                raise ValueError('invalid_pointer_obstacle')
            allowed=(int,float) if space=='returned_image_pixels' else (int,)
            if any(type(n) not in allowed or not math.isfinite(n) for n in rect):
                raise ValueError('invalid_pointer_obstacle')
            l,t,r,b=rect
            if not 0<=l<r<=extents[0] or not 0<=t<b<=extents[1]:
                raise ValueError('pointer_obstacle_outside_observation')
            crop_width,crop_height=view.box[2]-view.box[0],view.box[3]-view.box[1]
            base_x,base_y=bounds.left+view.box[0]-origin[0],bounds.top+view.box[1]-origin[1]
            mapped.append([base_x+math.floor(l*crop_width/extents[0]),base_y+math.floor(t*crop_height/extents[1]),
                base_x+math.ceil(r*crop_width/extents[0]),base_y+math.ceil(b*crop_height/extents[1])])
        result['avoid_rects']=mapped
        # Bound image quantization conservatively. This is not a confidence
        # estimate for the model's localization; uncertain geometry needs a new
        # closer observation or an explicitly larger allowance.
        hinted=result.get('uncertainty_px',4)
        if type(hinted) is not int or not 0<=hinted<=256:
            raise ValueError('invalid_pointer_uncertainty')
        quantization=math.ceil(max((view.box[2]-view.box[0])/extents[0],
                                  (view.box[3]-view.box[1])/extents[1]))
        if quantization>256:
            raise ValueError('pointer_observation_uncertainty_too_large')
        result['uncertainty_px']=max(hinted,quantization)
    if command == 'drag':
        if 'path' in result:
            path = result['path']
            if (type(path) is not list or not 2 <= len(path) <= 64
                    or any(type(row) not in (list, tuple) or len(row) != 2 for row in path)):
                raise ValueError('invalid_input_arguments')
            result['path'] = [list(point(*row)) for row in path]
        else:
            result['from_x'], result['from_y'] = point(result.get('from_x'), result.get('from_y'))
            result['to_x'], result['to_y'] = point(result.get('to_x'), result.get('to_y'))
    else:
        result['x'], result['y'] = point(result.get('x'), result.get('y'))
    return result
