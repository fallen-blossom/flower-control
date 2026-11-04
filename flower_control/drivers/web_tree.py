"""Bounded DOM depth/shadow/same-origin-frame collection; no old ref cache."""
from flower_control.control.state import ControlError


def validate_tree_depth(value):
    if value is not None and (type(value) is not int or not 1 <= value <= 256):
        raise ControlError('invalid_observation_max_depth')


_PARENT = """node => {
  if (node.parentElement) return node.parentElement;
  const tree=node.getRootNode();
  if (tree.host) return tree.host.shadowRoot===tree ? tree.host : null;
  const doc=node.ownerDocument;
  if(!doc || doc.defaultView?.document!==doc)return null;
  const frame=doc.defaultView.frameElement;
  if(frame && frame.contentDocument!==doc)return null;
  return frame || doc;
}"""

_WALK = """(root,a) => {
  if (!root.isConnected) throw Error('observation_root_detached');
  const rootDoc=root.ownerDocument||root;
  if(rootDoc.defaultView?.document!==rootDoc)throw Error('observation_changed');
  const pending=[],found=[],seen=new Set();
  let depthTruncated=false,crossOriginFrames=0,work=0;
  const children=(node,depth)=>{
    // Store collection cursors, never expand an unbounded sibling frontier.
    const groups=[node.children||[]];
    if(node.shadowRoot)groups.push(node.shadowRoot.children);
    if(node.tagName==='IFRAME') {
      let child=null;
      try {child=node.contentDocument;} catch {}
      if(child) {
        if(child.defaultView?.document!==child || child.defaultView.frameElement!==node)
          throw Error('observation_changed');
        groups.push(child.children);
      } else crossOriginFrames++;
    }
    if(depth>=a.max_depth){if(groups.some(g=>g.length))depthTruncated=true;return;}
    for(let i=groups.length-1;i>=0;i--)if(groups[i].length)
      pending.push({nodes:groups[i],index:0,depth:depth+1});
  };
  children(root,0);
  while(pending.length) {
    const cursor=pending[pending.length-1];
    if(cursor.index>=cursor.nodes.length){pending.pop();continue;}
    if(++work>50000)throw Error('observation_tree_budget');
    const node=cursor.nodes[cursor.index++],depth=cursor.depth;
    if(seen.has(node))continue;
    seen.add(node);
    const legacy=a.legacy_affordances && (node.matches('summary,[tabindex],[onclick],[data-clickable="true"],[data-action]') ||
      (node.ownerDocument.defaultView.getComputedStyle(node).cursor==='pointer' &&
       !!(node.getAttribute('aria-label')||node.getAttribute('title')||(node.textContent||'').trim())));
    if(node.matches(a.selector)||legacy)found.push(node);
    children(node,depth);
  }
  return {root,total:found.length,nodes:found.slice(a.offset,a.offset+a.limit),
    depth_truncated:depthTruncated,cross_origin_frames_skipped:crossOriginFrames};
}"""
ROOT_TREE_NODES = _WALK
FRAME_TREE_NODES = '(a) => { const walk=__WALK__; return walk(document,a); }'.replace('__WALK__',_WALK)


def descriptor_script(describe):
    return """(node,a) => {
      const parent=__PARENT__;
      const rootDoc=a.root.ownerDocument||a.root;
      if(rootDoc.defaultView?.document!==rootDoc)return null;
      let current=node,depth=0;
      while(current && current!==a.root && depth<=a.max_depth) {
        const doc=current.ownerDocument || current;
        if(doc.defaultView?.document!==doc)return null;
        const frame=doc.defaultView.frameElement;
        if(frame && frame.contentDocument!==doc)return null;
        current=parent(current);depth++;
      }
      if(current!==a.root || !depth || depth>a.max_depth || !node.isConnected || !a.root.isConnected)return null;
      const describe=__DESCRIBE__;
      return {descriptor:describe(node),depth};
    }""".replace('__PARENT__',_PARENT).replace('__DESCRIBE__',describe)


async def tree_handles(frame,root,selector,offset,limit,max_depth):
    """Transfer one anchor and bounded elements; every auxiliary handle closes."""
    auxiliary=[];owned=[];anchor=None;success=False
    try:
        args=dict(selector=selector,offset=offset,limit=limit,max_depth=max_depth,
            legacy_affordances=selector=='button,input,textarea,select,a,video,audio,[role],[contenteditable]')
        result=(await frame.evaluate_handle(FRAME_TREE_NODES,args) if root is None
                else await root.evaluate_handle(ROOT_TREE_NODES,args))
        auxiliary.append(result)
        facts=await result.evaluate('r=>({total:r.total,depth_truncated:r.depth_truncated,cross_origin_frames_skipped:r.cross_origin_frames_skipped})')
        if (type(facts) is not dict or type(facts.get('total')) is not int or facts['total']<0
                or type(facts.get('depth_truncated')) is not bool
                or type(facts.get('cross_origin_frames_skipped')) is not int or facts['cross_origin_frames_skipped']<0):
            raise ControlError('observation_changed')
        anchor=await result.get_property('root')
        nodes=await result.get_property('nodes');auxiliary.append(nodes)
        properties=await nodes.get_properties();owned.extend(properties.values())
        count=max(0,min(offset+limit,facts['total'])-offset)
        if set(properties)!={str(i) for i in range(count)}:raise ControlError('observation_changed')
        elements=tuple(properties[str(i)].as_element() for i in range(count))
        if any(element is None for element in elements):raise ControlError('observation_changed')
        while auxiliary:
            await auxiliary[-1].dispose();auxiliary.pop()
        success=True
        return facts,elements,anchor
    finally:
        if not success:
            for handle in (*owned,*(() if anchor is None else (anchor,))):
                try:await handle.dispose()
                except Exception:pass
        for handle in reversed(auxiliary):
            try:await handle.dispose()
            except Exception:pass
