package fuse

import (
	"context"
	"path/filepath"
	"syscall"
	"time"

	gofs "github.com/hanwen/go-fuse/v2/fs"
	gofuse "github.com/hanwen/go-fuse/v2/fuse"
)

// Hooks bundles the configuration injected into every intercepted
// filesystem operation.
type Hooks struct {
	// Resolver maps PIDs to caller info. Required.
	Resolver Resolver
	// Rules is the decision engine. Required.
	Rules *Ruleset
	// Sink receives FsEvents. Required.
	Sink EventSink
	// ObserveOnly forces every deny decision to be logged but not
	// enforced. The sandboxed process always gets through.
	ObserveOnly bool
}

// hookedNode embeds gofs.LoopbackNode and intercepts a subset of
// operations to emit events and optionally deny access.
type hookedNode struct {
	gofs.LoopbackNode
	hooks *Hooks
}

// backingPath returns the absolute path to this node on the underlying
// real filesystem. It concatenates the loopback root's backing path with
// the node's path relative to the FUSE mount.
func (n *hookedNode) backingPath(name string) string {
	rel := n.Inode.Path(nil)
	if name != "" {
		rel = filepath.Join(rel, name)
	}
	return filepath.Join(n.RootData.Path, rel)
}

// decide resolves the caller, consults rules, emits an event, and
// returns whether the operation should proceed.
//
// When the action is deny and ObserveOnly is false, decide returns
// (syscall.EACCES, true) meaning "do not forward, return EACCES".
// Otherwise it returns (0, false) meaning "forward to the embedded
// loopback node".
func (n *hookedNode) decide(ctx context.Context, op Op, path string) (syscall.Errno, bool) {
	var pid uint32
	caller, ok := gofuse.FromContext(ctx)
	if ok {
		pid = caller.Pid
	}

	info := CallerInfo{PID: pid, Exe: "unknown"}
	if n.hooks.Resolver != nil {
		info = n.hooks.Resolver.Resolve(pid)
	}

	action := ActionAllow
	ruleName := ""
	if n.hooks.Rules != nil {
		action, ruleName = n.hooks.Rules.Match(info.Exe, path, op)
	}

	effective := action
	if action == ActionDeny && n.hooks.ObserveOnly {
		effective = ActionLog
	}

	if n.hooks.Sink != nil {
		n.hooks.Sink.Emit(FsEvent{
			Timestamp: time.Now(),
			Op:        op,
			Path:      path,
			Caller:    info.Exe,
			PID:       info.PID,
			PPID:      info.PPID,
			Comm:      info.Comm,
			Action:    effective,
			Rule:      ruleName,
		})
	}

	if action == ActionDeny && !n.hooks.ObserveOnly {
		return syscall.EACCES, true
	}
	return 0, false
}

// --- intercepted operations ---
//
// Each override: compute backing path, call decide, short-circuit with
// EACCES if denied, otherwise forward to the embedded LoopbackNode.

var _ = (gofs.NodeLookuper)((*hookedNode)(nil))

func (n *hookedNode) Lookup(ctx context.Context, name string, out *gofuse.EntryOut) (*gofs.Inode, syscall.Errno) {
	errno, deny := n.decide(ctx, OpLookup, n.backingPath(name))
	if deny {
		return nil, errno
	}
	return n.LoopbackNode.Lookup(ctx, name, out)
}

var _ = (gofs.NodeOpener)((*hookedNode)(nil))

func (n *hookedNode) Open(ctx context.Context, flags uint32) (fh gofs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	op := OpOpen
	// Crude classification: O_WRONLY or O_RDWR implies write intent.
	if int(flags)&(syscall.O_WRONLY|syscall.O_RDWR) != 0 {
		op = OpWrite
	} else {
		op = OpRead
	}
	e, deny := n.decide(ctx, op, n.backingPath(""))
	if deny {
		return nil, 0, e
	}
	return n.LoopbackNode.Open(ctx, flags)
}

var _ = (gofs.NodeCreater)((*hookedNode)(nil))

func (n *hookedNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *gofuse.EntryOut) (*gofs.Inode, gofs.FileHandle, uint32, syscall.Errno) {
	e, deny := n.decide(ctx, OpCreate, n.backingPath(name))
	if deny {
		return nil, nil, 0, e
	}
	return n.LoopbackNode.Create(ctx, name, flags, mode, out)
}

var _ = (gofs.NodeUnlinker)((*hookedNode)(nil))

func (n *hookedNode) Unlink(ctx context.Context, name string) syscall.Errno {
	e, deny := n.decide(ctx, OpUnlink, n.backingPath(name))
	if deny {
		return e
	}
	return n.LoopbackNode.Unlink(ctx, name)
}

var _ = (gofs.NodeRmdirer)((*hookedNode)(nil))

func (n *hookedNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	e, deny := n.decide(ctx, OpRmdir, n.backingPath(name))
	if deny {
		return e
	}
	return n.LoopbackNode.Rmdir(ctx, name)
}

var _ = (gofs.NodeMkdirer)((*hookedNode)(nil))

func (n *hookedNode) Mkdir(ctx context.Context, name string, mode uint32, out *gofuse.EntryOut) (*gofs.Inode, syscall.Errno) {
	e, deny := n.decide(ctx, OpMkdir, n.backingPath(name))
	if deny {
		return nil, e
	}
	return n.LoopbackNode.Mkdir(ctx, name, mode, out)
}

var _ = (gofs.NodeRenamer)((*hookedNode)(nil))

func (n *hookedNode) Rename(ctx context.Context, name string, newParent gofs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	e, deny := n.decide(ctx, OpRename, n.backingPath(name))
	if deny {
		return e
	}
	return n.LoopbackNode.Rename(ctx, name, newParent, newName, flags)
}

var _ = (gofs.NodeGetattrer)((*hookedNode)(nil))

func (n *hookedNode) Getattr(ctx context.Context, f gofs.FileHandle, out *gofuse.AttrOut) syscall.Errno {
	e, deny := n.decide(ctx, OpGetattr, n.backingPath(""))
	if deny {
		return e
	}
	return n.LoopbackNode.Getattr(ctx, f, out)
}

// newHookedRoot builds a LoopbackRoot whose NewNode callback produces
// hookedNode instances so every child in the tree is intercepted.
func newHookedRoot(backing string, hooks *Hooks) (*gofs.LoopbackRoot, gofs.InodeEmbedder, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(backing, &st); err != nil {
		return nil, nil, err
	}
	root := &gofs.LoopbackRoot{
		Path: backing,
		Dev:  uint64(st.Dev),
	}
	root.NewNode = func(rd *gofs.LoopbackRoot, _ *gofs.Inode, _ string, _ *syscall.Stat_t) gofs.InodeEmbedder {
		return &hookedNode{
			LoopbackNode: gofs.LoopbackNode{RootData: rd},
			hooks:        hooks,
		}
	}
	rootNode := root.NewNode(root, nil, "", &st)
	root.RootNode = rootNode
	return root, rootNode, nil
}
