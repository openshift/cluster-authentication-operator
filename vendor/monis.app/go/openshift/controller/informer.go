package controller

// TODO decide how to best express changes of behavior for WithInformer

type InformerOption func() informerOptionCase // public so it can be referenced out of this package

type informerOptionCase int // private so the set of cases is sealed

// all cases are private
const (
	syncDefault informerOptionCase = iota
	noSync
)

// public opt-out of sync
func WithNoSync() InformerOption {
	return func() informerOptionCase {
		return noSync
	}
}

// private default
// will need to be exposed when more options are added
func withSync() InformerOption {
	return func() informerOptionCase {
		return syncDefault
	}
}

func informerOptionToOption(opt InformerOption, getter InformerGetter) Option {
	switch opt() {
	case syncDefault:
		return WithInformerSynced(getter) // safe default
	case noSync:
		return func(*controller) {} // do nothing
	default:
		panic(opt)
	}
}
