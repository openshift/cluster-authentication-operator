package deployment

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// Diagnostic baseline only. The delivery recorder and the lag observer
// describe observations. They never gate a rollout and never fail a sync.

const (
	// lagTargetNamespace matches the namespace the deployment controller reads.
	lagTargetNamespace = "openshift-authentication"
	// lagTrackedResourcePrefix matches the hash input selection in
	// getConfigResourceVersions. Only these resources enter the observation.
	lagTrackedResourcePrefix = "v4-0-config-"
	// lagProbeMinInterval sets the background prober cadence. The operator
	// client is QPS constrained, so probes must stay off the sync path.
	lagProbeMinInterval = 10 * time.Second
)

// informerDeliveryRecord captures when an informer event reached this process.
type informerDeliveryRecord struct {
	event           string
	resourceVersion string
	observedAt      time.Time
}

// informerDeliveryRecorder records the latest informer delivery per resource.
// It is registered on the same shared informers the controller factory uses,
// so it observes exactly what the deployment controller sync will read.
type informerDeliveryRecorder struct {
	mu      sync.Mutex
	records map[string]informerDeliveryRecord
}

func newInformerDeliveryRecorder() *informerDeliveryRecorder {
	return &informerDeliveryRecorder{records: map[string]informerDeliveryRecord{}}
}

// registerConfigMaps adds delivery handlers to the configmap informer.
// Handlers only record metadata. They never change controller behavior.
func (r *informerDeliveryRecorder) registerConfigMaps(informer cache.SharedInformer) {
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { r.record("configmaps", "add", obj) },
		UpdateFunc: func(_, newObj interface{}) { r.record("configmaps", "update", newObj) },
		DeleteFunc: func(obj interface{}) { r.record("configmaps", "delete", obj) },
	})
}

// registerSecrets adds delivery handlers to the secret informer.
func (r *informerDeliveryRecorder) registerSecrets(informer cache.SharedInformer) {
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { r.record("secrets", "add", obj) },
		UpdateFunc: func(_, newObj interface{}) { r.record("secrets", "update", newObj) },
		DeleteFunc: func(obj interface{}) { r.record("secrets", "delete", obj) },
	})
}

// record stores and logs one delivery. The log line is the delivery
// timestamp used to join with API write times from the audit log.
func (r *informerDeliveryRecorder) record(kind, event string, obj interface{}) {
	metaObj, ok := obj.(metav1.Object)
	if !ok {
		if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			metaObj, _ = tombstone.Obj.(metav1.Object)
		}
		if metaObj == nil {
			return
		}
	}
	name := metaObj.GetName()
	key := kind + ":" + name
	now := time.Now()
	r.mu.Lock()
	r.records[key] = informerDeliveryRecord{event: event, resourceVersion: metaObj.GetResourceVersion(), observedAt: now}
	r.mu.Unlock()
	if strings.HasPrefix(name, lagTrackedResourcePrefix) {
		klog.InfoS("Informer delivery observed",
			"resource", key, "event", event,
			"resourceVersion", metaObj.GetResourceVersion())
	}
}

// lookup returns the latest delivery record for a resource key.
func (r *informerDeliveryRecorder) lookup(key string) (informerDeliveryRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, found := r.records[key]
	return record, found
}

// liveResourceGetter reads the current resourceVersion straight from the API
// server, bypassing every cache. It returns the resourceVersion, or an error.
type liveResourceGetter func(ctx context.Context, kind, name string) (string, error)

// liveRVRecord is one background probe result for one resource.
type liveRVRecord struct {
	rv       string
	err      string
	probedAt time.Time
}

// lagEntry is one observed resource in one sync.
type lagEntry struct {
	kind       string
	name       string
	listerRV   string
	event      string
	hasEvent   bool
	observedAt time.Time
	hasLive    bool
	liveRV     string
	probeErr   string
	probedAt   time.Time
}

func (e lagEntry) format(now time.Time) string {
	parts := []string{e.kind + "/" + e.name, "listerRV=" + e.listerRV}
	if !e.hasEvent {
		parts = append(parts, "delivery=none")
	} else {
		parts = append(parts, "lastEvent="+e.event,
			"observedAgo="+now.Sub(e.observedAt).Round(time.Millisecond).String())
	}
	if !e.hasLive {
		parts = append(parts, "liveRV=none")
	} else if e.probeErr != "" {
		parts = append(parts, "liveRV=error:"+e.probeErr,
			"probedAgo="+now.Sub(e.probedAt).Round(time.Millisecond).String())
	} else {
		parts = append(parts, "liveRV="+e.liveRV,
			"probedAgo="+now.Sub(e.probedAt).Round(time.Millisecond).String(),
			"stale="+strconv.FormatBool(e.liveRV != e.listerRV))
	}
	return strings.Join(parts, " ")
}

// listerLagObserver measures how far the informer cache trails the API server
// for the resources that feed the rollout hash.
//
// The sync path never blocks and never calls the API server. A background
// prober refreshes the live resourceVersions on a fixed cadence, and each
// sync reads that snapshot plus the in-memory lister and delivery recorder.
// The prober started timestamp of each snapshot entry is reported as
// probedAgo, so a snapshot that predates a write is visible in the log.
type listerLagObserver struct {
	recorder        *informerDeliveryRecorder
	configMapLister corev1listers.ConfigMapLister
	secretLister    corev1listers.SecretLister
	liveGetter      liveResourceGetter

	proberOnce   sync.Once
	proberMu     sync.Mutex
	liveSnapshot map[string]liveRVRecord
}

func newListerLagObserver(
	recorder *informerDeliveryRecorder,
	configMapLister corev1listers.ConfigMapLister,
	secretLister corev1listers.SecretLister,
	liveGetter liveResourceGetter,
) *listerLagObserver {
	return &listerLagObserver{
		recorder:        recorder,
		configMapLister: configMapLister,
		secretLister:    secretLister,
		liveGetter:      liveGetter,
		liveSnapshot:    map[string]liveRVRecord{},
	}
}

// ensureProberStarted starts the background prober once, tied to the given
// context. The first probe happens on the first tick, not at startup.
func (o *listerLagObserver) ensureProberStarted(ctx context.Context) {
	o.proberOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(lagProbeMinInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					o.probeOnce(ctx)
				}
			}
		}()
	})
}

// probeOnce reads the live resourceVersion of every tracked resource and
// stores the result in the snapshot. It runs only on the prober goroutine.
func (o *listerLagObserver) probeOnce(ctx context.Context) {
	for _, tracked := range o.trackedResources() {
		record := liveRVRecord{probedAt: time.Now()}
		rv, err := o.liveGetter(ctx, tracked.kind, tracked.name)
		if err != nil {
			record.err = err.Error()
		} else {
			record.rv = rv
		}
		o.proberMu.Lock()
		o.liveSnapshot[tracked.kind+":"+tracked.name] = record
		o.proberMu.Unlock()
	}
}

type trackedResource struct {
	kind string
	name string
}

// trackedResources lists the hash input resources from the informer cache.
func (o *listerLagObserver) trackedResources() []trackedResource {
	resources := []trackedResource{}
	configMaps, err := o.configMapLister.ConfigMaps(lagTargetNamespace).List(labels.Everything())
	if err == nil {
		for _, cm := range configMaps {
			if strings.HasPrefix(cm.Name, lagTrackedResourcePrefix) {
				resources = append(resources, trackedResource{kind: "configmaps", name: cm.Name})
			}
		}
	}
	secrets, err := o.secretLister.Secrets(lagTargetNamespace).List(labels.Everything())
	if err == nil {
		for _, secret := range secrets {
			if strings.HasPrefix(secret.Name, lagTrackedResourcePrefix) {
				resources = append(resources, trackedResource{kind: "secrets", name: secret.Name})
			}
		}
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].kind != resources[j].kind {
			return resources[i].kind < resources[j].kind
		}
		return resources[i].name < resources[j].name
	})
	return resources
}

func (o *listerLagObserver) lookupLive(key string) (liveRVRecord, bool) {
	o.proberMu.Lock()
	defer o.proberMu.Unlock()
	record, found := o.liveSnapshot[key]
	return record, found
}

// observe returns one diagnostic entry per tracked resource. A stale entry
// means the lister read by this sync trails the last probed live state.
// This function performs no API calls and never blocks on the network.
func (o *listerLagObserver) observe(ctx context.Context, now time.Time) []string {
	o.ensureProberStarted(ctx)

	entries := []lagEntry{}
	for _, tracked := range o.trackedResources() {
		entry := lagEntry{kind: tracked.kind, name: tracked.name}
		switch tracked.kind {
		case "configmaps":
			if cm, err := o.configMapLister.ConfigMaps(lagTargetNamespace).Get(tracked.name); err == nil {
				entry.listerRV = cm.ResourceVersion
			} else {
				entry.listerRV = "error:" + err.Error()
			}
		case "secrets":
			if secret, err := o.secretLister.Secrets(lagTargetNamespace).Get(tracked.name); err == nil {
				entry.listerRV = secret.ResourceVersion
			} else {
				entry.listerRV = "error:" + err.Error()
			}
		}
		if delivery, found := o.recorder.lookup(tracked.kind + ":" + tracked.name); found {
			entry.event = delivery.event
			entry.hasEvent = true
			entry.observedAt = delivery.observedAt
		}
		if live, found := o.lookupLive(tracked.kind + ":" + tracked.name); found {
			entry.hasLive = true
			entry.liveRV = live.rv
			entry.probeErr = live.err
			entry.probedAt = live.probedAt
		}
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].kind != entries[j].kind {
			return entries[i].kind < entries[j].kind
		}
		return entries[i].name < entries[j].name
	})

	formatted := make([]string, 0, len(entries))
	for _, entry := range entries {
		formatted = append(formatted, entry.format(now))
	}
	return formatted
}
