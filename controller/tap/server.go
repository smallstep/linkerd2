package tap

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	httpPb "github.com/linkerd/linkerd2-proxy-api/go/http_types"
	netPb "github.com/linkerd/linkerd2-proxy-api/go/net"
	proxy "github.com/linkerd/linkerd2-proxy-api/go/tap"
	apiUtil "github.com/linkerd/linkerd2/controller/api/util"
	pb "github.com/linkerd/linkerd2/controller/gen/controller/tap"
	public "github.com/linkerd/linkerd2/controller/gen/public"
	"github.com/linkerd/linkerd2/controller/k8s"
	"github.com/linkerd/linkerd2/pkg/addr"
	pkgK8s "github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/prometheus"
	"github.com/linkerd/linkerd2/pkg/util"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

const podIPIndex = "ip"
const defaultMaxRps = 100.0

type (
	server struct {
		tapPort             uint
		k8sAPI              *k8s.API
		controllerNamespace string
	}
)

var (
	tapInterval = 1 * time.Second
)

func (s *server) Tap(req *public.TapRequest, stream pb.Tap_TapServer) error {
	return status.Error(codes.Unimplemented, "Tap is deprecated, use TapByResource")
}

func (s *server) TapByResource(req *public.TapByResourceRequest, stream pb.Tap_TapByResourceServer) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "TapByResource received nil TapByResourceRequest")
	}
	if req.Target == nil {
		return status.Error(codes.InvalidArgument, "TapByResource received nil target ResourceSelection")
	}
	if req.MaxRps == 0.0 {
		req.MaxRps = defaultMaxRps
	}

	objects, err := s.k8sAPI.GetObjects(req.Target.Resource.Namespace, req.Target.Resource.Type, req.Target.Resource.Name)
	if err != nil {
		return apiUtil.GRPCError(err)
	}

	pods := []*apiv1.Pod{}
	for _, object := range objects {
		podsFor, err := s.k8sAPI.GetPodsFor(object, false)
		if err != nil {
			return apiUtil.GRPCError(err)
		}

		for _, pod := range podsFor {
			if pkgK8s.IsMeshed(pod, s.controllerNamespace) {
				pods = append(pods, pod)
			}
		}
	}

	if len(pods) == 0 {
		return status.Errorf(codes.NotFound, "no pods found for %s/%s",
			req.GetTarget().GetResource().GetType(), req.GetTarget().GetResource().GetName())
	}

	log.Infof("Tapping %d pods for target: %+v", len(pods), *req.Target.Resource)

	events := make(chan *public.TapEvent)

	// divide the rps evenly between all pods to tap
	rpsPerPod := req.MaxRps / float32(len(pods))
	if rpsPerPod < 1 {
		rpsPerPod = 1
	}

	match, err := makeByResourceMatch(req.Match)
	if err != nil {
		return apiUtil.GRPCError(err)
	}

	for _, pod := range pods {
		// initiate a tap on the pod
		go s.tapProxy(stream.Context(), rpsPerPod, match, pod.Status.PodIP, events)
	}

	// read events from the taps and send them back
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case event := <-events:
			err := stream.Send(event)
			if err != nil {
				return apiUtil.GRPCError(err)
			}
		}
	}
}

func makeByResourceMatch(match *public.TapByResourceRequest_Match) (*proxy.ObserveRequest_Match, error) {
	// TODO: for now assume it's always a single, flat `All` match list
	seq := match.GetAll()
	if seq == nil {
		return nil, status.Errorf(codes.Unimplemented, "unexpected match specified: %+v", match)
	}

	matches := []*proxy.ObserveRequest_Match{}

	for _, reqMatch := range seq.Matches {
		switch typed := reqMatch.Match.(type) {
		case *public.TapByResourceRequest_Match_Destinations:

			for k, v := range destinationLabels(typed.Destinations.Resource) {
				matches = append(matches, &proxy.ObserveRequest_Match{
					Match: &proxy.ObserveRequest_Match_DestinationLabel{
						DestinationLabel: &proxy.ObserveRequest_Match_Label{
							Key:   k,
							Value: v,
						},
					},
				})
			}

		case *public.TapByResourceRequest_Match_Http_:

			httpMatch := proxy.ObserveRequest_Match_Http{}

			switch httpTyped := typed.Http.Match.(type) {
			case *public.TapByResourceRequest_Match_Http_Scheme:
				httpMatch = proxy.ObserveRequest_Match_Http{
					Match: &proxy.ObserveRequest_Match_Http_Scheme{
						Scheme: util.ParseScheme(httpTyped.Scheme),
					},
				}
			case *public.TapByResourceRequest_Match_Http_Method:
				httpMatch = proxy.ObserveRequest_Match_Http{
					Match: &proxy.ObserveRequest_Match_Http_Method{
						Method: util.ParseMethod(httpTyped.Method),
					},
				}
			case *public.TapByResourceRequest_Match_Http_Authority:
				httpMatch = proxy.ObserveRequest_Match_Http{
					Match: &proxy.ObserveRequest_Match_Http_Authority{
						Authority: &proxy.ObserveRequest_Match_Http_StringMatch{
							Match: &proxy.ObserveRequest_Match_Http_StringMatch_Exact{
								Exact: httpTyped.Authority,
							},
						},
					},
				}
			case *public.TapByResourceRequest_Match_Http_Path:
				httpMatch = proxy.ObserveRequest_Match_Http{
					Match: &proxy.ObserveRequest_Match_Http_Path{
						Path: &proxy.ObserveRequest_Match_Http_StringMatch{
							Match: &proxy.ObserveRequest_Match_Http_StringMatch_Prefix{
								Prefix: httpTyped.Path,
							},
						},
					},
				}
			default:
				return nil, status.Errorf(codes.Unimplemented, "unknown HTTP match type: %v", httpTyped)
			}

			matches = append(matches, &proxy.ObserveRequest_Match{
				Match: &proxy.ObserveRequest_Match_Http_{
					Http: &httpMatch,
				},
			})

		default:
			return nil, status.Errorf(codes.Unimplemented, "unknown match type: %v", typed)
		}
	}

	return &proxy.ObserveRequest_Match{
		Match: &proxy.ObserveRequest_Match_All{
			All: &proxy.ObserveRequest_Match_Seq{
				Matches: matches,
			},
		},
	}, nil
}

// TODO: factor out with `promLabels` in public-api
func destinationLabels(resource *public.Resource) map[string]string {
	dstLabels := map[string]string{}
	if resource.Name != "" {
		dstLabels[resource.Type] = resource.Name
	}
	if resource.Type != pkgK8s.Namespace && resource.Namespace != "" {
		dstLabels["namespace"] = resource.Namespace
	}
	return dstLabels
}

// Tap a pod.
// This method will run continuously until an error is encountered or the
// request is cancelled via the context.  Thus it should be called as a
// go-routine.
// To limit the rps to maxRps, this method calls Observe on the pod with a limit
// of maxRps * 1s at most once per 1s window.  If this limit is reached in
// less than 1s, we sleep until the end of the window before calling Observe
// again.
func (s *server) tapProxy(ctx context.Context, maxRps float32, match *proxy.ObserveRequest_Match, addr string, events chan *public.TapEvent) {
	tapAddr := fmt.Sprintf("%s:%d", addr, s.tapPort)
	log.Infof("Establishing tap on %s", tapAddr)
	conn, err := grpc.DialContext(ctx, tapAddr, grpc.WithInsecure())
	if err != nil {
		log.Error(err)
		return
	}
	client := proxy.NewTapClient(conn)
	defer conn.Close()

	req := &proxy.ObserveRequest{
		Limit: uint32(maxRps * float32(tapInterval.Seconds())),
		Match: match,
	}

	for { // Request loop
		windowStart := time.Now()
		windowEnd := windowStart.Add(tapInterval)
		rsp, err := client.Observe(ctx, req)
		if err != nil {
			log.Error(err)
			return
		}
		for { // Stream loop
			event, err := rsp.Recv()
			if err == io.EOF {
				log.Debugf("[%s] proxy terminated the stream", addr)
				break
			}
			if err != nil {
				log.Errorf("[%s] encountered an error: %s", addr, err)
				return
			}

			translatedEvent := s.translateEvent(event)

			select {
			case <-ctx.Done():
				log.Debugf("[%s] client terminated the stream", addr)
				return
			default:
				events <- translatedEvent
			}
		}
		if time.Now().Before(windowEnd) {
			time.Sleep(time.Until(windowEnd))
		}
	}
}

func (s *server) translateEvent(orig *proxy.TapEvent) *public.TapEvent {
	direction := func(orig proxy.TapEvent_ProxyDirection) public.TapEvent_ProxyDirection {
		switch orig {
		case proxy.TapEvent_INBOUND:
			return public.TapEvent_INBOUND
		case proxy.TapEvent_OUTBOUND:
			return public.TapEvent_OUTBOUND
		default:
			return public.TapEvent_UNKNOWN
		}
	}

	tcp := func(orig *netPb.TcpAddress) *public.TcpAddress {
		ip := func(orig *netPb.IPAddress) *public.IPAddress {
			switch i := orig.GetIp().(type) {
			case *netPb.IPAddress_Ipv6:
				return &public.IPAddress{
					Ip: &public.IPAddress_Ipv6{
						Ipv6: &public.IPv6{
							First: i.Ipv6.First,
							Last:  i.Ipv6.Last,
						},
					},
				}
			case *netPb.IPAddress_Ipv4:
				return &public.IPAddress{
					Ip: &public.IPAddress_Ipv4{
						Ipv4: i.Ipv4,
					},
				}
			default:
				return nil
			}
		}

		return &public.TcpAddress{
			Ip:   ip(orig.GetIp()),
			Port: orig.GetPort(),
		}
	}

	event := func(orig *proxy.TapEvent_Http) *public.TapEvent_Http_ {
		id := func(orig *proxy.TapEvent_Http_StreamId) *public.TapEvent_Http_StreamId {
			return &public.TapEvent_Http_StreamId{
				Base:   orig.GetBase(),
				Stream: orig.GetStream(),
			}
		}

		method := func(orig *httpPb.HttpMethod) *public.HttpMethod {
			switch m := orig.GetType().(type) {
			case *httpPb.HttpMethod_Registered_:
				return &public.HttpMethod{
					Type: &public.HttpMethod_Registered_{
						Registered: public.HttpMethod_Registered(m.Registered),
					},
				}
			case *httpPb.HttpMethod_Unregistered:
				return &public.HttpMethod{
					Type: &public.HttpMethod_Unregistered{
						Unregistered: m.Unregistered,
					},
				}
			default:
				return nil
			}
		}

		scheme := func(orig *httpPb.Scheme) *public.Scheme {
			switch s := orig.GetType().(type) {
			case *httpPb.Scheme_Registered_:
				return &public.Scheme{
					Type: &public.Scheme_Registered_{
						Registered: public.Scheme_Registered(s.Registered),
					},
				}
			case *httpPb.Scheme_Unregistered:
				return &public.Scheme{
					Type: &public.Scheme_Unregistered{
						Unregistered: s.Unregistered,
					},
				}
			default:
				return nil
			}
		}

		switch orig := orig.GetEvent().(type) {
		case *proxy.TapEvent_Http_RequestInit_:
			return &public.TapEvent_Http_{
				Http: &public.TapEvent_Http{
					Event: &public.TapEvent_Http_RequestInit_{
						RequestInit: &public.TapEvent_Http_RequestInit{
							Id:        id(orig.RequestInit.GetId()),
							Method:    method(orig.RequestInit.GetMethod()),
							Scheme:    scheme(orig.RequestInit.GetScheme()),
							Authority: orig.RequestInit.Authority,
							Path:      orig.RequestInit.Path,
						},
					},
				},
			}

		case *proxy.TapEvent_Http_ResponseInit_:
			return &public.TapEvent_Http_{
				Http: &public.TapEvent_Http{
					Event: &public.TapEvent_Http_ResponseInit_{
						ResponseInit: &public.TapEvent_Http_ResponseInit{
							Id:               id(orig.ResponseInit.GetId()),
							SinceRequestInit: orig.ResponseInit.GetSinceRequestInit(),
							HttpStatus:       orig.ResponseInit.GetHttpStatus(),
						},
					},
				},
			}

		case *proxy.TapEvent_Http_ResponseEnd_:
			eos := func(orig *proxy.Eos) *public.Eos {
				switch e := orig.GetEnd().(type) {
				case *proxy.Eos_ResetErrorCode:
					return &public.Eos{
						End: &public.Eos_ResetErrorCode{
							ResetErrorCode: e.ResetErrorCode,
						},
					}
				case *proxy.Eos_GrpcStatusCode:
					return &public.Eos{
						End: &public.Eos_GrpcStatusCode{
							GrpcStatusCode: e.GrpcStatusCode,
						},
					}
				default:
					return nil
				}
			}

			return &public.TapEvent_Http_{
				Http: &public.TapEvent_Http{
					Event: &public.TapEvent_Http_ResponseEnd_{
						ResponseEnd: &public.TapEvent_Http_ResponseEnd{
							Id:                id(orig.ResponseEnd.GetId()),
							SinceRequestInit:  orig.ResponseEnd.GetSinceRequestInit(),
							SinceResponseInit: orig.ResponseEnd.GetSinceResponseInit(),
							ResponseBytes:     orig.ResponseEnd.GetResponseBytes(),
							Eos:               eos(orig.ResponseEnd.GetEos()),
						},
					},
				},
			}

		default:
			return nil
		}
	}

	sourceLabels := orig.GetSourceMeta().GetLabels()
	if sourceLabels == nil {
		sourceLabels = make(map[string]string)
	}
	destinationLabels := orig.GetDestinationMeta().GetLabels()
	if destinationLabels == nil {
		destinationLabels = make(map[string]string)
	}

	ev := &public.TapEvent{
		Source: tcp(orig.GetSource()),
		SourceMeta: &public.TapEvent_EndpointMeta{
			Labels: sourceLabels,
		},
		Destination: tcp(orig.GetDestination()),
		DestinationMeta: &public.TapEvent_EndpointMeta{
			Labels: destinationLabels,
		},
		ProxyDirection: direction(orig.GetProxyDirection()),
		Event:          event(orig.GetHttp()),
	}

	s.hydrateEventLabels(ev)

	return ev
}

// NewServer creates a new gRPC Tap server
func NewServer(
	addr string,
	tapPort uint,
	controllerNamespace string,
	k8sAPI *k8s.API,
) (*grpc.Server, net.Listener, error) {
	k8sAPI.Pod().Informer().AddIndexers(cache.Indexers{podIPIndex: indexPodByIP})

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}

	s := prometheus.NewGrpcServer()
	srv := server{
		tapPort:             tapPort,
		k8sAPI:              k8sAPI,
		controllerNamespace: controllerNamespace,
	}
	pb.RegisterTapServer(s, &srv)

	return s, lis, nil
}

func indexPodByIP(obj interface{}) ([]string, error) {
	if pod, ok := obj.(*apiv1.Pod); ok {
		return []string{pod.Status.PodIP}, nil
	}
	return []string{""}, fmt.Errorf("object is not a pod")
}

// hydrateEventLabels attempts to hydrate the metadata labels for an event's
// source and (if the event was reported by an inbound proxy) destination,
// and adds them to the event's `SourceMeta` and `DestinationMeta` fields.
//
// Since errors encountered while hydrating metadata are non-fatal and result
// only in missing labels, any errors are logged at the WARN level.
func (s *server) hydrateEventLabels(ev *public.TapEvent) {
	err := s.hydrateIPLabels(ev.GetSource().GetIp(), ev.GetSourceMeta().GetLabels())
	if err != nil {
		log.Warnf("error hydrating source labels: %s", err)
	}

	if ev.ProxyDirection == public.TapEvent_INBOUND {
		// Events emitted by an inbound proxies don't have destination labels,
		// since the inbound proxy _is_ the destination, and proxies don't know
		// their own labels.
		err = s.hydrateIPLabels(ev.GetDestination().GetIp(), ev.GetDestinationMeta().GetLabels())
		if err != nil {
			log.Warnf("error hydrating destination labels: %s", err)
		}
	}

}

// hydrateIPMeta attempts to determine the metadata labels for `ip` and, if
// successful, adds them to `labels`.
func (s *server) hydrateIPLabels(ip *public.IPAddress, labels map[string]string) error {
	pod, err := s.podForIP(ip)
	switch {
	case err != nil:
		return err
	case pod == nil:
		log.Debugf("no pod for IP %s", addr.PublicIPToString(ip))
		return nil
	default:
		ownerKind, ownerName := s.k8sAPI.GetOwnerKindAndName(pod)
		podLabels := pkgK8s.GetPodLabels(ownerKind, ownerName, pod)
		for key, value := range podLabels {
			labels[key] = value
		}
		labels[pkgK8s.Namespace] = pod.Namespace
		return nil
	}
}

// podForIP returns the pod corresponding to a given IP address, if one exists.
//
// If multiple pods exist with the same IP address, this may be because some
// are terminating and the IP has been assigned to a new pod. In this case, we
// select the running pod, if one currently exists. If there is a single pod
// which is not running, we return that pod. Otherwise we return `nil`, as we
// cannot easily determine which pod sent a given request.
//
// If no pods were found for the provided IP address, it returns nil. Errors are
// returned only in the event of an error indexing the pods list.
func (s *server) podForIP(ip *public.IPAddress) (*apiv1.Pod, error) {
	ipStr := addr.PublicIPToString(ip)
	objs, err := s.k8sAPI.Pod().Informer().GetIndexer().ByIndex(podIPIndex, ipStr)

	if err != nil {
		return nil, err
	}

	if len(objs) == 1 {
		log.Debugf("found one pod at IP %s", ipStr)
		// It's safe to cast elements of `objs` to a `Pod`s here (and in the
		// loop below). If the object wasn't a pod, it should never have been
		// indexed by the indexing func in the first place.
		return objs[0].(*apiv1.Pod), nil
	}

	for _, obj := range objs {
		pod := obj.(*apiv1.Pod)
		if pod.Status.Phase == apiv1.PodRunning {
			// Found a running pod with this IP --- it's that!
			log.Debugf("found running pod at IP %s", ipStr)
			return pod, nil
		}
	}

	log.Warnf(
		"could not uniquely identify pod at %s (found %d pods)",
		ipStr,
		len(objs),
	)
	return nil, nil
}
