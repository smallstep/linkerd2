## edge-18.11.3

* CLI
  * **New** `linkerd routes` command displays per-route stats for services with
    service profiles
  * **Experimental** Add `--ha` flag to `linkerd install` command, for HA
    deployment of the control plane (thanks @benjdlambert!)
* Web UI
  * **Experimental** Top Routes page, served at `/routes`
* Controller
  * **Fixed** Fix auto injection issue on Kubernetes `v1.9.11` that would
    merge, rather than append, the proxy container into the application
* Proxy
  * **Improved** Add controller client metrics, scoped under `control_`
  * **Improved** Canonicalize outbound names via DNS for inbound profiles

## edge-18.11.2

* CLI
  * **Improved** Update stat command to accept multiple stat targets
  * **Fixed** Fix authority stat filtering when the `--from` flag is present
  * Various improvements to check command, including:
    * Emit warnings instead of errors when not running the latest version
    * Add retries if control plane health check fails initially
    * Run all pre-install RBAC checks, instead of stopping at first failure
* Proxy / Proxy-Init
  * **Fixed** Fix routing issue when a pod makes a request to itself (#1585)
  * Only include `classification` label on `response_total` metric

## edge-18.11.1

* Proxy
  * **Fixed** Remove panic when failing to get remote address
  * **Improved** Better logging in TCP connect error messages
* Web UI
  * **Improved** Fixed a smattering of small UI issues

## edge-18.10.4

This release includes a major redesign of the web frontend to make use of the
Material design system. Additional features that leverage the new design are
coming soon! This release also includes the following changes:

* CLI
  * **Fixed** Fixed an issue with the `--registry` install flag not accepting
    hosts with ports (thanks, @alenkacz!)
* Web UI
  * **New** Added a new Grafana dashboard for authorities (thanks, @alpeb!)
  * **New** Revamped look and feel of the Linkerd dashboard by switching
    component libraries from antd to material-ui

## edge-18.10.3

* CLI
  * **New** Added an `--output` stat flag, for printing stats as JSON
  * **Improved** Updated the `top` table to set column widths dynamically
  * **Experimental** Added a `--single-namespace` install flag for installing
    the control plane with Role permissions instead of ClusterRole permissions
* Controller
  * Fixed a few issues with auto injection via the proxy-injector webhook:
    * Injected pods now execute the linkerd-init container last, to avoid
      rerouting requests during pod init
    * Original pod labels and annotations are preserved when auto-injecting
* Web UI
  * **New** Added a Help section in the sidebar containing useful links

## edge-18.10.2

This release brings major improvements to the CLI as described below, including
support for auto-injecting deployments via a Kubernetes Admission Controller.
Proxy auto-injection is **experimental**, and the implementation may change
going forward.

* CLI
  * **New** Added a `--proxy-auto-inject` flag to the `install` command,
    allowing for auto-injection of sidecar containers (Thanks @ihcsim!)
  * **Improved** Added `--proxy-cpu` and `--proxy-memory` flags to the `install`
    and `inject` commands, giving the ability to configure CPU + Memory requests
    (Thanks @benjdlambert!)
  * **Improved** Added a `--context` flag to specify the context to use to talk
    to the Kubernetes apiserver (Thanks @ffd2subroutine!)

## edge-18.10.1

* Web UI
  * **Improved** Tap and Top pages
    * Added clear button to query form
  * **Improved** Resource Detail pages
    * Limit number of resources shown in the graph
* Controller
  * CLI health check now uses unified endpoint for data plane checks
  * Include Licence files in all Docker images

Special thanks to @alenkacz for contributing to this release!

## edge-18.9.3

* Web UI
  * **Improved** Resource Detail page
    * Better rendering of the dependency graph at the top of the page
    * Unmeshed sources are now populated in the Inbound traffic table
    * Sources and destinations are aligned in the popover
  * **Improved** Tap and Top pages
    * Additional validation and polish for the form controls
    * The top table clears older results when a new top call is started
    * The top table now aggregates by HTTP method as well
* CLI
  * **New** The namespace in which Linkerd is installed is configurable via the
    `LINKERD_NAMESPACE` env var, in addition to the `--linkerd-namespace` flag
  * **New** The wait time for the `check` and `dashboard` commands is
    configurable via the `--wait` flag
  * **Improved** The `top` command now aggregates by HTTP method as well

Special thanks to @rochacon, @fahrradflucht and @alenkacz for contributing to
this release!

## stable-2.0.0

## edge-18.9.2

* **New** _edge_ and _stable_ release channels
* Web UI
  * **Improved** Tap & Top UIs with better layout and linking
* CLI
  * **Improved** `check --pre` command verifies the caller has sufficient
    permissions to install Linkerd
  * **Improved** `check` command verifies that Prometheus has data for proxied
    pods
* Proxy
  * **Fix** `hyper` crate dependency corrects HTTP/1.0 Keep-Alive behavior

## v18.9.1

* Web UI
  * **New** Default landing page provides namespace overview with expandable
    sections
  * **New** Breadcrumb navigation at the top of the dashboard
  * **Improved** Tap and Top pages
    * Table rendering performance improvements via throttling
    * Tables now link to resource detail pages
    * Tap an entire namespace when no resource is specified
    * Tap websocket errors provide more descriptive text
    * Consolidated source and destination columns
  * Misc ui updates
    * Metrics tables now include a small success rate chart
    * Improved latency formatting for seconds latencies
    * Renamed upstream/downstream to inbound/outbound
    * Sidebar scrolls independently from main panel, scrollbars hidden when not
      needed
    * Removed social links from sidebar
* CLI
  * **New** `linkerd check` now validates Linkerd proxy versions and readiness
  * **New** `linkerd inject` now provides an injection status report, and warns
    when resources are not injectable
  * **New** `linkerd top` now has a `--hide-sources` flag, to hide the source
    column and collapse top results accordingly
* Control Plane
  * Updated Prometheus to v2.4.0, Grafana to 5.2.4

## v18.8.4

* Web UI
  * **Improved** Tap and Top now have a better sampling rate
  * **Fixed** Missing sidebar headings now appear

## v18.8.3

* Web UI
  * **Improved** Kubernetes resource navigation in the sidebar
  * **Improved** resource detail pages:
    * **New** live request view
    * **New** success rate graphs
* CLI
  * `tap` and `top` have been improved to sample up to 100 RPS
* Control plane
  * Injected proxy containers now have readiness and liveness probes enabled

Special thanks to @sourishkrout for contributing a web readibility fix!

## v18.8.2

* CLI
  * **New** `linkerd top` command has been added, displays live traffic stats
  * `linkerd check` has been updated with additional checks, now supports a
    `--pre` flag for running pre-install checks
  * `linkerd check` and `linkerd dashboard` now support a `--wait` flag that
    tells the CLI to wait for the control plane to become ready
  * `linkerd tap` now supports a `--output` flag to display output in a wide
    format that includes src and dst resources and namespaces
  * `linkerd stat` includes additional validation for command line inputs
  * All commands that talk to the Linkerd API now show better error messages
    when the control plane is unavailable
* Web UI
  * **New** individual resources can now be viewed on a resource detail page,
    which includes stats for the resource itself and its nearest neighbors
  * **Experimental** web-based Top interface accessible at `/top`, aggregates
    tap data in real time to display live traffic stats
  * The `/tap` page has multiple improvements, including displaying additional
    src/dst metadata, improved form controls, and better latency formatting
  * All resource tables have been updated to display meshed pod counts, as well
    as an icon linking to the resource's Grafana dashboard if it is meshed
  * The UI now shows more useful information when server errors are encountered
* Proxy
  * The `h2` crate fixed a HTTP/2 window management bug
  * The `rustls` crate fixed a bug that could improperly fail TLS streams
* Control Plane
  * The tap server now hydrates metadata for both sources and destinations

## v18.8.1

* Web UI
  * **New** Tap UI makes it possible to query & inspect requests from the browser!
* Proxy
  * **New** Automatic, transparent HTTP/2 multiplexing of HTTP/1 traffic
    reduces the cost of short-lived HTTP/1 connections
* Control Plane
  * **Improved** `linkerd inject` now supports injecting all resources in a folder
  * **Fixed** `linkerd tap` no longer crashes when there are many pods
  * **New** Prometheus now only scrapes proxies belonging to its own linkerd install
  * **Fixed** Prometheus metrics collection for clusters with >100 pods

Special thanks to @ihcsim for contributing the `inject` improvement!

## v18.7.3

Linkerd2 v18.7.3 completes the rebranding from Conduit to Linkerd2, and improves
overall performance and stability.

* Proxy
  * **Improved** CPU utilization by ~20%
* Web UI
  * **Experimental** `/tap` page now supports additional filters
* Control Plane
  * Updated all k8s.io dependencies to 1.11.1

## v18.7.2

Linkerd2 v18.7.2 introduces new stability features as we work toward production
readiness.

* Control Plane
  * **Breaking change** Injected pod labels have been renamed to be more
    consistent with Kubernetes; previously injected pods must be re-injected
    with new version of linkerd CLI in order to work with updated control plane
  * The "ca-bundle-distributor" deployment has been renamed to "ca"
* Proxy
  * **Fixed** HTTP/1.1 connections were not properly reused, leading to
    elevated latencies and CPU load
  * **Fixed** The `process_cpu_seconds_total` was calculated incorrectly
* Web UI
  * **New** per-namespace application topology graph
  * **Experimental** web-based Tap interface accessible at  `/tap`
  * Updated favicon to the Linkerd logo

## v18.7.1

Linkerd2 v18.7.1 is the first release of the Linkerd2 project, which was
formerly hosted at github.com/runconduit/conduit.

* Packaging
  * Introduce new date-based versioning scheme, `vYY.M.n`
  * Move all Docker images to `gcr.io/linkerd-io` repo
* User Interface
  * Update branding to reference Linkerd throughout
  * The CLI is now called `linkerd`
* Production Readiness
  * Fix issue with Destination service sending back incomplete pod metadata
  * Fix high CPU usage during proxy shutdown
  * ClusterRoles are now unique per Linkerd install, allowing multiple instances
    to be installed in the same Kubernetes cluster

## v0.5.0

Conduit v0.5.0 introduces a new, experimental feature that automatically
enables Transport Layer Security between Conduit proxies to secure
application traffic. It also adds support for HTTP protocol upgrades, so
applications that use WebSockets can now benefit from Conduit.

* Security
  * **New** `conduit install --tls=optional` enables automatic, opportunistic
    TLS. See [the docs][auto-tls] for more info.
* Production Readiness
  * The proxy now transparently supports HTTP protocol upgrades to support, for
    instance, WebSockets.
  * The proxy now seamlessly forwards HTTP `CONNECT` streams.
  * Controller services are now configured with liveness and readiness probes.
* User Interface
  * `conduit stat` now supports a virtual `authority` resource that aggregates
    traffic by the `:authority` (or `Host`) header of an HTTP request.
  * `dashboard`, `stat`, and `tap` have been updated to describe TLS state for
    traffic.
  * `conduit tap` now has more detailed information, including the direction of
    each message (outbound or inbound).
  * `conduit stat` now more-accurately records histograms for low-latency services.
  * `conduit dashboard` now includes error messages when a Conduit-enabled pod fails.
* Internals
  * Prometheus has been upgraded to v2.3.1.
  * A potential live-lock has been fixed in HTTP/2 servers.
  * `conduit tap` could crash due to a null-pointer access. This has been fixed.

[auto-tls]: docs/automatic-tls.md

## v0.4.4

Conduit v0.4.4 continues to improve production suitability and sets up internals for the
upcoming v0.5.0 release.

* Production Readiness
  * The destination service has been mostly-rewritten to improve safety and correctness,
    especially during controller initialization.
  * Readiness and Liveness checks have been added for some controller components.
  * RBAC settings have been expanded so that Prometheus can access node-level metrics.
* User Interface
  * Ad blockers like uBlock prevented the Conduit dashboard from fetching API data. This
    has been fixed.
  * The UI now highlights pods that have failed to start a proxy.
* Internals
  * Various dependency upgrades, including Rust 1.26.2.
  * TLS testing continues to bear fruit, precipitating stability improvements to
    dependencies like Rustls.

Special thanks to @alenkacz for improving docker build times!

## v0.4.3

Conduit v0.4.3 continues progress towards production readiness. It features a new
latency-aware load balancer.

* Production Readiness
  * The proxy now uses a latency-aware load balancer for outbound requests. This
    implementation is based on Finagle's Peak-EWMA balancer, which has been proven to
    significantly reduce tail latencies. This is the same load balancing strategy used by
    Linkerd.
* User Interface
  * `conduit stat` is now slightly more predictable in the way it outputs things,
    especially for commands like `watch conduit stat all --all-namespaces`.
  * Failed and completed pods are no longer shown in stat summary results.
* Internals
  * The proxy now supports some TLS configuration, though these features remain disabled
    and undocumented pending further testing and instrumentation.

Special thanks to @ihcsim for contributing his first PR to the project and to @roanta for
discussing the Peak-EWMA load balancing algorithm with us.

## v0.4.2

Conduit v0.4.2 is a major step towards production readiness. It features a wide array of
fixes and improvements for long-running proxies, and several new telemetry features. It
also lays the groundwork for upcoming releases that introduce mutual TLS everywhere.

* Production Readiness
  * The proxy now drops metrics that do not update for 10 minutes, preventing unbounded
    memory growth for long-running processes.
  * The proxy now constrains the number of services that a node can route to
    simultaneously (default: 100). This protects long-running proxies from consuming
    unbounded resources by tearing down the longest-idle clients when the capacity is
    reached.
  * The proxy now properly honors HTTP/2 request cancellation.
  * The proxy could incorrectly handle requests in the face of some connection errors.
    This has been fixed.
  * The proxy now honors DNS TTLs.
  * `conduit inject` now works with `statefulset` resources.
* Telemetry
  * **New** `conduit stat` now supports the `all` Kubernetes resource, which
    shows traffic stats for all Kubernetes resources in a namespace.
  * **New** the Conduit web UI has been reorganized to provide namespace overviews.
  * **Fix** a bug in Tap that prevented the proxy from simultaneously satisfying more than
    one Tap request.
  * **Fix** a bug that could prevent stats from being reported for some TCP streams in
    failure conditions.
  * The proxy now measures response latency as time-to-first-byte.
* Internals
  * The proxy now supports user-friendly time values (e.g. `10s`) from environment
    configuration.
  * The control plane now uses client for Kubernetes 1.10.2.
  * Much richer proxy debug logging, including socket and stream metadata.
  * The proxy internals have been changed substantially in preparation for TLS support.

Special thanks to @carllhw, @kichristensen, & @sfroment for contributing to this release!

### Upgrading from v0.4.1

When upgrading from v0.4.1, we suggest that the control plane be upgraded to v0.4.2 before
injecting application pods to use v0.4.2 proxies.

## v0.4.1

Conduit 0.4.1 builds on the telemetry work from 0.4.0, providing rich,
Kubernetes-aware observability and debugging.

* Web UI
  * **New** Automatically-configured Grafana dashboards for Services, Pods,
    ReplicationControllers, and Conduit mesh health.
  * **New** `conduit dashboard` Pod and ReplicationController views.
* Command-line interface
  * **Breaking change** `conduit tap` now operates on most Kubernetes resources.
  * `conduit stat` and `conduit tap` now both support kubectl-style resource
    strings (`deploy`, `deploy/web`, and `deploy web`), specifically:
    * `namespaces`
    * `deployments`
    * `replicationcontrollers`
    * `services`
    * `pods`
* Telemetry
  * **New** Tap support for filtering by and exporting destination metadata. Now
    you can sample requests from A to B, where A and B are any resource or group
    of resources.
  * **New** TCP-level stats, including connection counts and durations, and
    throughput, wired through to Grafana dashboards.
* Service Discovery
  * The proxy now uses the [trust-dns] DNS resolver. This fixes a number of DNS
    correctness issues.
  * The Destination service could sometimes return incorrect, stale, labels for an
    endpoint. This has been fixed!

[trust-dns]: https://github.com/bluejekyll/trust-dns

## v0.4.0

Conduit 0.4.0 overhauls Conduit's telemetry system and improves service discovery
reliability.

* Web UI
  * **New** automatically-configured Grafana dashboards for all Deployments.
* Command-line interface
  * `conduit stat` has been completely rewritten to accept arguments like `kubectl get`.
    The `--to` and `--from` filters can be used to filter traffic by destination and
    source, respectively.  `conduit stat` currently can operate on `Namespace` and
    `Deployment` Kubernetes resources. More resource types will be added in the next
    release!
* Proxy (data plane)
  * **New** Prometheus-formatted metrics are now exposed on `:4191/metrics`, including
    rich destination labeling for outbound HTTP requests. The proxy no longer pushes
    metrics to the control plane.
  * The proxy now handles `SIGINT` or `SIGTERM`, gracefully draining requests until all
    are complete or `SIGQUIT` is received.
  * SMTP and MySQL (ports 25 and 3306) are now treated as opaque TCP by default. You
    should no longer have to specify `--skip-outbound-ports` to communicate with such
    services.
  * When the proxy reconnected to the controller, it could continue to send requests to
    old endpoints. Now, when the proxy reconnects to the controller, it properly removes
    invalid endpoints.
  * A bug impacting some HTTP/2 reset scenarios has been fixed.
* Service Discovery
  * Previously, the proxy failed to resolve some domain names that could be misinterpreted
    as a Kubernetes Service name. This has been fixed by extending the _Destination_ API
    with a negative acknowledgement response.
* Control Plane
  * The _Telemetry_ service and associated APIs have been removed.
* Documentation
  * Updated [Roadmap](doc/roadmap.md)

Special thanks to @ahume, @alenkacz, & @xiaods for contributing to this release!

### Upgrading from v0.3.1

When upgrading from v0.3.1, it's important to upgrade proxies before upgrading the
controller. As you upgrade proxies, the controller will lose visibility into some data
plane stats. Once all proxies are updated, `conduit install |kubectl apply -f -` can be
run to upgrade the controller without causing any data plane disruptions. Once the
controller has been restarted, traffic stats should become available.

## v0.3.1

Conduit 0.3.1 improves Conduit's resilience and transparency.

* Proxy (data plane)
  * The proxy now makes fewer changes to requests and responses being proxied. In particular,
    requests and responses without bodies or with empty bodies are better supported.
  * HTTP/1 requests with different `Host` header fields are no longer sent on the same HTTP/1
    connection even when those hostnames resolve to the same IP address.
  * A connection leak during proxying of non-HTTP TCP connections was fixed.
  * The proxy now handles unavailable services more gracefully by timing out while waiting for an
    endpoint to become available for the service.
* Command-line interface
  * `$KUBECONFIG` with multiple paths is now supported. (PR #482 by @hypnoglow).
  * `conduit check` now checks for the availability of a Conduit update. (PR #460 by @ahume).
* Service Discovery
  * Kubernetes services with type `ExternalName` are now supported.
* Control Plane
  * The proxy is injected into the control plane during installation to improve the control plane's
    resilience and to "dogfood" the proxy.
  * The control plane is now more resilient regarding networking failures.
* Documentation
  * The markdown source for the documentation published at https://conduit.io/docs/ is now open
    source at https://github.com/runconduit/conduit/tree/master/doc.

## v0.3.0

Conduit 0.3 focused heavily on production hardening of Conduit's telemetry system. Conduit 0.3
should "just work" for most apps on Kubernetes 1.8 or 1.9 without configuration, and should support
Kubernetes clusters with hundreds of services, thousands of instances, and hundreds of RPS per
instance.

With this release, Conduit also moves from _experimental_ to _alpha_---meaning that we're ready
for some serious testing and vetting from you. As part of this, we've published the
[Conduit roadmap](https://conduit.io/roadmap/), and we've also launched some new mailing lists:
[conduit-users](https://groups.google.com/forum/#!forum/conduit-users),
[conduit-dev](https://groups.google.com/forum/#!forum/conduit-dev), and
[conduit-announce](https://groups.google.com/forum/#!forum/conduit-announce).

* CLI
  * CLI commands no longer depend on `kubectl`
  * `conduit dashboard` now runs on an ephemeral port, removing port 8001 conflicts
  * `conduit inject` now skips pods with `hostNetwork=true`
  * CLI commands now have friendlier error messages, and support a `--verbose` flag for debugging
* Web UI
  * All displayed metrics are now instantaneous snapshots rather than aggregated over 10 minutes
  * The sidebar can now be collapsed
  * UX refinements and bug fixes
* Conduit proxy (data plane)
  * Proxy does load-aware (P2C + least-loaded) L7 balancing for HTTP
  * Proxy can now route to external DNS names
  * Proxy now properly sheds load in some pathological cases when it cannot route
* Telemetry system
  * Many optimizations and refinements to support scale goals
  * Per-path and per-pod metrics have been removed temporarily to improve scalability and stability;
    they will be reintroduced in Conduit 0.4 (#405)
* Build improvements
  * The Conduit docker images are now much smaller.
  * Dockerfiles have been changed to leverage caching, improving build times substantially

Known Issues:
* Some DNS lookups to external domains fail (#62, #155, #392)
* Applications that use WebSockets, HTTP tunneling/proxying, or protocols such as MySQL and SMTP,
  require additional configuration (#339)

## v0.2.0

This is a big milestone! With this release, Conduit adds support for HTTP/1.x and raw TCP traffic,
meaning it should "just work" for most applications that are running on Kubernetes without
additional configuration.

* Data plane
  * Conduit now transparently proxies all TCP traffic, including HTTP/1.x and HTTP/2.
    (See caveats below.)
* Command-line interface
  * Improved error handling for the `tap` command
  * `tap` also now works with HTTP/1.x traffic
* Dashboard
  * Minor UI appearance tweaks
  * Deployments now searchable from the dashboard sidebar

Caveats:
* Conduit will automatically work for most protocols. However, applications that use WebSockets,
  HTTP tunneling/proxying, or protocols such as MySQL and SMTP, will require some additional
  configuration. See the [documentation](https://conduit.io/adding-your-service/#protocol-support)
  for details.
* Conduit doesn't yet support external DNS lookups. These will be addressed in an upcoming release.
* There are known issues with Conduit's telemetry pipeline that prevent it from scaling beyond a
  few nodes. These will be addressed in an upcoming release.
* Conduit is still in alpha! Please help us by
  [filing issues and contributing pull requests](https://github.com/runconduit/conduit/issues/new).

## v0.1.3

* This is a minor bugfix for some web dashboard UI elements that were not rendering correctly.

## v0.1.2

Conduit 0.1.2 continues down the path of increasing usability and improving debugging and
introspection of the service mesh itself.

* Conduit CLI
  * New `conduit check` command reports on the health of your Conduit installation.
  * New `conduit completion` command provides shell completion.
* Dashboard
  * Added per-path metrics to the deployment detail pages.
  * Added animations to line graphs indicating server activity.
  * More descriptive CSS variable names. (Thanks @natemurthy!)
  * A variety of other minor UI bugfixes and improvements
* Fixes
  * Fixed Prometheus config when using RBAC. (Thanks @FaKod!)
  * Fixed `tap` failure when pods do not belong to a deployment. (Thanks @FaKod!)

## v0.1.1

Conduit 0.1.1 is focused on making it easier to get started with Conduit.

* Conduit can now be installed on Kubernetes clusters that use RBAC.
* The `conduit inject` command now supports a `--skip-outbound-ports` flag that directs Conduit to
  bypass proxying for specific outbound ports, making Conduit easier to use with non-gRPC or HTTP/2
  protocols.
* The `conduit tap` command output has been reformatted to be line-oriented, making it easier to
  parse with common UNIX command line utilities.
* Conduit now supports routing of non-fully qualified domain names.
* The web UI has improved support for large deployments and deployments that don't have any
  inbound/outbound traffic.

## v0.1.0

Conduit 0.1.0 is the first public release of Conduit.

* This release supports services that communicate via gRPC only. non-gRPC HTTP/2 services should
  work. More complete HTTP support, including HTTP/1.0 and HTTP/1.1 and non-gRPC HTTP/2, will be
  added in an upcoming release.
* Kubernetes 1.8.0 or later is required.
* kubectl 1.8.0 or later is required. `conduit dashboard` will not work with earlier versions of
  kubectl.
* When deploying to Minikube, Minikube 0.23 or 0.24.1 or later are required. Earlier versions will
  not work.
* This release has been tested using Google Kubernetes Engine and Minikube. Upcoming releases will
  be tested on additional providers too.
* Configuration settings and protocols are not stable yet.
* Services written in Go must use grpc-go 1.3 or later to avoid
  [grpc-go bug #1120](https://github.com/grpc/grpc-go/issues/1120).
