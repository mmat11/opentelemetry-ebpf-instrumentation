//go:build integration_k8s

package promtest

import (
	"log/slog"
	"os"
	"testing"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/integration/components/docker"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/integration/components/kube"
	k8s "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/integration/k8s/common"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/integration/k8s/common/testpath"
	otel "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/integration/k8s/netolly"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/tools"
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: k8s.DockerfileBeyla},
		docker.ImageBuild{Tag: "httppinger:dev", Dockerfile: k8s.DockerfileHTTPPinger},
		docker.ImageBuild{Tag: "quay.io/prometheus/prometheus:v2.55.1"},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-netolly-promexport",
		kube.KindConfig(testpath.Manifests+"/00-kind.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.LocalImage("httppinger:dev"),
		kube.LocalImage("quay.io/prometheus/prometheus:v2.55.1"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-promscrape.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-service.yml"),
		kube.Deploy(testpath.Manifests+"/06-beyla-netolly-promexport.yml"),
	)

	cluster.Run(m)
}

func TestNetworkFlowBytes_Prom(t *testing.T) {
	cluster.TestEnv().Test(t, otel.FeatureNetworkFlowBytes())
}
