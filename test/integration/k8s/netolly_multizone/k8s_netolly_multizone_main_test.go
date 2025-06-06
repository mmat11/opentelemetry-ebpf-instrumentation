//go:build integration_k8s

package otel

import (
	"log/slog"
	"os"
	"testing"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/integration/components/docker"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/integration/components/kube"
	k8s "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/integration/k8s/common"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/integration/k8s/common/testpath"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/tools"
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "beyla:dev", Dockerfile: k8s.DockerfileBeyla},
		docker.ImageBuild{Tag: "httppinger:dev", Dockerfile: k8s.DockerfileHTTPPinger},
		docker.ImageBuild{Tag: "quay.io/prometheus/prometheus:v2.55.1"},
		docker.ImageBuild{Tag: "otel/opentelemetry-collector-contrib:0.103.0"},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-netolly-multizone",
		kube.KindConfig(testpath.Manifests+"/00-kind-multi-zone.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("beyla:dev"),
		kube.LocalImage("httppinger:dev"),
		kube.LocalImage("quay.io/prometheus/prometheus:v2.55.1"),
		kube.LocalImage("otel/opentelemetry-collector-contrib:0.103.0"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-otelscrape-multi-node.yml"),
		kube.Deploy(testpath.Manifests+"/03-otelcol-multi-node.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-multizone-client-server.yml"),
		kube.Deploy(testpath.Manifests+"/06-beyla-netolly-multizone.yml"),
	)

	cluster.Run(m)
}

func TestMultizoneNetworkFlows(t *testing.T) {
	cluster.TestEnv().Test(t, FeatureMultizoneNetworkFlows())
}
