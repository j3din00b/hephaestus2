// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1 "github.com/dominodatalab/hephaestus/pkg/clientset/typed/hephaestus/v1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeHephaestusV1 struct {
	*testing.Fake
}

func (c *FakeHephaestusV1) ImageBuilds(namespace string) v1.ImageBuildInterface {
	return newFakeImageBuilds(c, namespace)
}

func (c *FakeHephaestusV1) ImageCaches(namespace string) v1.ImageCacheInterface {
	return newFakeImageCaches(c, namespace)
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeHephaestusV1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
