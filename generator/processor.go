package generator

import (
	"fmt"

	"sigs.k8s.io/kustomize/kyaml/fn/framework"
	"sigs.k8s.io/kustomize/kyaml/kio/kioutil"
	"sigs.k8s.io/kustomize/kyaml/yaml"

	sdk "github.com/GoogleContainerTools/kpt-functions-catalog/thirdparty/kyaml/fnsdk"
	"github.com/neutronth/kpt-update-ksops-secrets/config"
)

func NewProcessor() *Processor {
	return &Processor{}
}

type Processor struct {
	uks config.UpdateKSopsSecrets
}

func (p *Processor) Process(resourceList *framework.ResourceList) error {
	if err := p.uks.Config(sdk.NewFromRNode(resourceList.FunctionConfig)); err != nil {
		return errorHandler(resourceList, err)
	}

	gen := &KSopsGenerator{}
	uksConfig := &p.uks
	baseSecrets, results := gen.GenerateBaseSecrets(resourceList.Items, uksConfig)
	resourceList.Results = append(resourceList.Results, results...)
	if results.ExitCode() == 1 {
		return resourceList.Results
	}
	setFilename(baseSecrets, ResultFileBaseSecrets)

	kustomization, results := gen.GenerateKustomization(resourceList.Items)
	resourceList.Results = append(resourceList.Results, results...)
	if results.ExitCode() == 1 {
		return resourceList.Results
	}
	setFilename(kustomization, ResultFileKustomization)

	ksopsGenerator, results := gen.GenerateKSopsGenerator(resourceList.Items, uksConfig)
	resourceList.Results = append(resourceList.Results, results...)
	if results.ExitCode() == 1 {
		return resourceList.Results
	}
	setFilename(ksopsGenerator, ResultFileKSopsGenerator)

	secretRef := newSecretReference(resourceList.Items, uksConfig)
	secretEncryptedFiles, results := gen.GenerateSecretEncryptedFiles(
		resourceList.Items, uksConfig, secretRef)
	resourceList.Results = append(resourceList.Results, results...)
	if results.ExitCode() == 1 {
		return resourceList.Results
	}

	resourceListUpserts(resourceList,
		kustomization,
		baseSecrets,
		ksopsGenerator,
		secretEncryptedFiles,
	)
	return nil
}

func resourceListUpserts(resourceList *framework.ResourceList, list ...[]*yaml.RNode) {
	for _, resources := range list {
		for _, node := range resources {
			nodeUpserts(resourceList, node)
		}
	}
}

func nodeUpserts(resourceList *framework.ResourceList, node *yaml.RNode) {
	nodePath, _, _ := kioutil.GetFileAnnotations(node)

	replaced := false

	for idx, resource := range resourceList.Items {
		resourcePath, _, _ := kioutil.GetFileAnnotations(resource)

		if resourcePath == nodePath && resource.GetName() == node.GetName() {
			replaced = true
			resourceList.Items[idx] = node
			break
		}
	}

	if !replaced {
		resourceList.Items = append(resourceList.Items, node)
	}
}

func errorHandler(resourceList *framework.ResourceList, err error) framework.Results {
	resourceList.Results = framework.Results{
		&framework.Result{
			Message:  err.Error(),
			Severity: framework.Error,
		},
	}

	return resourceList.Results
}

func setFilename(nodes []*yaml.RNode, filename string) {
	for idx, node := range nodes {
		annotations := node.GetAnnotations()
		annotations[kioutil.PathAnnotation] = filename
		annotations[kioutil.IndexAnnotation] = fmt.Sprintf("%d", idx)

		node.SetAnnotations(annotations)
	}
}
