package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/hashicorp/vault/api"
)

// Service struct
type Service struct {
	Name        string
	Context     string
	Namespace   string
	AccountName string
}

// Vault vault client
type Vault struct {
	*api.Client
}

var vaultAddr = os.Getenv("VAULT_ADDR")

// DefaultServiceAccountName default service account name
const DefaultServiceAccountName = "default"

func main() {
	// connection to the API server
	//namespace := "default"

	var kubeconfig *string
	if home := homeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	context, err := getCurrentContext()
	if err != nil {
		panic(err.Error())
	}

	// fmt.Println("Context: ", context)

	var services = []Service{}

	deployments, err := clientset.AppsV1().Deployments("").List(metav1.ListOptions{})

	for _, v := range deployments.Items {
		serviceAccount := v.Spec.Template.Spec.ServiceAccountName
		if serviceAccount == "" {
			serviceAccount = DefaultServiceAccountName
		}
		service := Service{
			Name:        v.GetObjectMeta().GetName(),
			Context:     context,
			Namespace:   v.GetObjectMeta().GetNamespace(),
			AccountName: serviceAccount,
		}

		services = append(services, service)

		// fmt.Println(services)
	}

	client, err := NewVaultClient(vaultAddr, "")
	if err != nil {
		panic(err.Error())
	}

	for _, service := range services {
		policy, err := client.addPolicy(service)
		if err != nil {
			fmt.Println(err)
		}

		role, err := client.writeRole(policy, service)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println(role)
	}

}

func getVaultClient(vaultAddr, vaultToken string) (*api.Client, error) {
	config := &api.Config{
		Address: vaultAddr,
	}

	// creating a client
	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}

	if vaultToken != "" {
		client.SetToken(vaultToken)
	}

	return client, nil
}

// NewVaultClient returns *Vault Client
func NewVaultClient(vaultAddr, vaultToken string) (*Vault, error) {
	client, err := getVaultClient(vaultAddr, vaultToken)
	if err != nil {
		return nil, err
	}

	return &Vault{
		Client: client,
	}, nil
}

func (vault *Vault) writeRole(policy string, service Service) (string, error) {
	if policy == "default" || policy == "" {
		return "", errors.New("policy should be defined and should be different than default")
	}

	policies := []string{"default"}
	// pathTmpl := "auth/{{.Context}}/role/{{.Namespace}}-{{.Name}}-role"

	pathTmpl := "auth/kubernetes/role/{{.Context}}{{.Namespace}}-{{.Name}}-role"
	path := service.parseTemplate(pathTmpl)

	data := map[string]interface{}{
		"bound_service_account_names":      service.AccountName,
		"bound_service_account_namespaces": service.Namespace,
		"policies":                         append(policies, policy),
		"ttl":                              "15m",
	}

	_, err := vault.Client.Logical().Write(path, data)

	if err != nil {
		return "", err
	}

	return path, nil
}

func (vault *Vault) addPolicy(service Service) (string, error) {

	policyNameTmpl := "{{.Context}}-{{.Namespace}}-{{.Name}}"
	policyRuleTmpl := `path "secret/data/{{.Context}}/{{.Namespace}}/{{.Name}}/*" {
		capabilities = ["create", "read", "update", "delete", "list"]
	  }`

	policyName := service.parseTemplate(policyNameTmpl)
	policyRule := service.parseTemplate(policyRuleTmpl)

	if policyName == "" || policyRule == "" {
		return "", errors.New("something wrong with parsing templates")
	}
	sys := vault.Client.Sys()
	err := sys.PutPolicy(policyName, policyRule)
	if err != nil {
		return "", err
	}

	return policyName, nil
}

func (service *Service) parseTemplate(t string) string {
	// define a buffer writer
	var writer bytes.Buffer

	tmpl, err := template.New("template").Parse(t)
	if err != nil {
		return ""
	}

	err = tmpl.Execute(&writer, service) // we need to pass a pointer (address) to writer
	if err != nil {
		return ""
	}

	
	return writer.String()
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}

func getCurrentContext() (string, error) {
	pathOptions := clientcmd.NewDefaultPathOptions()

	config, err := pathOptions.GetStartingConfig()
	if err != nil {
		return "", err
	}

	return config.CurrentContext, nil
}
