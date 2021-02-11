package token

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"

	_ "github.com/aws/aws-sdk-go-v2/service/sts"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

func clientSetForCluster(cluster *types.Cluster) (*kubernetes.Clientset, error) {
	log.Printf("%+v", cluster)
	gen, err := token.NewGenerator(true, false)
	if err != nil {
		return nil, err
	}
	opts := &token.GetTokenOptions{
		ClusterID: *cluster.Name,
	}

	// opts := &token.GetTokenOptions{
	// 	ClusterID: aws.StringValue(cluster.Name),
	// 	Session: sess,
	// }
	// tok, err := gen.GetWithOptions(opts)
	//
	// https://stackoverflow.com/a/63733871

	tok, err := gen.GetWithOptions(opts)
	if err != nil {
		return nil, err
	}

	fmt.Println(tok)

	ca, err := base64.StdEncoding.DecodeString(*cluster.CertificateAuthority.Data)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(
		&rest.Config{
			Host:        *cluster.Endpoint,
			BearerToken: tok.Token,
			TLSClientConfig: rest.TLSClientConfig{
				CAData: ca,
			},
		},
	)

	if err != nil {
		return nil, err
	}

	return clientset, nil
}

func Token() {

	// region := "eu-central-1"

	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile("cluster-name-comes-here"))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	eksClusterName := "cluster-name-comes-here"

	eksSvc := eks.NewFromConfig(cfg)

	res, err := eksSvc.DescribeCluster(context.TODO(), &eks.DescribeClusterInput{
		Name: aws.String(eksClusterName),
	})
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	//name := "wonderful-outfit-1583362361"
	// region := "us-east-2"

	fmt.Println(res.Cluster)

	clientSetForCluster(res.Cluster)

	// sess := session.Must(session.NewSession(&aws.Config{
	// 	Region: aws.String(region),
	// }))

}
