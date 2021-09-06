package token

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/smithy-go/middleware"

	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"k8s.io/client-go/tools/clientcmd/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1alpha1 "k8s.io/client-go/pkg/apis/clientauthentication/v1alpha1"

	smithyhttp "github.com/aws/smithy-go/transport/http"

	"sigs.k8s.io/yaml"
)

const (
	// The sts GetCallerIdentity request is valid for 15 minutes regardless of this parameters value after it has been
	// signed, but we set this unused parameter to 60 for legacy reasons (we check for a value between 0 and 60 on the
	// server side in 0.3.0 or earlier).  IT IS IGNORED.  If we can get STS to support x-amz-expires, then we should
	// set this parameter to the actual expiration, and make it configurable.
	requestPresignParam = 60
	// The actual token expiration (presigned STS urls are valid for 15 minutes after timestamp in x-amz-date).
	presignedURLExpiration = 15 * time.Minute
	v1Prefix               = "k8s-aws-v1."
	clusterIDHeader        = "x-k8s-aws-id"
	// Format of the X-Amz-Date header used for expiration
	// https://golang.org/pkg/time/#pkg-constants
	dateHeaderFormat = "20060102T150405Z"
)

// Token is generated and used by Kubernetes client-go to authenticate with a Kubernetes cluster.
type EKSToken struct {
	Token      string
	Expiration time.Time
}

type kubeCluster struct {
	Name    string       `json:"name"`
	Cluster *api.Cluster `json:"cluster"`
}

type kubeUser struct {
	Name string        `json:"name"`
	User *api.AuthInfo `json:"user"`
}

type kubeContext struct {
	Name    string       `json:"name"`
	Context *api.Context `json:"context"`
}

type qbConfig struct {
	Kind           string        `json:"kind"`
	APIVersion     string        `json:"apiVersion"`
	Clusters       []kubeCluster `json:"clusters,inline"`
	Users          []kubeUser    `json:"users,inline"`
	Contexts       []kubeContext `json:"contexts,inline"`
	CurrentContext string        `json:"current-context"`
}

// // FormatJSON formats the json to support ExecCredential authentication
// func getExecCredentialJSON(token token.Token) string {
// 	expirationTimestamp := metav1.NewTime(token.Expiration)
// 	execInput := &clientauthv1alpha1.ExecCredential{
// 		TypeMeta: metav1.TypeMeta{
// 			APIVersion: "client.authentication.k8s.io/v1alpha1",
// 			Kind:       "ExecCredential",
// 		},
// 		Status: &clientauthv1alpha1.ExecCredentialStatus{
// 			ExpirationTimestamp: &expirationTimestamp,
// 			Token:               token.Token,
// 		},
// 	}

// 	enc, _ := json.Marshal(execInput)
// 	return string(enc)
// }

// func getToken(ClusterID string) (*token.Token, error) {
// 	gen, err := token.NewGenerator(true, false)
// 	if err != nil {
// 		return nil, err
// 	}
// 	opts := &token.GetTokenOptions{
// 		ClusterID: ClusterID,
// 	}

// 	tok, err := gen.GetWithOptions(opts)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &tok, nil
// }

// func getTokenWithRole(ClusterID, RoleARN string) (*token.Token, error) {
// 	gen, err := token.NewGenerator(true, false)
// 	if err != nil {
// 		return nil, err
// 	}

// 	tok, err := gen.GetWithRole(ClusterID, RoleARN)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &tok, nil
// }

// func clientSetForCluster(cluster *types.Cluster) (*kubernetes.Clientset, error) {
// 	gen, err := token.NewGenerator(true, false)
// 	if err != nil {
// 		return nil, err
// 	}
// 	opts := &token.GetTokenOptions{
// 		ClusterID: *cluster.Name,
// 	}

// 	// opts := &token.GetTokenOptions{
// 	// 	ClusterID: aws.StringValue(cluster.Name),
// 	// 	Session: sess,
// 	// }
// 	// tok, err := gen.GetWithOptions(opts)
// 	//
// 	// https://stackoverflow.com/a/63733871

// 	tok, err := gen.GetWithOptions(opts)
// 	if err != nil {
// 		return nil, err
// 	}

// 	//	fmt.Println(tok)

// 	ca, err := base64.StdEncoding.DecodeString(*cluster.CertificateAuthority.Data)
// 	if err != nil {
// 		return nil, err
// 	}
// 	clientset, err := kubernetes.NewForConfig(
// 		&rest.Config{
// 			Host:        *cluster.Endpoint,
// 			BearerToken: tok.Token,
// 			TLSClientConfig: rest.TLSClientConfig{
// 				CAData: ca,
// 			},
// 		},
// 	)

// 	if err != nil {
// 		return nil, err
// 	}

// 	return clientset, nil
// }

// FormatJSON formats the json to support ExecCredential authentication
func FormatJSON(token EKSToken) string {
	expirationTimestamp := metav1.NewTime(token.Expiration)
	execInput := &clientauthv1alpha1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "client.authentication.k8s.io/v1alpha1",
			Kind:       "ExecCredential",
		},
		Status: &clientauthv1alpha1.ExecCredentialStatus{
			ExpirationTimestamp: &expirationTimestamp,
			Token:               token.Token,
		},
	}
	enc, _ := json.Marshal(execInput)
	return string(enc)
}

func TokenWithCustomSign() {

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile("nlo-admin-cli"))
	if err != nil {
		panic(err)
	}

	req, body := generateSigningRequest()

	//expires := 14 * time.Minute

	query := req.URL.Query()
	// query.Set("X-Amz-Expires", strconv.FormatInt(int64(expires/time.Second), 10))
	query.Set("X-Amz-Expires", "60")
	query.Set("Action", "GetCallerIdentity")
	query.Set("Version", "2011-06-15")

	req.URL.RawQuery = query.Encode()

	req.Header.Add(clusterIDHeader, "nlo-dev-gateway")

	signerCredentials, _ := cfg.Credentials.Retrieve(context.Background())

	signer := v4.NewSigner()
	signed, _, err := signer.PresignHTTP(context.Background(), signerCredentials, req, body, "sts", "eu-central-1", time.Unix(time.Now().Unix(), 0))
	if err != nil {
		log.Fatalf("expected no error, got %v", err)
	}

	// fmt.Println(signed)
	// fmt.Println(headers)

	fmt.Println(signed)
	// // Set token expiration to 1 minute before the presigned URL expires for some cushion
	tokenExpiration := time.Now().Local().Add(14 * time.Minute)
	// // TODO: this may need to be a constant-time base64 encoding
	ekstoken := EKSToken{
		Token:      v1Prefix + base64.RawURLEncoding.EncodeToString([]byte(signed)),
		Expiration: tokenExpiration,
	}

	// k8sToken, err := json.Marshal(ekstoken)
	// if err != nil {
	// 	fmt.Printf("err: %v\n", err)
	// }
	//fmt.Println(string(k8sToken))

	fmt.Println(FormatJSON(ekstoken))

}

func generateSigningRequest() (*http.Request, string) {
	var (
		// bodyLen     = 0
		serviceName = "sts"
		region      = "eu-central-1"
	)

	reader := strings.NewReader("")

	// type lenner interface {
	// 	Len() int
	// }
	// if lr, ok := body.(lenner); ok {
	// 	bodyLen = lr.Len()
	// }

	endpoint := "https://" + serviceName + "." + region + ".amazonaws.com/"
	req, _ := http.NewRequest("GET", endpoint, reader)

	req.URL.Opaque = fmt.Sprintf("//%s.%s.amazonaws.com/", serviceName, region)

	// req.Header.Set("X-Amz-Target", "prefix.Operation")
	// req.Header.Set("Content-Type", "application/x-amz-json-1.0")

	// if bodyLen > 0 {
	// 	req.ContentLength = int64(bodyLen)
	// }

	h := sha256.New()
	_, _ = io.Copy(h, reader)
	payloadHash := hex.EncodeToString(h.Sum(nil))

	return req, payloadHash
}

// func (g generator) GetWithSTS(ctx context.Context, clusterID string, client *sts.Client) (Token, error) {
// 	// generate an sts:GetCallerIdentity request and add our custom cluster ID header
// 	presigner := sts.NewPresignClient(client)
// 	presignedURLRequest, err := presigner.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(presignOptions *sts.PresignOptions) {
// 		presignOptions.ClientOptions = append(presignOptions.ClientOptions, func(stsOptions *sts.Options) {
// 			// Add clusterId Header
// 			stsOptions.APIOptions = append(stsOptions.APIOptions, smithyhttp.SetHeaderValue(clusterIDHeader, clusterID))
// 			// Add back useless X-Amz-Expires query param
// 			stsOptions.APIOptions = append(stsOptions.APIOptions, smithyhttp.SetHeaderValue("X-Amz-Expires", "60"))
// 			// Remove not previously whitelisted X-Amz-User-Agent
// 			stsOptions.APIOptions = append(stsOptions.APIOptions, func(stack *middleware.Stack) (error) {
// 				 _, err := stack.Build.Remove("UserAgent")
// 				 return err
// 			})
// 		})
// 	})
// 	if err != nil {
// 		return Token{}, err
// 	}

// 	// Set token expiration to 1 minute before the presigned URL expires for some cushion
// 	tokenExpiration := time.Now().Local().Add(presignedURLExpiration - 1*time.Minute)
// 	// TODO: this may need to be a constant-time base64 encoding
// 	return Token{v1Prefix + base64.RawURLEncoding.EncodeToString([]byte(presignedURLRequest.URL)), tokenExpiration}, nil
// }

func TokenWithRoleFromArn(roleArn string) {

	eksClusterName := "nlo-dev-gateway"

	// region := "eu-central-1"

	// // Using the SDK's default configuration, loading additional config
	// // and credentials values from the environment variables, shared
	// // credentials, and shared configuration files
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile("nlo-admin-cli"))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	// // Initial credentials loaded from SDK's default credential chain. Such as
	// // the environment, shared credentials (~/.aws/credentials), or EC2 Instance
	// // Role. These credentials will be used to to make the STS Assume Role API.
	//
	// cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile("admincli"))

	// cfg, err := config.LoadDefaultConfig(context.TODO(),
	// 	config.WithSharedConfigProfile("nlo-admin-cli"))
	// if err != nil {
	// 	panic(err)
	// }

	// r, _ := url.Parse("https://sts.eu-central-1.amazonaws.com/")
	// q := r.Query()
	// q.Add("Action", "GetCallerIdentity")
	// q.Add("Version", "2011-06-15")
	// r.RawQuery = q.Encode()
	// nsignerCreds, _ := cfg.Credentials.Retrieve(context.Background())
	// nsignerReq := &http.Request{
	// 	URL: r,
	// }

	// nsigner := v4.NewSigner()
	// nsignerURI, nsignedHeaders, nsignerErr := nsigner.PresignHTTP(context.Background(), nsignerCreds, nsignerReq, "", "sts", "eu-central-1", time.Now())
	// if nsignerErr != nil {
	// 	log.Fatal(nsignerErr)
	// }

	// fmt.Println(nsignedHeaders)
	// fmt.Println(nsignerURI)

	// Create the credentials from AssumeRoleProvider to assume the role
	// referenced by the "myRoleARN" ARN.
	stsSvc := sts.NewFromConfig(cfg)

	// generate an sts:GetCallerIdentity request and add our custom cluster ID header
	//request, _ := stsSvc.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})

	// Sign the request.  The expires parameter (sets the x-amz-expires header) is
	// currently ignored by STS, and the token expires 15 minutes after the x-amz-date
	// timestamp regardless.  We set it to 60 seconds for backwards compatibility (the
	// parameter is a required argument to Presign(), and authenticators 0.3.0 and older are expecting a value between
	// 0 and 60 on the server side).
	// https://github.com/aws/aws-sdk-go/issues/2167
	// presignedURLString, err := request.Presign(requestPresignParam)
	// if err != nil {
	// 	return Token{}, err
	// }

	//cos := v1Prefix + base64.RawURLEncoding.EncodeToString([]byte(presignedURLString))

	// Assume Role for STS - this seems to not have worked!
	creds := stscreds.NewAssumeRoleProvider(stsSvc, roleArn, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = "EKSGetTokenAuth"
	})
	cfg.Credentials = aws.NewCredentialsCache(creds)

	// // Client
	presignClient := sts.NewPresignClient(stsSvc, sts.WithPresignClientFromClientOptions(func(o *sts.Options) {
		o.Credentials = cfg.Credentials
	}))
	// presignClient := sts.NewPresignClient(stsSvc)

	// EKSGetTokenAuth

	getCallerIdentity, err := presignClient.PresignGetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{}, func(presignOptions *sts.PresignOptions) {
		presignOptions.ClientOptions = append(presignOptions.ClientOptions, func(stsOptions *sts.Options) {
			// Add clusterId Header
			stsOptions.APIOptions = append(stsOptions.APIOptions, smithyhttp.SetHeaderValue(clusterIDHeader, eksClusterName))
			// Add back useless X-Amz-Expires query param
			stsOptions.APIOptions = append(stsOptions.APIOptions, smithyhttp.SetHeaderValue("X-Amz-Expires", "60"))
			// Remove not previously whitelisted X-Amz-User-Agent
			stsOptions.APIOptions = append(stsOptions.APIOptions, func(stack *middleware.Stack) error {
				_, err := stack.Build.Remove("UserAgent")
				return err
			})
		})
	})
	if err != nil {
		log.Fatalln(err.Error())
	}

	u2, _ := url.Parse(getCallerIdentity.URL)
	// if err != nil {
	//   // TODO: log or handle error, in the meanwhile just return the original
	//   return inURL
	// }
	// q2 := u2.Query()
	// q2.Del("X-Amz-User-Agent") // input token was not properly formatted: non-whitelisted query parameter \"X-Amz-User-Agent\"
	// u2.RawQuery = q2.Encode()

	// req := &http.Request{
	// 	Method: getCallerIdentity.Method,
	// 	URL: func() *url.URL {
	// 		parse, err := url.Parse(getCallerIdentity.URL)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		return parse
	// 	}(),
	// 	Header: getCallerIdentity.SignedHeader,
	// }

	req := &http.Request{
		Method: getCallerIdentity.Method,
		URL:    u2,
		Header: getCallerIdentity.SignedHeader,
	}

	// req.Header.Add(clusterIDHeader, eksClusterName)

	//fmt.Printf("%s\n", getCallerIdentity.URL)

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	body, _ := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", body)

	// // Set token expiration to 1 minute before the presigned URL expires for some cushion
	tokenExpiration := time.Now().Local().Add(14 * time.Minute)
	// // TODO: this may need to be a constant-time base64 encoding
	ekstoken := EKSToken{
		Token:      v1Prefix + base64.RawURLEncoding.EncodeToString([]byte(getCallerIdentity.URL)),
		Expiration: tokenExpiration,
	}

	// k8sToken, err := json.Marshal(ekstoken)
	// if err != nil {
	// 	fmt.Printf("err: %v\n", err)
	// }
	//fmt.Println(string(k8sToken))

	fmt.Println(FormatJSON(ekstoken))

	eksSvc := eks.NewFromConfig(cfg)

	res, err := eksSvc.DescribeCluster(context.TODO(), &eks.DescribeClusterInput{
		Name: aws.String(eksClusterName),
	})
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	//fmt.Println(*res.Cluster.Name)

	//name := "wonderful-outfit-1583362361"
	// region := "us-east-2"

	//fmt.Println(res.Cluster)

	//clientSetForCluster(res.Cluster)

	// opts := &token.GetTokenOptions{
	// 	ClusterID: aws.StringValue(cluster.Name),
	// 	Session: sess,
	// }
	// tok, err := gen.GetWithOptions(opts)
	//
	// https://stackoverflow.com/a/63733871

	//token, err := getToken(*res.Cluster.Name)
	// token, err := getTokenWithRole(*res.Cluster.Name, "arn:aws:iam::107641125883:role/OrganizationAccountAccessRole")
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }

	//fmt.Println(getExecCredentialJSON(*token))

	// sess := session.Must(session.NewSession(&aws.Config{
	// 	Region: aws.String(region),
	// }))

	// // Kubernetes generated config
	// kubeConfig := api.Config{
	// 	Kind:           "Config",
	// 	APIVersion:     "v1",
	// 	Preferences:    api.Preferences{},
	// 	Clusters:       map[string]*api.Cluster{},
	// 	AuthInfos:      map[string]*api.AuthInfo{},
	// 	Contexts:       map[string]*api.Context{},
	// 	CurrentContext: "",
	// }

	// kubeConfig.AuthInfos[*res.Cluster.Name] = api.NewAuthInfo()
	// kubeConfig.AuthInfos[*res.Cluster.Name].Username = *res.Cluster.Name
	// kubeConfig.AuthInfos[*res.Cluster.Name].Token = ekstoken.Token

	// y, err := yaml.Marshal(kubeConfig)
	// if err != nil {
	// 	fmt.Printf("err: %v\n", err)
	// }
	// fmt.Println(string(y))

	certificateAuthorityData, _ := base64.StdEncoding.DecodeString(*res.Cluster.CertificateAuthority.Data)

	test := qbConfig{
		Kind:       "Config",
		APIVersion: "v1",
		Clusters: []kubeCluster{
			{
				Name: *res.Cluster.Name,
				Cluster: &api.Cluster{
					Server:                   *res.Cluster.Endpoint,
					InsecureSkipTLSVerify:    false,
					CertificateAuthority:     "",
					CertificateAuthorityData: certificateAuthorityData,
				},
			},
		},
		Users: []kubeUser{
			{
				Name: *res.Cluster.Name,
				User: &api.AuthInfo{
					Token: ekstoken.Token,
				},
			},
		},
		Contexts: []kubeContext{
			{
				Name: *res.Cluster.Name,
				Context: &api.Context{
					Cluster:   *res.Cluster.Name,
					Namespace: "default",
					AuthInfo:  *res.Cluster.Name,
				},
			},
		},
		CurrentContext: *res.Cluster.Name,
	}

	qConfigYaml, _ := yaml.Marshal(test)
	// if err != nil {
	// 	fmt.Printf("err: %v\n", err)
	// }
	fmt.Println(string(qConfigYaml))

	// // testConfig, _ := json.Marshal(test)
	// // fmt.Println(string(testConfig))

	// y, err := yaml.Marshal(test)
	// if err != nil {
	// 	fmt.Printf("err: %v\n", err)
	// }
	// fmt.Println(string(y))

	// kubeConfig.Clusters["cluster"] = &api.Cluster{
	// 	Server:                   "",
	// 	InsecureSkipTLSVerify:    false,
	// 	CertificateAuthority:     "",
	// 	CertificateAuthorityData: certificateAuthorityData,
	// }

	// kubeConfig.Clusters["cluster"] = api.NewCluster()
	// kubeConfig.Clusters["cluster"].CertificateAuthorityData = []byte(*res.Cluster.CertificateAuthority.Data)
	// kubeConfig.Clusters["cluster"].Server = *res.Cluster.Endpoint

	// kubeConfig.Contexts[*res.Cluster.Name] = api.NewContext()
	// kubeConfig.Contexts[*res.Cluster.Name].Cluster = *res.Cluster.Name
	// kubeConfig.Contexts[*res.Cluster.Name].AuthInfo = *res.Cluster.Name

	// kubeConfig.CurrentContext = *res.Cluster.Name

	// qConfig, _ := json.Marshal(kubeConfig)
	// fmt.Println(string(qConfig))
}
