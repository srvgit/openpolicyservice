package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"text/template"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/open-policy-agent/opa/rego"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	// Global logger
	sugar *zap.SugaredLogger
	// Global OPA query, prepared at startup
	regoQuery *rego.PreparedEvalQuery
)

// PolicyData reflects the dynamic parts of your policy.
type PolicyData struct {
	ApplicationName   string   `json:"ApplicationName"`
	Environment       string   `json:"Environment"`
	ClientID          string   `json:"ClientID"`
	ApiName           string   `json:"ApiName"`
	ApiVersion        string   `json:"ApiVersion"`
	AllowedActions    []string `json:"AllowedActions"`
	AllowedAttributes []string `json:"AllowedAttributes"`
}

func initConfig() {
	viper.AddConfigPath(".")      // directory of the config file
	viper.SetConfigName("config") // name of the config file (without extension)
	viper.SetConfigType("yaml")   // extension of the config file
	viper.AutomaticEnv()          // Automatically override values from environment variables

	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
}

func main() {

	logger, _ := zap.NewProduction()
	defer logger.Sync() // Flushes buffer, if any
	sugar := logger.Sugar()

	initConfig()

	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Error getting working directory: %v", err)
	}
	log.Printf("Working directory: %s", wd)

	if err := loadAndPreparePolicy(context.Background()); err != nil {
		sugar.Error("Failed to load or prepare policy", "error", err)
	}
	// Routes
	http.HandleFunc("/evaluate", func(w http.ResponseWriter, r *http.Request) {
		evaluatePolicyHandler(w, r, sugar)
	})
	http.HandleFunc("/generate-policy", func(w http.ResponseWriter, r *http.Request) {
		generatePolicyHandler(w, r, sugar)
	})

	sugar.Info("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func evaluatePolicyHandler(w http.ResponseWriter, r *http.Request, logger *zap.SugaredLogger) {
	if r.Method != "POST" {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var input map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logger.Errorw("Invalid JSON payload", "error", err)
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
		results, err := regoQuery.Eval(ctx, rego.EvalInput(input))

	if err != nil {
		logger.Error("Failed to evaluate policy", zap.Error(err))
		http.Error(w, "Failed to evaluate policy", http.StatusInternalServerError)
		return
	}

	if len(results) == 0 {
		logger.Warn("No result from policy evaluation")
		http.Error(w, "No result from policy evaluation", http.StatusInternalServerError)
		return
	}

	// Assuming the decision is a boolean allow/deny
	decision := results[0].Expressions[0].Value.(bool)
	if decision {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Access granted"))
	} else {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access denied"))
	}
}

func generatePolicyHandler(w http.ResponseWriter, r *http.Request, sugar *zap.SugaredLogger) {
	if r.Method != "POST" {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	var policyData PolicyData

	if err := json.NewDecoder(r.Body).Decode(&policyData); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Fetch the policy template path from configuration
	templatePath := viper.GetString("policy.templatePath")
	bucketName := viper.GetString("s3.bucketName")
	objectKey := fmt.Sprintf("policies/%s_%s_%s.rego", policyData.ApplicationName, policyData.ApiName, policyData.ApiVersion)

	templateBytes, err := os.ReadFile(templatePath)
	if err != nil {
		log.Printf("Failed to read policy template file: %v", err)
		http.Error(w, "Failed to read policy template file", http.StatusInternalServerError)
		return
	}

	// tmpl, err := template.New("policy").Parse(string(templateBytes))

	allowedActionsJSON, err := jsonMarshal(policyData.AllowedActions)
	fmt.Println("AllowedActionsJSON:", allowedActionsJSON) // Should output: ["read","write"]

	if err != nil {
		log.Fatalf("Failed to marshal AllowedActions: %v", err)
	}
	allowedAttributesJSON, err := jsonMarshal(policyData.AllowedAttributes)
	fmt.Println("AllowedAttributesJSON:", allowedAttributesJSON) // Should output: ["username","email"]
	if err != nil {
		log.Fatalf("Failed to marshal AllowedAttributes: %v", err)
	}

	// Include the JSON strings in your TemplateData struct
	// templateData := struct {
	// 	PolicyData
	// 	AllowedActionsJSON    string
	// 	AllowedAttributesJSON string
	// }{
	// 	PolicyData:            policyData,
	// 	AllowedActionsJSON:    allowedActionsJSON,
	// 	AllowedAttributesJSON: allowedAttributesJSON,
	// }

	// // Execute the template with the struct that includes the JSON strings.
	// var filledPolicy bytes.Buffer
	// tmpl, err := template.New("policy").Funcs(template.FuncMap{"jsonMarshal": jsonMarshal}).Parse(string(templateBytes)) // Assuming you have loaded your template into policyTemplateString.
	// if err != nil {
	// 	log.Fatalf("Failed to parse policy template: %v", err)
	// }

	// if err := tmpl.Execute(&filledPolicy, templateData); err != nil {
	// 	log.Fatalf("Failed to execute policy template with data: %v", err)
	// }
	// if err != nil {
	// 	log.Printf("Failed to parse policy template: %v", err)
	// 	http.Error(w, "Failed to parse policy template", http.StatusInternalServerError)
	// 	return
	// }

	// allowedActionsJSON, err := jsonMarshal(policyData.AllowedActions)
	// if err != nil {
	// 	log.Fatalf("Failed to marshal AllowedActions: %v", err)
	// }

	// allowedAttributesJSON, err := jsonMarshal(policyData.AllowedAttributes)
	// if err != nil {
	// 	log.Fatalf("Failed to marshal AllowedAttributes: %v", err)
	// }

	templateData := struct {
		PolicyData
		AllowedActionsJSON    string
		AllowedAttributesJSON string
	}{
		PolicyData:            policyData,
		AllowedActionsJSON:    allowedActionsJSON,
		AllowedAttributesJSON: allowedAttributesJSON,
	}

	var filledPolicy bytes.Buffer
	tmpl, err := template.New("policy").Parse(string(templateBytes))
	fmt.Println("Template content:", string(templateBytes))

	if err != nil {
		log.Fatalf("Failed to parse policy template: %v", err)
	}

	if err := tmpl.Execute(&filledPolicy, templateData); err != nil {
		log.Fatalf("Failed to execute policy template with data: %v", err)
	}
	fmt.Println("Filled policy:", filledPolicy.String())
	// var policy bytes.Buffer
	// if err := tmpl.Execute(&policy, policyData); err != nil { // Use `data` instead of `templateBytes`
	// 	log.Printf("Failed to execute template: %v", err)
	// 	http.Error(w, "Failed to execute template", http.StatusInternalServerError)
	// 	return
	// }

	// Initialize AWS S3 client and context remains the same

	// Uploading the policy to S3
	// Initialize AWS S3 client
	ctx := context.Background()
	// cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Unable to load SDK config, %v", err)
	}

	// s3Client := s3.NewFromConfig(cfg)
	// s3Client := s3.NewFromConfig(cfg)
	s3Client := initS3Client(ctx)

	// Define the S3 bucket and object key

	// Upload the policy to S3
	// _, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
	// 	Bucket:      aws.String(bucketName), // Use the bucket name from config
	// 	Key:         aws.String(objectKey),
	// 	Body:        bytes.NewReader(policy.Bytes()),
	// 	ContentType: aws.String("text/plain"),
	// })

	uploader := manager.NewUploader(s3Client)
	_, err = uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(filledPolicy.Bytes()),
	})

	if err != nil {
		log.Printf("Failed to upload policy to S3: %v", err)
		http.Error(w, "Failed to upload policy to S3", http.StatusInternalServerError)
		return
	}

	log.Printf("Policy successfully uploaded to S3: %s", objectKey)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Policy generated and uploaded to S3 successfully"))
}
func initS3Client(ctx context.Context) *s3.Client {
	var cfg aws.Config
	var err error

	if viper.GetString("profile") != "local" {
		cfg, err = config.LoadDefaultConfig(ctx)
		if err != nil {
			log.Fatalf("Unable to load SDK config, %v", err)
		}
		log.Printf("Using AWS profile: %s", viper.GetString("profile"))

		// ...

	} else {

		cfg, err = config.LoadDefaultConfig(
			ctx,
			config.WithRegion("us-east-1"),
			config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
				func(service, region string, options ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{URL: "http://localhost:4566"}, nil
				}),
			),
		)

	}

	if err != nil {
		log.Fatalf("Unable to load SDK config, %v", err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})
	// AmazonS3Client client = new AmazonS3Client(new ClientConfiguration().withForcePathStyle(true));
	return client
}

func loadAndPreparePolicy(ctx context.Context) error {
	policyString, err := fetchPolicyFromS3(ctx)
	if err != nil {
		return err
	}

	// Assuming the policy does not require template processing
	// If it does, insert template processing logic here before compiling
	compiledQuery, err := rego.New(
		rego.Query("data.api.access.allow"),
		rego.Module("policy.rego", policyString),
	).PrepareForEval(ctx)

	if err != nil {
		return fmt.Errorf("failed to prepare rego query: %w", err)
	}

	regoQuery = &compiledQuery
	return nil
}

func fetchPolicyFromS3(ctx context.Context) (string, error) {
	s3Client := initS3Client(ctx)
	bucketName := viper.GetString("s3.bucketName")
	policyObjectKey := viper.GetString("s3.policyObjectKey")

	getObjResp, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucketName,
		Key:    &policyObjectKey,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get object from S3: %w", err)
	}
	defer getObjResp.Body.Close()

	policyBytes, err := ioutil.ReadAll(getObjResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read policy body: %w", err)
	}

	return string(policyBytes), nil
}

func jsonMarshal(v interface{}) (string, error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return "", err // Return an empty string and the error if marshaling fails
	}
	txt := string(bytes)
	escapeText := fmt.Sprintf("%q", txt)
	fmt.Println("TST:", escapeText)
	return escapeText, nil
}
