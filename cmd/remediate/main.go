package remediate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/tidwall/sjson"

	"github.com/datreeio/datree/bl/files"
	"github.com/datreeio/datree/bl/messager"
	policy_factory "github.com/datreeio/datree/bl/policy"
	"github.com/datreeio/datree/bl/validation"
	"github.com/datreeio/datree/pkg/cliClient"
	"github.com/datreeio/datree/pkg/defaultRules"
	"github.com/datreeio/datree/pkg/evaluation"
	"github.com/datreeio/datree/pkg/extractor"
	"github.com/datreeio/datree/pkg/localConfig"
	"github.com/datreeio/datree/pkg/policy"
	"github.com/datreeio/datree/pkg/utils"
	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

type LocalConfig interface {
	GetLocalConfiguration() (*localConfig.LocalConfig, error)
}

type Printer interface {
	PrintMessage(messageText string, messageColor string)
}

type CliClient interface {
	//todo add the publish remediate file code
	RequestEvaluationPrerunData(token string, isCi bool) (*cliClient.EvaluationPrerunDataResponse, error)
	AddFlags(flags map[string]interface{})
	GetRemediationConfig(token string, policyName string) (*cliClient.RemediationConfig, error)
	PublishRemediation(remediationConfig cliClient.PublishFailedRequestBody, token string) (*cliClient.PublishFailedResponse, error)
}

type K8sValidator interface {
	ValidateResources(filesConfigurations chan *extractor.FileConfigurations, concurrency int) (chan *extractor.FileConfigurations, chan *extractor.InvalidFile, chan *validation.FileWithWarning)
	InitClient(k8sVersion string, ignoreMissingSchemas bool, schemaLocations []string)
	GetK8sFiles(filesConfigurationsChan chan *extractor.FileConfigurations, concurrency int) (chan *extractor.FileConfigurations, chan *extractor.FileConfigurations)
}

type Evaluator interface {
	Evaluate(policyCheckData evaluation.PolicyCheckData) (evaluation.PolicyCheckResultData, error)
}

type Reader interface {
	FilterFiles(paths []string) ([]string, error)
}

type Messager interface {
	LoadVersionMessages(cliVersion string) chan *messager.VersionMessage
}

var ViolationsFoundError = errors.New("")

type RemediateCommandFlags struct {
	Output               string
	K8sVersion           string
	IgnoreMissingSchemas bool
	OnlyK8sFiles         bool
	Verbose              bool
	PolicyName           string
	SchemaLocations      []string
	PolicyConfig         string
	NoRecord             bool
}

// RemediateCommandFlags constructor
func NewRemediateCommandFlags() *RemediateCommandFlags {
	return &RemediateCommandFlags{
		Output:               "",
		K8sVersion:           "",
		IgnoreMissingSchemas: false,
		OnlyK8sFiles:         false,
		Verbose:              false,
		PolicyName:           "",
		SchemaLocations:      make([]string, 0),
	}
}

type TestCommandData struct {
	Output               string
	K8sVersion           string
	IgnoreMissingSchemas bool
	OnlyK8sFiles         bool
	Policy               policy_factory.Policy
	SchemaLocations      []string
	Token                string
}

func (flags *RemediateCommandFlags) ToMapping() map[string]interface{} {
	val := reflect.Indirect(reflect.ValueOf(flags))
	fieldsAmount := val.Type().NumField()
	flagsByString := make(map[string]interface{})

	for i := 0; i < fieldsAmount; i++ {
		field := val.Type().Field(i)
		flagsByString[field.Name] = val.Field(i).Interface()
	}

	return flagsByString
}

func (flags *RemediateCommandFlags) Validate() error {
	outputValue := flags.Output

	if !evaluation.IsValidOutputOption(outputValue) {
		return fmt.Errorf("invalid --output option - %q\n"+
			"Valid output values are - "+evaluation.OutputFormats(), outputValue)
	}

	err := validateK8sVersionFormatIfProvided(flags.K8sVersion)

	if err != nil {
		return err
	}

	return nil

}

func validateK8sVersionFormatIfProvided(k8sVersion string) error {
	if k8sVersion == "" {
		return nil
	}

	var isK8sVersionInCorrectFormat, _ = regexp.MatchString(`^[0-9]+\.[0-9]+\.[0-9]+$`, k8sVersion)
	if isK8sVersionInCorrectFormat {
		return nil
	} else {
		return fmt.Errorf("the specified schema-version %q is not in the correct format.\n"+
			"Make sure you are following the semantic versioning format <MAJOR>.<MINOR>.<PATCH>\n"+
			"Read more about kubernetes versioning: https://kubernetes.io/releases/version-skew-policy/#supported-versions", k8sVersion)
	}
}

type RemediateCommandContext struct {
	CliVersion     string
	LocalConfig    LocalConfig
	Printer        Printer
	CliClient      CliClient
	Evaluator      Evaluator
	K8sValidator   K8sValidator
	FilesExtractor files.FilesExtractorInterface
	Reader         Reader
	Messager       Messager
}

// AddFlags registers flags for a cli
func (flags *RemediateCommandFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&flags.K8sVersion, "schema-version", "s", "", "Set kubernetes version to validate against. Defaults to 1.20.0")
	cmd.Flags().StringVarP(&flags.PolicyName, "policy", "p", "", "Policy name to run against")

	cmd.Flags().StringVar(&flags.PolicyConfig, "policy-config", "", "Path for local policies configuration file")
	cmd.Flags().BoolVar(&flags.OnlyK8sFiles, "only-k8s-files", false, "Evaluate only valid yaml files with the properties 'apiVersion' and 'kind'. Ignore everything else")
	// kubeconform flag
	cmd.Flags().StringArrayVarP(&flags.SchemaLocations, "schema-location", "", []string{}, "Override schemas location search path (can be specified multiple times)")
	cmd.Flags().BoolVarP(&flags.IgnoreMissingSchemas, "ignore-missing-schemas", "", false, "Ignore missing schemas when executing schema validation step")
}

func New(ctx *RemediateCommandContext) *cobra.Command {
	var localConfigContent *localConfig.LocalConfig

	remediateCommandFlags := NewRemediateCommandFlags()

	configCommand := &cobra.Command{
		Use:   "remediate",
		Short: "Create remediate file for configurations in given <pattern>.",
		Long:  "Create remediate file for configurations in given <pattern>. Input should be glob or `-` for stdin",
		Example: utils.Example(`
		# Remediate the configurations in given YAML file
		datree remediate policies.yaml
		`),
	}

	runCommand := &cobra.Command{
		Use:   "run <pattern>",
		Short: "Create remediate file for configurations in given <pattern>.",
		Long:  "Create remediate file for configurations in given <pattern>. Input should be glob or `-` for stdin",
		Example: utils.Example(`
		# Remediate the configurations in given YAML file
		datree remediate policies.yaml

		`),
		Args: func(cmd *cobra.Command, args []string) error {
			err := utils.ValidateStdinPathArgument(args)
			if err != nil {
				return err
			}
			return remediateCommandFlags.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true

			localConfigContent, err := ctx.LocalConfig.GetLocalConfiguration()
			if err != nil {
				return err
			}

			evaluationPrerunData, err := ctx.CliClient.RequestEvaluationPrerunData(localConfigContent.Token, false)
			if err != nil {
				return err
			}

			saveDefaultRulesAsFile(evaluationPrerunData.DefaultRulesYaml)
			testCommandOptions, err := GenerateTestCommandData(remediateCommandFlags, localConfigContent, evaluationPrerunData)
			if err != nil {
				return err
			}
			return testAndRemediate(ctx, args, testCommandOptions)

			return err
		},
	}
	remediateCommandFlags.AddFlags(runCommand)

	publishCommand := &cobra.Command{
		Use:   "publish <fileName>",
		Short: "Publish remediate configuration for given <fileName>.",
		Long:  "Publish remediate configuration for given <fileName>. Input should be the path to the Policy-as-Code yaml configuration file",
		Example: utils.Example(`
		# Publish the remediate configuration YAML file
		datree remediate publish remediate.yaml

		# Note You need to first enable Policy-as-Code (PaC) on the settings page in the dashboard
		`),
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				errMessage := "requires at least 1 arg"
				return fmt.Errorf(errMessage)
			}
			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			outputFlag, _ := cmd.Flags().GetString("output")
			if !evaluation.IsFormattedOutputOption(outputFlag) {

				messages := ctx.Messager.LoadVersionMessages(ctx.CliVersion)
				for msg := range messages {
					ctx.Printer.PrintMessage(msg.MessageText+"\n", msg.MessageColor)
				}
			}
			var err error
			localConfigContent, err = ctx.LocalConfig.GetLocalConfiguration()
			if err != nil {
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true

			publishFailedResponse, err := publish(ctx, args[0], args[1], localConfigContent)
			if publishFailedResponse != nil {
				ctx.Printer.PrintMessage("Publish failed:\n", "error")
				for _, message := range publishFailedResponse.Payload {
					ctx.Printer.PrintMessage("\t"+message+"\n", "error")
				}
			} else if err != nil {
				ctx.Printer.PrintMessage("Publish failed: \n"+err.Error()+"\n", "error")
			} else {
				ctx.Printer.PrintMessage("Published successfully\n", "green")
			}

			return err
		},
	}

	configCommand.AddCommand(runCommand)
	configCommand.AddCommand(publishCommand)

	return configCommand
}

func GenerateTestCommandData(testCommandFlags *RemediateCommandFlags, localConfigContent *localConfig.LocalConfig, evaluationPrerunDataResp *cliClient.EvaluationPrerunDataResponse) (*TestCommandData, error) {
	k8sVersion := testCommandFlags.K8sVersion
	if k8sVersion == "" {
		k8sVersion = localConfigContent.SchemaVersion
	}
	if k8sVersion == "" {
		k8sVersion = evaluationPrerunDataResp.DefaultK8sVersion
	}

	if k8sVersion == "" {
		k8sVersion = "1.20.0"
	}

	var policies *cliClient.EvaluationPrerunPolicies
	var err error

	if testCommandFlags.PolicyConfig != "" {
		if !evaluationPrerunDataResp.IsPolicyAsCodeMode {
			return nil, fmt.Errorf("to use --policy-config flag you must first enable policy-as-code mode: https://hub.datree.io/policy-as-code")
		}

		policies, err = policy.GetPoliciesFileFromPath(testCommandFlags.PolicyConfig)
		if err != nil {
			return nil, err
		}
	} else {
		policies = evaluationPrerunDataResp.PoliciesJson
	}

	defaultRules, err := defaultRules.GetDefaultRules()
	if err != nil {
		return nil, err
	}

	policy, err := policy_factory.CreatePolicy(policies, testCommandFlags.PolicyName, evaluationPrerunDataResp.RegistrationURL, defaultRules)
	if err != nil {
		return nil, err
	}

	testCommandOptions := &TestCommandData{Output: testCommandFlags.Output,
		K8sVersion:           k8sVersion,
		IgnoreMissingSchemas: testCommandFlags.IgnoreMissingSchemas,
		OnlyK8sFiles:         testCommandFlags.OnlyK8sFiles,
		Policy:               policy,
		SchemaLocations:      testCommandFlags.SchemaLocations,
		Token:                localConfigContent.Token,
	}

	return testCommandOptions, nil
}

func saveDefaultRulesAsFile(preRunDefaultRulesYaml string) {
	if preRunDefaultRulesYaml == "" {
		return
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}

	defaultRulesFilePath := filepath.Join(homeDir, ".datree", "defaultRules.yaml")

	const fileReadPermission = 0644
	_ = ioutil.WriteFile(defaultRulesFilePath, []byte(preRunDefaultRulesYaml), os.FileMode(fileReadPermission))
}

type MessagesContext struct {
	CliVersion  string
	LocalConfig LocalConfig
	Printer     Printer
	CliClient   *cliClient.CliClient
}

func testAndRemediate(ctx *RemediateCommandContext, paths []string, testCommandData *TestCommandData) error {
	if paths[0] == "-" {
		tempFile, err := os.CreateTemp("", "datree_temp_*.yaml")
		if err != nil {
			return err
		}
		defer os.Remove(tempFile.Name())

		if _, err := io.Copy(tempFile, os.Stdin); err != nil {
			return err
		}
		paths = []string{tempFile.Name()}
	}

	filesPaths, err := ctx.Reader.FilterFiles(paths)
	if err != nil {
		return err
	}
	filesCount := len(filesPaths)
	if filesCount == 0 {
		noFilesErr := fmt.Errorf("no files detected")
		return noFilesErr
	}

	evaluationResultData, err := evaluate(ctx, filesPaths, testCommandData)
	if err != nil {
		return err
	}

	validationManager := evaluationResultData.ValidationManager

	if testCommandData.OnlyK8sFiles {
		filesCount -= validationManager.IgnoredFilesCount()
	}

	if err != nil {
		return err
	}

	results := evaluationResultData.FormattedResults

	if wereViolationsFound(validationManager, &results) {
		err = remediate(ctx, testCommandData.Token, testCommandData.Policy.Name, results)
		// todo handle remediate error
		return ViolationsFoundError
	} else {
		fmt.Println("All rules passed successfully")
	}

	return nil
}

type EvaluationResultData struct {
	ValidationManager *ValidationManager
	RulesCount        int
	FormattedResults  evaluation.FormattedResults
}

func wereViolationsFound(validationManager *ValidationManager, results *evaluation.FormattedResults) bool {
	if validationManager.InvalidYamlFilesCount() > 0 {
		return true
	} else if validationManager.InvalidK8sFilesCount() > 0 {
		return true
	} else if results.EvaluationResults != nil && results.EvaluationResults.Summary.TotalFailedRules > 0 {
		return true
	} else {
		return false
	}
}

func remediate(ctx *RemediateCommandContext, token string, policyName string, testResults evaluation.FormattedResults) error {
	remediationConfig, _ := ctx.CliClient.GetRemediationConfig(token, policyName)
	remediationConfigJsonStr, _ := json.Marshal(remediationConfig)

	remediateJson, _ := yaml.JSONToYAML(remediationConfigJsonStr)
	remediateJson, _ = yaml.YAMLToJSON(remediateJson)

	// todo support same resource name and kind in different namespaces
	// map[resource_name]map[resource kind]*path_content_to_be_yamled
	patchMapper := make(map[string]map[string][]string)

	// create patches folder
	// todo maybe rename
	isDirExists, _ := exists("patches")
	if !isDirExists {
		osMkdirErr := os.Mkdir("patches", os.ModePerm)
		if osMkdirErr != nil {
			return osMkdirErr
		}
	}

	// todo use filename in the loop
	for _, rules := range testResults.EvaluationResults.FileNameRuleMapper {
		for _, rule := range rules {
			for _, occurrence := range rule.OccurrencesDetails {

				if _, exists := patchMapper[occurrence.MetadataName]; !exists {
					patchMapper[occurrence.MetadataName] = make(map[string][]string)
				}

				remediateObj := gjson.Get(string(remediateJson), rule.Identifier)
				// rule exists in remediate file
				if remediateObj.Type != gjson.Null {
					remediatePatchObj := gjson.Get(remediateObj.Raw, "remediate")
					path := gjson.Get(remediatePatchObj.Raw, "path")
					replacedPath := strings.ReplaceAll(path.String(), "{{$INSTANCE_LOCATION}}", rule.InstanceLocation)
					remediatePatchObjUpdated, _ := sjson.Set(remediatePatchObj.Raw, "path", replacedPath)
					remediateJson, _ := yaml.YAMLToJSON([]byte(remediatePatchObjUpdated))
					// resource name and kind not already exists in mapper
					if _, exists := patchMapper[occurrence.MetadataName][occurrence.Kind]; !exists {
						patchMapper[occurrence.MetadataName][occurrence.Kind] = []string{}
					}

					patchMapper[occurrence.MetadataName][occurrence.Kind] = append(patchMapper[occurrence.MetadataName][occurrence.Kind], string(remediateJson))
				}
			}
		}
	}

	for resourceName, metadataNamePatcher := range patchMapper {
		res := "["
		for kind, kindPatcher := range metadataNamePatcher {
			for _, remediateObj := range kindPatcher {
				res += remediateObj
				res += ","
			}
			res += "]"
			resYml, _ := yaml.JSONToYAML([]byte(res))
			err := os.WriteFile(fmt.Sprintf("patches/%s-%s-fixed.yml", kind, resourceName), resYml, 0644)
			fmt.Println(err)
		}
	}

	return nil
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func evaluate(ctx *RemediateCommandContext, filesPaths []string, testCommandData *TestCommandData) (EvaluationResultData, error) {
	isInteractiveMode := !evaluation.IsFormattedOutputOption(testCommandData.Output)

	validationManager := NewValidationManager()

	ctx.K8sValidator.InitClient(testCommandData.K8sVersion, testCommandData.IgnoreMissingSchemas, testCommandData.SchemaLocations)

	concurrency := 100
	var wg sync.WaitGroup

	validYamlConfigurationsChan, invalidYamlFilesChan := ctx.FilesExtractor.ExtractFilesConfigurations(filesPaths, concurrency)

	wg.Add(1)
	go validationManager.AggregateInvalidYamlFiles(invalidYamlFilesChan, &wg)

	if testCommandData.OnlyK8sFiles {
		var ignoredYamlFilesChan chan *extractor.FileConfigurations
		validYamlConfigurationsChan, ignoredYamlFilesChan = ctx.K8sValidator.GetK8sFiles(validYamlConfigurationsChan, concurrency)
		wg.Add(1)
		go validationManager.AggregateIgnoredYamlFiles(ignoredYamlFilesChan, &wg)
	}

	validK8sFilesConfigurationsChan, invalidK8sFilesChan, filesWithWarningsChan := ctx.K8sValidator.ValidateResources(validYamlConfigurationsChan, concurrency)

	wg.Add(3)
	go validationManager.AggregateValidK8sFiles(validK8sFilesConfigurationsChan, &wg)
	go validationManager.AggregateInvalidK8sFiles(invalidK8sFilesChan, &wg)
	go validationManager.AggregateK8sValidationWarningsPerValidFile(filesWithWarningsChan, &wg)

	wg.Wait()

	policyName := testCommandData.Policy.Name

	policyCheckData := evaluation.PolicyCheckData{
		FilesConfigurations: validationManager.ValidK8sFilesConfigurations(),
		IsInteractiveMode:   isInteractiveMode,
		PolicyName:          policyName,
		Policy:              testCommandData.Policy,
	}

	emptyEvaluationResultData := EvaluationResultData{
		ValidationManager: nil,
		RulesCount:        0,
		FormattedResults:  evaluation.FormattedResults{},
	}

	if policyCheckData.FilesConfigurations == nil {
		fmt.Println("didn't find valid configurations to remediate")
		return emptyEvaluationResultData, errors.New("didn't find valid configurations")
	}

	policyCheckResultData, err := ctx.Evaluator.Evaluate(policyCheckData)
	if err != nil {
		return emptyEvaluationResultData, err
	}

	evaluationResultData := EvaluationResultData{
		ValidationManager: validationManager,
		RulesCount:        policyCheckResultData.RulesCount,
		FormattedResults:  policyCheckResultData.FormattedResults,
	}

	return evaluationResultData, nil
}

func publish(ctx *RemediateCommandContext, path string, policyName string, localConfigContent *localConfig.LocalConfig) (*cliClient.PublishFailedResponse, error) {
	remediationConfiguration, err := ctx.FilesExtractor.ExtractYamlFileToUnknownStruct(path)
	if err != nil {
		return nil, err
	}

	requestBody := cliClient.PublishFailedRequestBody{
		File:       remediationConfiguration,
		PolicyName: policyName,
	}

	return ctx.CliClient.PublishRemediation(requestBody, localConfigContent.Token)
}
