package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	protolang "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CompliancePlugin struct {
	logger hclog.Logger
	data   map[string]interface{}
	config map[string]string
}

// // TODO: move these to a common lib
// type EC2Instance struct {
// 	InstanceID   string `json:"InstanceId"`
// 	InstanceType string `json:"InstanceType"`
// 	ImageID      string `json:"ImageId"`
// 	PrivateIP    string `json:"PrivateIpAddress"`
// 	PublicIP     string `json:"PublicIpAddress,omitempty"`
// 	State        string `json:"State"`
// 	Tags         []Tag  `json:"Tags"`
// }

type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.config = req.GetConfig()
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) PrepareForEval(req *proto.PrepareForEvalRequest) (*proto.PrepareForEvalResponse, error) {

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(os.Getenv("AWS_REGION")))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	if l.config["ec2"] == "true" || l.config["ec2"] == "1" {
		svc := ec2.NewFromConfig(cfg)

		// Get the list of instances
		result, err := svc.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
		if err != nil {
			log.Fatalf("unable to list instances, %v", err)
		}

		// Parse EC2 instance data into a readable format
		var instances []map[string]interface{}
		for _, reservation := range result.Reservations {
			for _, instance := range reservation.Instances {
				// Convert EC2 tags
				var tags []Tag
				for _, tag := range instance.Tags {
					tags = append(tags, Tag{Key: *tag.Key, Value: *tag.Value})
				}

				// Append instance to list
				instances = append(instances, map[string]interface{}{
					"InstanceID":   *instance.InstanceId,
					"InstanceType": string(instance.InstanceType),
					"ImageID":      *instance.ImageId,
					"PrivateIP":    aws.ToString(instance.PrivateIpAddress),
					"PublicIP":     aws.ToString(instance.PublicIpAddress),
					"State":        string(instance.State.Name),
					"Tags":         tags,
				})
			}
		}

		// instanceJSON, err := json.Marshal(instances)
		// if err != nil {
		// 	log.Fatalf("unable to marshal instance to JSON, %v", err)
		// }

		// var instanceMap map[string]interface{}
		// err = json.Unmarshal(instanceJSON, &instanceMap)
		// if err != nil {
		// 	log.Fatalf("unable to unmarshal instance JSON to map, %v", err)
		// }

		// l.logger.Debug("converting AWS configuration to json map for evaluation")
		// awsConfigMap, err := pkg.ConvertConfToMap(scanner)
		// if err != nil {
		// 	l.logger.Error("Failed to convert AWS config to map", "error", err)
		// 	return &proto.PrepareForEvalResponse{}, err
		// }

		l.data["instances"] = instances
	} else {
		fmt.Println("EC2 is not enabled")
	}
	return &proto.PrepareForEvalResponse{}, nil
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	startTime := time.Now()

	// Use the data from the PrepareForEval
	l.logger.Debug("evaluating data", l.data)

	// The Policy Manager aggregates much of the policy execution and output structuring.
	results, err := policyManager.New(ctx, l.logger, request.BundlePath).Execute(ctx, "compliance_plugin", l.data)

	if err != nil {
		l.logger.Error("Failed to evaluate against policy bundle", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	assessmentResult := runner.NewCallableAssessmentResult()
	assessmentResult.Title = "Plugin template"

	for _, result := range results {

		// There are no violations reported from the policies.
		// We'll send the observation back to the agent
		if len(result.Violations) == 0 {
			title := "The plugin succeeded. No compliance issues to report."
			assessmentResult.AddObservation(&proto.Observation{
				Uuid:        uuid.New().String(),
				Title:       &title,
				Description: "The plugin policies did not return any violations. The configuration is in compliance with policies.",
				Collected:   timestamppb.New(time.Now()),
				Expires:     timestamppb.New(time.Now().AddDate(0, 1, 0)), // Add one month for the expiration
				RelevantEvidence: []*proto.RelevantEvidence{
					{
						Description: fmt.Sprintf("Policy %v was evaluated, and no violations were found on machineId: %s", result.Policy.Package.PurePackage(), "ARN:12345"),
					},
				},
				Labels: map[string]string{
					"package": string(result.Policy.Package),
					"type":    "template",
				},
			})

			status := runner.FindingTargetStatusSatisfied
			assessmentResult.AddFinding(&proto.Finding{
				Title:       fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage()),
				Description: fmt.Sprintf("No violations found on the %s policy within the Template Compliance Plugin.", result.Policy.Package.PurePackage()),
				Target: &proto.FindingTarget{
					Status: &proto.ObjectiveStatus{
						State: status,
					},
				},
				Labels: map[string]string{
					"package": string(result.Policy.Package),
					"type":    "template",
				},
			})
		}

		// There are violations in the policy checks.
		// We'll send these observations back to the agent
		if len(result.Violations) > 0 {
			title := fmt.Sprintf("The plugin found violations for policy %s on machineId: %s", result.Policy.Package.PurePackage(), "ARN:12345")
			observationUuid := uuid.New().String()
			assessmentResult.AddObservation(&proto.Observation{
				Uuid:        observationUuid,
				Title:       &title,
				Description: fmt.Sprintf("Observed %d violation(s) for policy %s within the Plugin on machineId: %s.", len(result.Violations), result.Policy.Package.PurePackage(), "ARN:12345"),
				Collected:   timestamppb.New(time.Now()),
				Expires:     timestamppb.New(time.Now().AddDate(0, 1, 0)), // Add one month for the expiration
				RelevantEvidence: []*proto.RelevantEvidence{
					{
						Description: fmt.Sprintf("Policy %v was evaluated, and %d violations were found on machineId: %s", result.Policy.Package.PurePackage(), len(result.Violations), "ARN:12345"),
					},
				},
				Labels: map[string]string{
					"package": string(result.Policy.Package),
					"type":    "template",
				},
			})

			for _, violation := range result.Violations {
				status := runner.FindingTargetStatusNotSatisfied
				assessmentResult.AddFinding(&proto.Finding{
					Title:       violation.Title,
					Description: violation.Description,
					Remarks:     &violation.Remarks,
					RelatedObservations: []*proto.RelatedObservation{
						{
							ObservationUuid: observationUuid,
						},
					},
					Target: &proto.FindingTarget{
						Status: &proto.ObjectiveStatus{
							State: status,
						},
					},
					Labels: map[string]string{
						"package": string(result.Policy.Package),
						"type":    "template",
					},
				})
			}
		}

		for _, risk := range result.Risks {
			links := []*proto.Link{}
			for _, link := range risk.Links {
				links = append(links, &proto.Link{
					Href: link.URL,
					Text: &link.Text,
				})
			}

			assessmentResult.AddRiskEntry(&proto.Risk{
				Title:       risk.Title,
				Description: risk.Description,
				Statement:   risk.Statement,
				Props:       []*proto.Property{},
				Links:       links,
			})
		}
	}

	endTime := time.Now()

	// Send the results back to the agent using the API Helper process the agent created for us
	assessmentResult.Start = timestamppb.New(startTime)
	assessmentResult.End = timestamppb.New(endTime)

	assessmentResult.AddLogEntry(&proto.AssessmentLog_Entry{
		Title:       protolang.String("Template check"),
		Description: protolang.String("Template plugin checks completed successfully"),
		Start:       timestamppb.New(startTime),
		End:         timestamppb.New(endTime),
	})

	streamId, err := sdk.SeededUUID(map[string]string{
		"type":    "template",
		"_policy": request.GetBundlePath(),
	})
	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	err = apiHelper.CreateResult(streamId.String(), map[string]string{
		"type":    "template",
		"_policy": request.GetBundlePath(),
	}, assessmentResult.Result())
	if err != nil {
		l.logger.Error("Failed to add assessment result", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
		data:   make(map[string]interface{}),
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("initiating plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
