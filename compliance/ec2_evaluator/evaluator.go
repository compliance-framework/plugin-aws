package ec2_evaluator

import (
	"context"
	"errors"
	"fmt"
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
	protolang "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Evaluator struct {
	Logger hclog.Logger
}

type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

func (e *Evaluator) Run(ctx context.Context, request *proto.EvalRequest, apiHelper runner.ApiHelper) (proto.ExecutionStatus, error) {
	startTime := time.Now()
	evalStatus := proto.ExecutionStatus_SUCCESS
	var errAcc error

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(os.Getenv("AWS_REGION")))
	if err != nil {
		e.Logger.Error("unable to load SDK config", "error", err)
		return proto.ExecutionStatus_FAILURE, err
	}

	svc := ec2.NewFromConfig(cfg)

	// Get instances
	result, err := svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		e.Logger.Error("unable to list instances", "error", err)
		return proto.ExecutionStatus_FAILURE, err
	}

	// Parse instances
	var instances []map[string]interface{}
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			e.Logger.Debug("instance", instance)

			var tags []Tag
			for _, tag := range instance.Tags {
				tags = append(tags, Tag{Key: *tag.Key, Value: *tag.Value})
			}

			// Append instance to list
			instances = append(instances, map[string]interface{}{
				"InstanceID":          aws.ToString(instance.InstanceId),
				"InstanceType":        string(instance.InstanceType),
				"ImageID":             aws.ToString(instance.ImageId),
				"PrivateIP":           aws.ToString(instance.PrivateIpAddress),
				"PublicIP":            aws.ToString(instance.PublicIpAddress),
				"State":               string(instance.State.Name),
				"Tags":                tags,
				"LaunchTime":          instance.LaunchTime,
				"SubnetID":            aws.ToString(instance.SubnetId),
				"VpcID":               aws.ToString(instance.VpcId),
				"KeyName":             aws.ToString(instance.KeyName),
				"Architecture":        string(instance.Architecture),
				"Platform":            string(instance.Platform),
				"PlatformDetails":     aws.ToString(instance.PlatformDetails),
				"RootDeviceType":      string(instance.RootDeviceType),
				"RootDeviceName":      aws.ToString(instance.RootDeviceName),
				"VirtualizationType":  string(instance.VirtualizationType),
				"Monitoring":          instance.Monitoring.State,
				"SecurityGroups":      instance.SecurityGroups,
				"BlockDeviceMappings": instance.BlockDeviceMappings,
				"NetworkInterfaces":   instance.NetworkInterfaces,
				"Hypervisor":          string(instance.Hypervisor),
				"EbsOptimized":        instance.EbsOptimized,
				"CpuOptions":          instance.CpuOptions,
				"Placement":           instance.Placement,
				"UsageOperation":      aws.ToString(instance.UsageOperation),
				"MetadataOptions":     instance.MetadataOptions,
				"MaintenanceOptions":  instance.MaintenanceOptions,
				"HibernationOptions":  instance.HibernationOptions,
				"InstanceLifecycle":   string(instance.InstanceLifecycle),
				"EnclaveOptions":      instance.EnclaveOptions,
				"TpmSupport":          aws.ToString(instance.TpmSupport),
				"SriovNetSupport":     aws.ToString(instance.SriovNetSupport),
			})
		}
	}

	e.Logger.Debug("evaluating data", instances)

	// Run policy checks
	for _, instance := range instances {
		for _, policyPath := range request.GetPolicyPaths() {
			results, err := policyManager.New(ctx, e.Logger, policyPath).Execute(ctx, "compliance_plugin", instance)
			if err != nil {
				e.Logger.Error("policy evaluation failed", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				errAcc = errors.Join(errAcc, err)
				continue
			}

			// Build and send results (this is also from your existing logic)
			assessmentResult := runner.NewCallableAssessmentResult()
			assessmentResult.Title = "EC2 checks - AWS plugin"

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
							"type":    "aws-cloud",
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
							"type":    "aws-cloud",
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
						Description: fmt.Sprintf("Observed %d violation(s) for policy %s", len(result.Violations), result.Policy.Package.PurePackage()),
						Collected:   timestamppb.New(time.Now()),
						Expires:     timestamppb.New(time.Now().AddDate(0, 1, 0)), // Add one month for the expiration
						RelevantEvidence: []*proto.RelevantEvidence{
							{
								Description: fmt.Sprintf("Policy %v was evaluated, and %d violations were found", result.Policy.Package.PurePackage(), len(result.Violations)),
							},
						},
						Labels: map[string]string{
							"package": string(result.Policy.Package),
							"type":    "aws-cloud",
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
								"type":    "aws-cloud",
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

			assessmentResult.Start = timestamppb.New(startTime)

			var endTime = time.Now()
			assessmentResult.End = timestamppb.New(endTime)

			streamId, err := sdk.SeededUUID(map[string]string{
				"type":    "aws-cloud",
				"_policy": policyPath,
			})
			if err != nil {
				e.Logger.Error("Failed to seedUUID", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				errAcc = errors.Join(errAcc, err)
				continue
			}

			assessmentResult.AddLogEntry(&proto.AssessmentLog_Entry{
				Title:       protolang.String("Template check"),
				Description: protolang.String("Template plugin checks completed successfully"),
				Start:       timestamppb.New(startTime),
				End:         timestamppb.New(endTime),
			})

			err = apiHelper.CreateResult(
				streamId.String(),
				map[string]string{
					"type":    "aws-cloud",
					"_policy": policyPath,
				},
				policyPath,
				assessmentResult.Result())
			if err != nil {
				e.Logger.Error("Failed to add assessment result", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				errAcc = errors.Join(errAcc, err)
			}
		}
	}

	return evalStatus, errAcc
}
