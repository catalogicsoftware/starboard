package cmd

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/plugin"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/aquasecurity/starboard/pkg/trivymisconfig"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewScanMisconfigurationReportsCmd(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"misconfigs", "misconfig"},
		Use:     "misconfigurationreports (NAME | TYPE/NAME)",
		RunE:    ScanMisconfigurationReports(buildInfo, cf),
	}

	registerScannerOpts(cmd)

	return cmd
}

func ScanMisconfigurationReports(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		ns, _, err := cf.ToRawKubeConfigLoader().Namespace()
		if err != nil {
			return err
		}
		mapper, err := cf.ToRESTMapper()
		if err != nil {
			return err
		}
		workload, _, err := WorkloadFromArgs(mapper, ns, args)
		if err != nil {
			return err
		}
		kubeConfig, err := cf.ToRESTConfig()
		if err != nil {
			return err
		}
		kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			return err
		}
		scheme := starboard.NewScheme()
		kubeClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
		if err != nil {
			return err
		}
		config, err := starboard.NewConfigManager(kubeClientset, starboard.NamespaceName).Read(ctx)
		if err != nil {
			return err
		}
		opts, err := getScannerOpts(cmd)
		if err != nil {
			return err
		}
		plugin, pluginContext, err := plugin.NewResolver().
			WithBuildInfo(buildInfo).
			WithNamespace(starboard.NamespaceName).
			WithServiceAccountName(starboard.ServiceAccountName).
			WithConfig(config).
			WithClient(kubeClient).
			GetTrivyMisconfigPlugin()
		if err != nil {
			return err
		}
		scanner := trivymisconfig.NewScanner(kubeClientset, kubeClient, plugin, pluginContext, config, opts)
		reports, err := scanner.Scan(ctx, workload)
		if err != nil {
			return err
		}
		fmt.Println(reports)
		// writer := trivymisconfig.NewReadWriter(kubeClient)
		return nil
	}
}
