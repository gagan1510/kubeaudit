package commands

import (
	"io"
	"os"

	"github.com/gagan1510/kubeaudit/auditors/all"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var autofixConfig struct {
	outFile             string
	kubeauditConfigFile string
}

func autofix(cmd *cobra.Command, args []string) {
	conf := loadKubeAuditConfigFromFile(autofixConfig.kubeauditConfigFile)

	conf = setConfigFromFlags(cmd, conf)

	auditors, err := all.Auditors(conf)

	if err != nil {
		log.WithError(err).Fatal("Error creating auditors")
	}

	report := getReport(auditors...)

	var f io.Writer
	if autofixConfig.outFile != "" {
		f, err = os.Create(autofixConfig.outFile)
		if err != nil {
			log.WithError(err).Fatal("Error opening out file")
		}
	} else {
		f, err = os.OpenFile(rootConfig.manifest, os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			log.WithError(err).Fatal("Error opening manifest file")
		}
	}

	err = report.Fix(f)
	if err != nil {
		log.WithError(err).Fatal("Error fixing manifest")
	}
}

var autofixCmd = &cobra.Command{
	Use:   "autofix",
	Short: "Automagically make a manifest secure",
	Long: `This command automatically fixes all identified security issues for a given manifest
(ie. all ERROR results generated by 'kubeaudit all'). If no output file is specified using the -o flag,
the source manifest will be modified. You can use the -k flag followed by the path to the kubeaudit
config file to run fixes based on custom rules.

Example usage:
kubeaudit autofix -f /path/to/yaml
kubeaudit autofix -f /path/to/yaml -o /path/for/fixed/yaml
kubeaudit autofix -k /path/to/kubeaudit-config.yaml -f /path/to/yaml
`,
	Run: autofix,
}

func init() {
	RootCmd.AddCommand(autofixCmd)
	autofixCmd.Flags().StringVarP(&autofixConfig.outFile, "outfile", "o", "", "File to write fixed manifest to")
	autofixCmd.Flags().StringVarP(&autofixConfig.kubeauditConfigFile, "kconfig", "k", "", "Path to kubeaudit config")
}
