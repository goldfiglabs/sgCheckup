package nmap

import (
	"html/template"
	"io/ioutil"
	"os"
	"strings"

	"github.com/markbates/pkger"
	"github.com/pkg/errors"
	"goldfiglabs.com/sgcheckup/internal/report"
)

type templateData struct {
	Bin       string
	Targets   string
	Ports     string
	ExtraArgs string
}

const defaultNMapDockerRef = "broadinstitute/nmap"

type ScriptOptions struct {
	UseNative bool
	DockerRef string
	ExtraArgs string
}

func (o *ScriptOptions) fillInDefaults() {
	if !o.UseNative && o.DockerRef == "" {
		o.DockerRef = defaultNMapDockerRef
	}
}

func (o *ScriptOptions) bin() string {
	if o.UseNative {
		return "nmap"
	}
	return "docker run --rm -it --network host " + o.DockerRef
}

func scriptTemplate() (*template.Template, error) {
	filename := "/templates/security_group.gosh"
	f, err := pkger.Open(filename)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load shell script template")
	}
	defer f.Close()
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read shell script template")
	}
	t := template.New("sgCheckup-nmap")
	t, err = t.Parse(string(bytes))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse template")
	}
	return t, nil
}

func writeScript(outputDir string, t *template.Template, opts *ScriptOptions, row *report.Row) (bool, error) {
	if len(row.PublicIps) == 0 || row.UnsafePorts.Size() == 0 {
		return false, nil
	}
	outputFilename := outputDir + "/nmap-" + row.GroupID + ".sh"
	outputFile, err := os.Create(outputFilename)
	if err != nil {
		return false, errors.Wrapf(err, "Failed to create output file %v", outputFilename)
	}
	defer outputFile.Close()
	err = outputFile.Chmod(0755)
	if err != nil {
		return false, errors.Wrapf(err, "Failed setting file permissions on %v", outputFilename)
	}
	err = t.Execute(outputFile, &templateData{
		Bin:       opts.bin(),
		Targets:   strings.Join(row.PublicIps, ","),
		Ports:     "-p T:" + row.UnsafePorts.Humanize(),
		ExtraArgs: opts.ExtraArgs,
	})
	if err != nil {
		return false, errors.Wrap(err, "Failed to run shell script template")
	}

	return true, nil
}

func copyRunAll(outputDir string) error {
	src := "/templates/nmap_all.sh"
	f, err := pkger.Open(src)
	if err != nil {
		return errors.Wrap(err, "Failed to load run all shell script")
	}
	defer f.Close()
	dstFilename := outputDir + "/nmap_all.sh"
	dstFile, err := os.Create(dstFilename)
	if err != nil {
		return errors.Wrapf(err, "Failed to create output file %v", dstFilename)
	}
	defer dstFile.Close()
	err = dstFile.Chmod(0755)
	if err != nil {
		return errors.Wrapf(err, "Failed setting file permissions on %v", dstFilename)
	}
	_, err = dstFile.ReadFrom(f)
	if err != nil {
		return errors.Wrap(err, "Failed to write shell script")
	}
	return nil
}

func WriteScripts(outputDir string, report *report.Report, opts ScriptOptions) error {
	opts.fillInDefaults()
	t, err := scriptTemplate()
	if err != nil {
		return err
	}
	anyWritten := false
	for _, row := range report.Rows {
		written, err := writeScript(outputDir, t, &opts, &row)
		if err != nil {
			return err
		}
		if written {
			anyWritten = true
		}
	}
	if anyWritten {
		err = copyRunAll(outputDir)
		if err != nil {
			return err
		}
	}
	return nil
}
