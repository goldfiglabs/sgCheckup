package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/markbates/pkger"
	"github.com/pkg/errors"

	"github.com/aws/aws-sdk-go-v2/config"

	log "github.com/sirupsen/logrus"

	ds "github.com/goldfiglabs/go-introspector/dockersession"
	"github.com/goldfiglabs/go-introspector/introspector"
	ps "github.com/goldfiglabs/go-introspector/postgres"
	"goldfiglabs.com/sgcheckup/internal/report"
)

type awsAuthError struct {
	Err error
}

func (e *awsAuthError) Error() string {
	return "Failed to find AWS Credentials"
}

func (e *awsAuthError) Unwrap() error {
	return e.Err
}

func loadAwsCredentials(ctx context.Context) ([]string, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, &awsAuthError{err}
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, &awsAuthError{err}
	}
	env := []string{
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%v", creds.AccessKeyID),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%v", creds.SecretAccessKey),
	}
	if len(creds.SessionToken) > 0 {
		env = append(env, fmt.Sprintf("AWS_SESSION_TOKEN=%v", creds.SessionToken))
	}
	return env, nil
}

func printReportRows(report *report.Report) {
	for _, r := range report.Rows {
		fmt.Printf("Name %v Status %v # Public Ips %v In Use %v Is Default %v %v\n",
			r.Name, r.Status, len(r.PublicIps), r.InUse, r.IsDefault, strings.Join(r.Notes, ","))
	}
}

func writeCSVReport(rpReport *report.Report, outputFilename string) error {
	outputFile, err := os.Create(outputFilename)
	if err != nil {
		return errors.Wrapf(err, "Failed to create output file %v", outputFilename)
	}
	defer outputFile.Close()
	writer := csv.NewWriter(outputFile)
	defer writer.Flush()
	writer.Write([]string{"ARN", "Name", "Status", "Public Ips", "In Use", "Is Default", "Notes"})
	for _, row := range rpReport.Rows {
		writer.Write([]string{
			row.Arn,
			row.Name,
			row.Status,
			strings.Join(row.PublicIps, ","),
			strconv.FormatBool(row.InUse),
			strconv.FormatBool(row.IsDefault),
			strings.Join(row.Notes, ", "),
		})
	}
	return nil
}

type templateData struct {
	Report *report.Report
}

func writeHTMLReport(report *report.Report, outputFilename string) error {
	filename := "/templates/security_groups.gohtml"
	f, err := pkger.Open(filename)
	if err != nil {
		return errors.Wrap(err, "Failed to load html template")
	}
	defer f.Close()
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		return errors.Wrap(err, "Failed to read html template")
	}
	t := template.New("sgCheckup")
	t.Funcs(template.FuncMap{
		"yn": func(b bool) string {
			if b {
				return "yes"
			}
			return "no"
		},
		"inc": func(i int) int {
			return i + 1
		},
		"notes": func(s []string) string {
			return strings.Join(s, ", ")
		},
		"ipList": func(ips []string) string {
			if len(ips) == 0 {
				return "-"
			}
			if len(ips) > 8 {
				return strings.Join(ips[:8], ", ") + "...(+" + strconv.Itoa(len(ips)-8) + ")"
			}
			return strings.Join(ips, ", ") + " (" + strconv.Itoa(len(ips)) + ")"
		},
		"humanize": func(t time.Time) string {
			return t.Format(time.RFC1123)
		},
		"portList": func(intPorts []int) string {
			if len(intPorts) == 0 {
				return "-"
			}
			ports := []string{}
			for _, intPort := range intPorts {
				ports = append(ports, strconv.Itoa(intPort))
			}
			return strings.Join(ports, ", ")
		},
	})
	t, err = t.Parse(string(bytes))
	if err != nil {
		return errors.Wrap(err, "Failed to parse template")
	}
	outputFile, err := os.Create(outputFilename)
	if err != nil {
		return errors.Wrapf(err, "Failed to create output file %v", outputFilename)
	}
	defer outputFile.Close()
	err = t.Execute(outputFile, &templateData{Report: report})
	if err != nil {
		return errors.Wrap(err, "Failed to run html template")
	}
	return nil
}

type resourceSpecMap = map[string][]string

var supportedResources resourceSpecMap = map[string][]string{
	"ec2": {"SecurityGroups", "NetworkInterfaces"},
}

func serviceSpec(r resourceSpecMap) string {
	services := []string{}
	for service, resources := range r {
		if resources == nil {
			services = append(services, service)
		} else {
			services = append(services, service+"="+strings.Join(resources, ","))
		}
	}
	return strings.Join(services, ";")
}

func parseSafePorts(s string) ([]int, error) {
	stringPorts := strings.Split(s, ",")
	ports := []int{}
	for _, stringPort := range stringPorts {
		port, err := strconv.Atoi(stringPort)
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func main() {
	pkger.Include("/templates")
	pkger.Include("/queries")
	var skipIntrospector, leavePostgresUp, logIntrospector, reusePostgres, skipIntrospectorPull, printToStdOut bool
	var outputDir, introspectorRef, safePortsList string
	flag.BoolVar(&skipIntrospector, "skip-introspector", false, "Skip running an import, use existing data")
	flag.BoolVar(&leavePostgresUp, "leave-postgres", false, "Leave postgres running in a docker container")
	flag.BoolVar(&reusePostgres, "reuse-postgres", false, "Reuse an existing postgres instance, if it is running")
	flag.BoolVar(&logIntrospector, "log-introspector", false, "Pass through logs from introspector docker image")
	flag.BoolVar(&skipIntrospectorPull, "skip-introspector-pull", false, "Skip pulling the introspector docker image. Allows for using a local image")
	flag.BoolVar(&printToStdOut, "print-to-stdout", false, "Print report results to stdout")
	flag.StringVar(&introspectorRef, "introspector-ref", "", "Override the introspector docker image to use")
	flag.StringVar(&safePortsList, "safe-ports", "22,80,443", "Specify a comma-separated list of ports considered safe. Default is 22,80,443")
	flag.StringVar(&outputDir, "output", "output", "Specify a directory for output")
	flag.Parse()

	ds, err := ds.NewSession()
	if err != nil {
		panic(errors.Wrap(err, "Failed to get docker client. Is it installed?"))
	}
	importer := &ps.DBCredential{
		Username: "introspector",
		Password: "introspector",
	}
	superuser := &ps.DBCredential{
		Username: "postgres",
		Password: "postgres",
	}
	postgresService, err := ps.NewDockerPostgresService(ds, ps.DockerPostgresOptions{
		ReuseExisting:       reusePostgres,
		SuperUserCredential: superuser,
		ContainerName:       "sgCheckup-db",
	})
	if err != nil {
		panic(err)
	}
	shutdownPostgres := func() {
		if !leavePostgresUp {
			err = postgresService.ShutDown()
			if err != nil {
				panic(err)
			}
		}
	}
	if !skipIntrospector {
		awsCreds, err := loadAwsCredentials(ds.Ctx)
		if err != nil {
			var authErr *awsAuthError
			if errors.As(err, &authErr) {
				shutdownPostgres()
				log.Fatal("Failed to find AWS Credentials. Please ensure that your enviroment is correctly configued as described here: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html")
			} else {
				panic(err)
			}
		}
		i, err := introspector.New(ds, postgresService, introspector.Options{
			LogDockerOutput: logIntrospector,
			SkipDockerPull:  skipIntrospectorPull,
			InspectorRef:    introspectorRef,
		})
		if err != nil {
			panic(err)
		}
		spec := serviceSpec(supportedResources)
		log.Infof("Running introspector with service spec %v", spec)
		log.Info("Introspector run may take a few minutes")
		err = i.ImportAWSService(awsCreds, spec)
		if err != nil {
			panic(err)
		}
		err = i.ShutDown()
		if err != nil {
			panic(err)
		}
	}

	safePorts, err := parseSafePorts(safePortsList)
	if err != nil {
		panic(err)
	}
	report, err := report.Generate(postgresService.ConnectionString(importer), report.GenerateOpts{
		SafePorts: safePorts,
	})
	if err != nil {
		panic(err)
	}
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		err = os.Mkdir(outputDir, 0755)
		if err != nil {
			panic(err)
		}
	}
	if printToStdOut {
		printReportRows(report)
	}
	err = writeHTMLReport(report, outputDir+"/index.html")
	if err != nil {
		panic(err)
	}
	err = writeCSVReport(report, outputDir+"/report.csv")
	if err != nil {
		panic(err)
	}
	log.Infof("Reports written to directory %v", outputDir)
	shutdownPostgres()
}
