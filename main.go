package main

import (
	"context"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/markbates/pkger"
	"github.com/pkg/errors"

	"github.com/aws/aws-sdk-go-v2/config"

	log "github.com/sirupsen/logrus"

	ds "goldfiglabs.com/sgcheckup/internal/dockersession"
	"goldfiglabs.com/sgcheckup/internal/introspector"
	ps "goldfiglabs.com/sgcheckup/internal/postgres"
	"goldfiglabs.com/sgcheckup/internal/report"
)

func loadAwsCredentials(ctx context.Context) ([]string, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
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

func printReportRows(rows []report.Row) {
	log.Infof("Report rows %v", len(rows))
	for _, r := range rows {
		fmt.Printf("Name %v Status %v # Public Ips %v In Use %v Is Default %v %v\n",
			r.Name, r.Status, len(r.PublicIps), r.InUse, r.IsDefault, strings.Join(r.Notes, ","))
	}
}

type templateData struct {
	Report report.Report
}

func writeHtmlReport(report report.Report, outputFilename string) error {
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
				return "<NONE>"
			}
			if len(ips) > 8 {
				return strings.Join(ips[:8], ", ") + "...(+" + strconv.Itoa(len(ips)-8) + ")"
			}
			return strings.Join(ips, ", ") + " (" + strconv.Itoa(len(ips)) + ")"
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

func main() {
	pkger.Include("/templates")
	pkger.Include("/queries")
	var skipIntrospector, leavePostgresUp, reusePostgres bool
	flag.BoolVar(&skipIntrospector, "skip-introspector", false, "Skip running an import, use existing data")
	flag.BoolVar(&leavePostgresUp, "leave-postgres", false, "Leave postgres running in a docker container")
	flag.BoolVar(&reusePostgres, "reuse-postgres", false, "Reuse an existing postgres instance, if it is running")
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
	})
	if err != nil {
		panic(err)
	}
	if !skipIntrospector {
		awsCreds, err := loadAwsCredentials(ds.Ctx)
		if err != nil {
			panic(err)
		}
		i, err := introspector.New(ds, postgresService)
		if err != nil {
			panic(err)
		}
		err = i.ImportAWSService(awsCreds, "ec2=SecurityGroups,NetworkInterfaces")
		if err != nil {
			panic(err)
		}
		err = i.ShutDown()
		if err != nil {
			panic(err)
		}
	}
	report, err := report.Generate(postgresService.ConnectionString(importer), nil)
	if err != nil {
		panic(err)
	}
	// printReportRows(report)
	err = writeHtmlReport(report, "index.html")
	if err != nil {
		panic(err)
	}
	if !leavePostgresUp {
		err = postgresService.ShutDown()
		if err != nil {
			panic(err)
		}
	}
}
