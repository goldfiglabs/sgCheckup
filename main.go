package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

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

func main() {
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
	printReportRows(report)
	if !leavePostgresUp {
		err = postgresService.ShutDown()
		if err != nil {
			panic(err)
		}
	}
}
