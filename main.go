package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"sort"
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
	"goldfiglabs.com/sgcheckup/internal/nmap"
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
	err = writer.Write([]string{"ARN", "Name", "Status", "Public Ips", "In Use", "Is Default", "Notes"})
	if err != nil {
		return errors.Wrapf(err, "Failed to write headers to %v", outputFilename)
	}
	for _, row := range rpReport.Rows {
		err = writer.Write([]string{
			row.Arn,
			row.Name,
			row.Status,
			strings.Join(row.PublicIps, ","),
			strconv.FormatBool(row.InUse),
			strconv.FormatBool(row.IsDefault),
			strings.Join(row.Notes, ", "),
		})
		if err != nil {
			return errors.Wrapf(err, "Failed to write row to %v", outputFilename)
		}
	}
	return nil
}

func writeNMapCSVReport(scanResults nmap.IpScanResults, outputFilename string) error {
	outputFile, err := os.Create(outputFilename)
	if err != nil {
		return errors.Wrapf(err, "Failed to create output file %v", outputFilename)
	}
	defer outputFile.Close()
	writer := csv.NewWriter(outputFile)
	defer writer.Flush()
	err = writer.Write([]string{"IP", "Port", "Service", "Security Group(s)"})
	if err != nil {
		return errors.Wrapf(err, "Failed to write headers to %v", outputFilename)
	}
	for ipAddr, ports := range scanResults {
		for port, portScan := range ports {
			err = writer.Write([]string{
				ipAddr,
				strconv.Itoa(int(port)),
				portScan.Service.Display(),
				strings.Join(portScan.SecurityGroups, ", "),
			})
			if err != nil {
				return errors.Wrapf(err, "Failed writing row to %v", outputFilename)
			}
		}
	}
	return nil
}

type nmapTemplateData struct {
	Metadata *report.Metadata
	Ports    []portRow
}

type Group struct {
	GroupId string
	Name    string
	Last    bool
}

type SGDisplay struct {
	Len    int
	Groups []Group
}

type portRow struct {
	First     bool
	IP        string
	Port      uint16
	Service   string
	SGDisplay SGDisplay
}

func toSGDisplay(rows []report.Row, sgIds []string) SGDisplay {
	groups := []Group{}
	for i, sgId := range sgIds {
		for _, row := range rows {
			if row.GroupID == sgId {
				groups = append(groups, Group{
					GroupId: sgId,
					Name:    row.Name,
					Last:    i == len(sgIds)-1,
				})
				break
			}
		}
	}
	return SGDisplay{
		Len:    len(sgIds),
		Groups: groups,
	}
}

func toPortRows(report *report.Report, sr nmap.IpScanResults) []portRow {
	rows := []portRow{}
	for ipAddr, portMap := range sr {
		ipPorts := []portRow{}
		for port, scanResult := range portMap {
			ipPorts = append(ipPorts, portRow{
				First:     false,
				IP:        ipAddr,
				Port:      port,
				Service:   scanResult.Service.Display(),
				SGDisplay: toSGDisplay(report.Rows, scanResult.SecurityGroups),
			})
		}
		sort.Slice(ipPorts[:], func(i, j int) bool {
			return ipPorts[i].Port < ipPorts[j].Port
		})
		ipPorts[0].First = true
		rows = append(rows, ipPorts...)
	}
	return rows
}

func writeNMapReport(report *report.Report, outputFilename string, scanResults nmap.IpScanResults) error {
	filename := "/templates/nmap_scan.html"
	f, err := pkger.Open(filename)
	if err != nil {
		return errors.Wrap(err, "Failed to load nmap html template")
	}
	defer f.Close()
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		return errors.Wrap(err, "Failed to read nmap html template")
	}
	t := template.New("sgCheckup-nmap")
	t.Funcs(template.FuncMap{
		"humanize": func(t time.Time) string {
			return t.Local().Format("2006-01-02 15:04:05")
		},
		"inc": func(i int) int {
			return i + 1
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
	err = t.Execute(outputFile, &nmapTemplateData{
		Metadata: report.Metadata,
		Ports:    toPortRows(report, scanResults),
	})
	if err != nil {
		return errors.Wrap(err, "Failed to run nmap html template")
	}
	return nil
}

type templateData struct {
	Metadata    report.Metadata
	Rows        []templateRow
	NMapSkipped bool
}

type templateRow struct {
	report.Row
	Ips ipList
}

type ipList struct {
	Len      int
	Subset   []string
	Overflow bool
}

func makeTemplateRows(reportRows []report.Row) []templateRow {
	rows := []templateRow{}
	for _, reportRow := range reportRows {
		numIps := len(reportRow.PublicIps)
		cap := numIps
		if cap >= 8 {
			cap = 8
		}
		tr := templateRow{
			reportRow,
			ipList{
				Len:      numIps,
				Subset:   reportRow.PublicIps[:cap],
				Overflow: numIps > 8,
			},
		}
		rows = append(rows, tr)
	}
	return rows
}

func writeHTMLReport(report *report.Report, outputFilename string, nmapSkipped bool) error {
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
			return t.Local().Format("2006-01-02 15:04:05")
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
	err = t.Execute(outputFile, &templateData{
		Metadata:    *report.Metadata,
		Rows:        makeTemplateRows(report.Rows),
		NMapSkipped: nmapSkipped,
	})
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
	ports := []int{}
	if s == "" {
		return ports, nil
	}
	stringPorts := strings.Split(s, ",")
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
	// introspector options
	var skipIntrospector, logIntrospector, skipIntrospectorPull bool
	var introspectorRef string
	flag.BoolVar(&skipIntrospector, "skip-introspector", false, "Skip running an import, use existing data")
	flag.BoolVar(&logIntrospector, "log-introspector", false, "Pass through logs from introspector docker image")
	flag.BoolVar(&skipIntrospectorPull, "skip-introspector-pull", false, "Skip pulling the introspector docker image. Allows for using a local image")
	flag.StringVar(&introspectorRef, "introspector-ref", "", "Override the introspector docker image to use")
	// postgres options
	var leavePostgresUp, reusePostgres bool
	flag.BoolVar(&leavePostgresUp, "leave-postgres", false, "Leave postgres running in a docker container")
	flag.BoolVar(&reusePostgres, "reuse-postgres", false, "Reuse an existing postgres instance, if it is running")
	// report options
	var safePortsList string
	flag.StringVar(&safePortsList, "safe-ports", "22,80,443", "Specify a comma-separated list of ports considered safe. Default is 22,80,443")
	// nmap options
	var extraNMapArgs, nMapDockerRef string
	var nativeNMap, skipNMap bool
	flag.BoolVar(&skipNMap, "skip-nmap", false, "Skip generating nmap scripts")
	flag.BoolVar(&nativeNMap, "native-nmap", false, "Use natively-installed nmap in nmap scripts, rather than a docker image")
	flag.StringVar(&nMapDockerRef, "nmap-docker-ref", "", "Override the docker image used for nmap")
	flag.StringVar(&extraNMapArgs, "nmap-args", "", "Extra arguments to be provided to nmap")
	// output options
	var outputDir string
	var printToStdOut bool
	flag.BoolVar(&printToStdOut, "print-to-stdout", false, "Print report results to stdout")
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
	if !skipNMap {
		log.Info("Running nmap scan")
		_, err = nmap.RunScan(ds, outputDir, report)
		if err != nil {
			panic(err)
		}
		scanResults, err := nmap.ReadScanResults(outputDir + "/nmap/results")
		if err != nil {
			panic(err)
		}
		err = writeNMapReport(report, outputDir+"/nmap.html", scanResults)
		if err != nil {
			panic(err)
		}
		err = writeNMapCSVReport(scanResults, outputDir+"/nmap.csv")
		if err != nil {
			panic(err)
		}
	}
	err = writeHTMLReport(report, outputDir+"/index.html", skipNMap)
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
