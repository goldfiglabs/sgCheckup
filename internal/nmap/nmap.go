package nmap

import (
	"encoding/xml"
	"html/template"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	log "github.com/sirupsen/logrus"

	ds "github.com/goldfiglabs/go-introspector/dockersession"
	"github.com/markbates/pkger"
	"github.com/markbates/pkger/pkging"
	"github.com/pkg/errors"
	"goldfiglabs.com/sgcheckup/internal/report"
)

const defaultNMapDockerRef = "jefftadashi/nmap"

func copyRunScan(outputDir string) error {
	src := "/templates/run_scan.sh"
	f, err := pkger.Open(src)
	if err != nil {
		return errors.Wrap(err, "Failed to load run all shell script")
	}
	defer f.Close()
	dstFilename := outputDir + "/run_scan.sh"
	return copyTemplate(f, dstFilename)
}

func copyTemplate(f pkging.File, dstFilename string) error {
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

func RunScan(ds *ds.Session, outputDir string, report *report.Report) (interface{}, error) {
	volumeRoot := outputDir + "/nmap"
	if _, err := os.Stat(volumeRoot); os.IsNotExist(err) {
		err = os.Mkdir(volumeRoot, 0755)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to create nmap docker volume directory")
		}
	}
	err := copyRunScan(volumeRoot)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to copy run_scan")
	}
	dir, err := os.Getwd()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get working directory")
	}
	written, err := writeGroupScans(volumeRoot, report)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to write scan scripts")
	}
	if written {
		_, err = runNMap(ds, dir+"/"+volumeRoot)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to run nmap scan")
		}
	} else {
		log.Warn("Skipping NMap, no groups had public IPs and unsafe ports")
	}
	return nil, nil
}

type groupScanTemplateData struct {
	Bin        string
	OutputFile string
	Ports      string
	Targets    string
	Speed      string
}

func writeGroupScans(outputDir string, report *report.Report) (bool, error) {
	scriptDir := outputDir + "/groups"
	if _, err := os.Stat(scriptDir); os.IsNotExist(err) {
		err = os.Mkdir(scriptDir, 0755)
		if err != nil {
			return false, errors.Wrap(err, "Failed to create groups directory")
		}
	}
	resultsDir := outputDir + "/results"
	if _, err := os.Stat(resultsDir); os.IsNotExist(err) {
		err = os.Mkdir(resultsDir, 0755)
		if err != nil {
			return false, errors.Wrap(err, "Failed to create results directory")
		}
	}
	templateFilename := "/templates/scan_group.gosh"
	f, err := pkger.Open(templateFilename)
	if err != nil {
		return false, errors.Wrap(err, "Failed to open group template file")
	}
	defer f.Close()
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		return false, errors.Wrap(err, "Failed to read group template file")
	}
	t := template.New("nmap-security-group")
	t, err = t.Parse(string(bytes))
	if err != nil {
		return false, errors.Wrap(err, "Failed to load group template")
	}
	written := false
	for _, row := range report.Rows {
		if len(row.PublicIps) == 0 || row.UnsafePorts.Size() == 0 {
			continue
		}
		written = true
		filename := scriptDir + "/" + row.GroupID + ".sh"
		err = writeScanGroup(t, filename, &row)
		if err != nil {
			return false, err
		}
	}
	return written, nil
}

func writeScanGroup(t *template.Template, filename string, row *report.Row) error {
	outputFile, err := os.Create(filename)
	if err != nil {
		return errors.Wrapf(err, "Failed to create file %v", filename)
	}
	defer outputFile.Close()
	err = outputFile.Chmod(0755)
	if err != nil {
		return errors.Wrapf(err, "Failed to chmod file %v", filename)
	}
	speed := "2"
	if row.UnsafePorts.Size() * len(row.PublicIps) > 20 {
		speed = "4"
	}
	t.Execute(outputFile, &groupScanTemplateData{
		Bin:        "nmap",
		OutputFile: "/opt/sgCheckup/results/" + row.GroupID + ".xml",
		Targets:    strings.Join(row.PublicIps, " "),
		Ports:      "-p T:" + row.UnsafePorts.Humanize(),
		Speed:      speed,
	})
	if err != nil {
		return errors.Wrapf(err, "Failed to execute template for %v", filename)
	}
	return nil
}

func runNMap(ds *ds.Session, volumeRoot string) (interface{}, error) {
	ref := "jefftadashi/nmap"
	err := ds.RequireImage(ref)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to load docker image %v", ref)
	}
	containerName := "sgCheckup-nmap"
	existingContainer, err := ds.FindContainer(containerName)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to list existing containers")
	}
	if existingContainer != nil {
		err = ds.StopAndRemoveContainer(existingContainer.ID)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to remove existing container")
		}
	}
	nmapContainer, err := ds.Client.ContainerCreate(ds.Ctx, &container.Config{
		Image:      ref,
		Cmd:        []string{"/opt/sgCheckup/run_scan.sh"},
		Entrypoint: []string{},
	}, &container.HostConfig{
		NetworkMode: "host",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: volumeRoot,
				Target: "/opt/sgCheckup",
			},
		},
	}, &network.NetworkingConfig{},
		nil,
		containerName,
	)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create nmap container")
	}
	err = ds.Client.ContainerStart(ds.Ctx, nmapContainer.ID, types.ContainerStartOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to start nmap container")
	}
	ch, errCh := ds.Client.ContainerWait(ds.Ctx, nmapContainer.ID, container.WaitConditionNextExit)
	select {
	case <-ch:
		break
	case err := <-errCh:
		return nil, errors.Wrap(err, "Failed waiting for container")

	case <-ds.Ctx.Done():
		return nil, errors.Wrap(ds.Ctx.Err(), "Context failed waiting for container")
	}
	return nil, nil
}

type xmlHostname struct {
	Name string `xml:"name,attr"`
}

type xmlHostnames struct {
	Hostname []xmlHostname `xml:"hostname"`
}

type xmlHostStatus struct {
	State string `xml:"state,attr"`
}

type xmlHostAddress struct {
	Addr string `xml:"addr,attr"`
}

type xmlPortState struct {
	State string `xml:"state,attr"`
}

type xmlService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

func (s *xmlService) Display() string {
	d := s.Name
	if s.Product != "" {
		d += " - " + s.Product
		if s.Version != "" {
			d += " (" + s.Version + ")"
		}
	}
	return d
}

type xmlPort struct {
	PortID  string       `xml:"portid,attr"`
	State   xmlPortState `xml:"state"`
	Service *xmlService  `xml:"service"`
}

func (p *xmlPort) ToScanResult() PortScanResult {
	return PortScanResult{
		Service:        p.Service,
		Status:         p.State.State,
		SecurityGroups: []string{},
	}
}

type xmlHostPorts struct {
	Port []xmlPort `xml:"port"`
}

type xmlScanHost struct {
	Status    xmlHostStatus  `xml:"status"`
	Address   xmlHostAddress `xml:"address"`
	Hostnames xmlHostnames   `xml:"hostnames"`
	Ports     xmlHostPorts   `xml:"ports"`
}

func (sh *xmlScanHost) ToGroupHostResult() (string, *groupHostResult, error) {
	hostnames := []string{}
	for _, hostname := range sh.Hostnames.Hostname {
		hostnames = append(hostnames, hostname.Name)
	}
	ports := map[uint16]PortScanResult{}
	for _, port := range sh.Ports.Port {
		port64, err := strconv.ParseUint(port.PortID, 10, 16)
		if err != nil {
			return "", nil, errors.Wrapf(err, "Failed to parse port %v", port.PortID)
		}
		ports[uint16(port64)] = port.ToScanResult()
	}
	return sh.Address.Addr, &groupHostResult{
		Hostnames: hostnames,
		Ports:     ports,
	}, nil
}

type xmlNMapRun struct {
	Hosts []xmlScanHost `xml:"host"`
}

type groupHostResult struct {
	Ports     map[uint16]PortScanResult
	Hostnames []string
}

type groupScanResult = map[string]groupHostResult

func readScanResult(filename string) (groupScanResult, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to read %v", filename)
	}
	nmr := xmlNMapRun{}
	err = xml.Unmarshal(bytes, &nmr)
	if err != nil {
		return nil, errors.Wrapf(err, "xml unmarshall failed for %v", filename)
	}
	results := make(groupScanResult)
	for _, h := range nmr.Hosts {
		addr, result, err := h.ToGroupHostResult()
		if err != nil {
			return nil, err
		}
		results[addr] = *result
	}
	return results, nil
}

// Result types
type IPAddr = string

type PortScanResult struct {
	Status         string
	Service        *xmlService
	SecurityGroups []string
}

type PortMap = map[uint16]PortScanResult
type IpScanResults = map[IPAddr]PortMap

func ReadScanResults(resultsDir string) (IpScanResults, error) {
	files, err := ioutil.ReadDir(resultsDir)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to list %v", resultsDir)
	}
	results := make(IpScanResults)
	for _, file := range files {
		parts := strings.Split(file.Name(), "/")
		groupName := strings.TrimSuffix(parts[len(parts)-1], ".xml")
		groupResult, err := readScanResult(resultsDir + "/" + file.Name())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to read %v", file.Name())
		}
		for addr := range groupResult {
			newResults := groupResult[addr]
			existingResults, exists := results[addr]
			if !exists {
				existingResults = make(map[uint16]PortScanResult)
			}
			for port, scanResult := range newResults.Ports {
				existingPortScanResults, ok := existingResults[port]
				if !ok {
					scanResult.SecurityGroups = append(scanResult.SecurityGroups, groupName)
					existingPortScanResults = scanResult
				} else {
					existingPortScanResults.SecurityGroups = append(existingPortScanResults.SecurityGroups, groupName)
				}
				existingResults[port] = existingPortScanResults
			}
			results[addr] = existingResults
		}
	}
	return results, nil
}
