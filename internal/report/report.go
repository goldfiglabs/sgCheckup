package report

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/markbates/pkger"
	"github.com/pkg/errors"
	"goldfiglabs.com/sgcheckup/internal/multirange"

	log "github.com/sirupsen/logrus"
)

type PairedGroup struct {
	Name       string
	URI        string
	ToPort     int
	FromPort   int
	IpProtocol string
	GroupId    string
}

type PairedGroups []PairedGroup
type ExternalSecurityGroups map[string]PairedGroup

func (pairedGroups *PairedGroups) Scan(value interface{}) error {
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, pairedGroups)
	case string:
		return json.Unmarshal([]byte(v), pairedGroups)
	case nil:
		*pairedGroups = []PairedGroup{}
		return nil
	}
	return errors.New("type assertion failed")
}

func (externalGroups *ExternalSecurityGroups) Scan(value interface{}) error {
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, externalGroups)
	case string:
		return json.Unmarshal([]byte(v), externalGroups)
	case nil:
		*externalGroups = map[string]PairedGroup{}
		return nil
	}
	return errors.New("type assertion failed")
}

type securityGroupRow struct {
	arn                  string
	groupName            string
	ips                  []string
	inUse                bool
	isDefault            bool
	portRanges           []string
	isLargePublicBlock   bool
	largeRangeCount      bool
	isRestricted         bool
	internalOnly         bool
	pairedSecurityGroups PairedGroups
	externalGroups       ExternalSecurityGroups
}

func consoleUrl(arn string) string {
	parts := strings.Split(arn, ":")
	partition := parts[1]
	var console string
	if partition == "aws" {
		console = "console.aws.amazon.com"
	} else if partition == "aws-us-gov" {
		console = "console.amazonaws-us-gov.com"
	} else {
		console = "console.amazonaws.cn"
	}
	region := parts[3]
	groupID := strings.Split(parts[5], "/")[1]
	return "https://" + region + "." + console + "/ec2/v2/home?region=" + region + "#SecurityGroup:groupId=" + groupID
}

func (r *securityGroupRow) isProblematic() bool {
	if r.largeRangeCount {
		return true
	}
	if r.isLargePublicBlock {
		return true
	}
	return false
}

func (r *securityGroupRow) unsafePorts(safePorts []int) (*multirange.MultiRange, error) {
	if len(r.portRanges) > 0 {
		mr, err := multirange.FromString(r.portRanges[0])
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to parse port range %v", r.portRanges)
		}
		for _, port := range safePorts {
			mr.RemoveElement(port)
		}
		return mr, nil
	}
	return &multirange.MultiRange{}, nil
}

func (r *securityGroupRow) notes(unsafePorts *multirange.MultiRange) []string {
	notes := []string{}
	if unsafePorts.Size() > 0 && !r.internalOnly {
		notes = append(notes, fmt.Sprintf("Allows traffic from anywhere on TCP ports (%v)", unsafePorts.Humanize()))
	}
	if r.isLargePublicBlock {
		notes = append(notes, "Has IP restrictions, but they let through large ranges")
	}
	if r.largeRangeCount {
		notes = append(notes, "Uses a lot of IP Ranges")
	}
	if !r.inUse {
		notes = append(notes, "Not in use")
	}
	if len(r.ips) > 0 {
		notes = append(notes, fmt.Sprintf("Contains %v public IP address(es)", len(r.ips)))
	} else {
		notes = append(notes, "No public IP addresses found")
	}
	return notes
}

type Row struct {
	Arn       string
	Url       string
	Name      string
	Status    string
	PublicIps []string
	InUse     bool
	IsDefault bool
	Notes     []string
}

// Metadata includes information about the report, such as when the data was
// snapshotted and for what account
type Metadata struct {
	Imported     time.Time
	Generated    time.Time
	Account      string
	Organization string
	SafePorts    []int
}

type Report struct {
	Metadata *Metadata
	Rows     []Row
}

type GenerateOpts struct {
	SafePorts []int
}

func (o *GenerateOpts) fillInDefaults() {
	if o.SafePorts == nil {
		o.SafePorts = []int{}
	}
}

// Generate uses a connection string to postgres and a list of designated-safe ports
// to produce a report assessing the risk of each security group that has been imported.
func Generate(connectionString string, opts GenerateOpts) (*Report, error) {
	opts.fillInDefaults()
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to connect to db")
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to ping db")
	}
	err = installDbFunctions(db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to install fixture functions")
	}
	rows, err := runSecurityGroupQuery(db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to run analysis query")
	}
	reportRows, err := analyzeSecurityGroupResults(rows, opts.SafePorts)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate report from query results")
	}
	sort.SliceStable(reportRows, func(i, j int) bool {
		return sortRowsLess(&reportRows[i], &reportRows[j])
	})
	metadata, err := loadMetadata(db, reportRows, opts.SafePorts)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load metadata")
	}
	return &Report{
		Rows:     reportRows,
		Metadata: metadata,
	}, nil
}

var statusIndex map[string]int = map[string]int{
	"red":    0,
	"yellow": 1,
	"green":  2,
}

func arnRegion(arn string) string {
	parts := strings.Split(arn, ":")
	return parts[3]
}

func loadMetadata(db *sql.DB, reportRows []Row, safePorts []int) (*Metadata, error) {
	query, err := loadQuery("most_recent_import")
	if err != nil {
		return nil, errors.Wrap(err, "failed to load query")
	}
	queryRows, err := db.Query(query)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to query for most recent import")
	}
	defer queryRows.Close()
	if !queryRows.Next() {
		return nil, errors.New("Query for most recent import job found no results")
	}
	var endDate time.Time
	var organization string
	err = queryRows.Scan(&endDate, &organization)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read most recent import job row")
	}
	arn := reportRows[0].Arn
	parts := strings.Split(arn, ":")
	accountID := parts[4]
	if strings.HasPrefix(organization, "OrgDummy") {
		organization = "<NONE>"
	}
	return &Metadata{
		Imported:     endDate,
		Generated:    time.Now(),
		Account:      accountID,
		Organization: organization,
		SafePorts:    safePorts,
	}, nil
}

// Sort by status first, then region, then name
func sortRowsLess(a, b *Row) bool {
	if a.Status == b.Status {
		aRegion := arnRegion(a.Arn)
		bRegion := arnRegion(b.Arn)
		if aRegion == bRegion {
			return a.Name < b.Name
		}
		return aRegion < bRegion
	}
	aIndex := statusIndex[a.Status]
	bIndex := statusIndex[b.Status]
	return aIndex < bIndex
}

func analyzeSecurityGroupResults(results []securityGroupRow, safePorts []int) ([]Row, error) {
	reportRows := []Row{}
	for _, row := range results {
		var status string
		unsafePorts, err := row.unsafePorts(safePorts)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to calculate unsafe ports")
		}
		externalGroupCount := len(row.externalGroups)
		if row.isDefault {
			if row.inUse {
				if externalGroupCount == 0 && (row.isRestricted || row.internalOnly || len(row.ips) == 0) {
					status = "yellow"
				} else {
					status = "red"
				}
			} else {
				if row.isRestricted {
					// best case for default groups, locked down and not in use
					status = "green"
				} else {
					status = "yellow"
				}
			}
		} else {
			if row.inUse {
				if externalGroupCount == 0 {
					if row.isRestricted || (!row.isProblematic() && unsafePorts.Size() == 0) {
						status = "green"
					} else if len(row.ips) == 0 {
						status = "yellow"
					} else {
						status = "red"
					}
				} else {
					status = "red"
				}
			} else {
				// Not the default, so shouldn't exist if it's not in use
				status = "yellow"
			}
		}
		reportRows = append(reportRows, Row{
			Arn:       row.arn,
			Url:       consoleUrl(row.arn),
			Name:      row.groupName,
			Status:    status,
			PublicIps: row.ips,
			InUse:     row.inUse,
			IsDefault: row.isDefault,
			Notes:     row.notes(unsafePorts),
		})
	}
	return reportRows, nil
}

func installDbFunctions(db *sql.DB) error {
	isRFC1918, err := loadQuery("rfc1918")
	if err != nil {
		return errors.New("Failed to load sql for is_rfc1918block")
	}
	_, err = db.Exec(isRFC1918)
	if err != nil {
		return err
	}
	return nil
}

func runSecurityGroupQuery(db *sql.DB) ([]securityGroupRow, error) {
	analysisQuery, err := loadQuery("security_groups")
	if err != nil {
		return nil, errors.Wrap(err, "Failed to to load analysis query")
	}
	rows, err := db.Query(analysisQuery)
	if err != nil {
		return nil, errors.Wrap(err, "DB error analyzing")
	}
	defer rows.Close()
	results := make([]securityGroupRow, 0)
	for rows.Next() {
		row := securityGroupRow{}
		err = rows.Scan(&row.arn, &row.groupName, pq.Array(&row.ips), &row.inUse, &row.isDefault,
			pq.Array(&row.portRanges),
			&row.isLargePublicBlock, &row.largeRangeCount, &row.isRestricted, &row.internalOnly, &row.pairedSecurityGroups, &row.externalGroups)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to unmarshal a row")
		}
		results = append(results, row)
	}
	log.Infof("# Report Rows: %v", len(results))
	return results, nil
}

func loadQuery(name string) (string, error) {
	filename := "/queries/" + name + ".sql"
	f, err := pkger.Open(filename)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to open %v", filename)
	}
	defer f.Close()
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to read %v", filename)
	}
	return string(bytes), nil
}
