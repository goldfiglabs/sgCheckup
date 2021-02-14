package report

import (
	"database/sql"
	"fmt"

	"github.com/lib/pq"
	"github.com/pkg/errors"
	"goldfiglabs.com/sgcheckup/internal/multirange"

	log "github.com/sirupsen/logrus"
)

type securityGroupRow struct {
	arn                string
	groupName          string
	ips                []string
	inUse              bool
	isDefault          bool
	portRanges         []string
	isLargePublicBlock bool
	largeRangeCount    bool
	isRestricted       bool
	internalOnly       bool
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
	Name      string
	Status    string
	PublicIps []string
	InUse     bool
	IsDefault bool
	Notes     []string
}

type Report = []Row

var defaultSafePorts = []int{22, 80, 443}

func Generate(connectionString string, safePorts []int) (Report, error) {
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to connect to db")
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to ping db")
	}
	log.Info("db ready")
	err = installDbFunctions(db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to install fixture functions")
	}
	rows, err := runSecurityGroupQuery(db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to run analysis query")
	}
	if safePorts == nil {
		safePorts = defaultSafePorts
	}
	report, err := analyzeSecurityGroupResults(rows, safePorts)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate report from query results")
	}
	return report, nil
}

func analyzeSecurityGroupResults(results []securityGroupRow, safePorts []int) ([]Row, error) {
	reportRows := []Row{}
	for _, row := range results {
		var status string
		unsafePorts, err := row.unsafePorts(safePorts)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to calculate unsafe ports")
		}
		if row.isDefault {
			if row.inUse {
				if row.isRestricted || row.internalOnly || len(row.ips) == 0 {
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
				if row.isRestricted || (!row.isProblematic() && unsafePorts.Size() == 0) {
					status = "green"
				} else if len(row.ips) == 0 {
					status = "yellow"
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
	const isRFC1918 = `CREATE OR REPLACE FUNCTION is_rfc1918block(block cidr)
	RETURNS boolean
	LANGUAGE plpgsql
	AS
	$$
	BEGIN
		RETURN
			('192.168.0.0/16' >>= block)
			OR ('172.16.0.0/12' >>= block)
			OR ('10.0.0.0/8' >>= block);
	END;
	$$`

	result, err := db.Exec(isRFC1918)
	if err != nil {
		return err
	}
	log.Infof("result %v", result)
	return nil
}

func runSecurityGroupQuery(db *sql.DB) ([]securityGroupRow, error) {
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
			&row.isLargePublicBlock, &row.largeRangeCount, &row.isRestricted, &row.internalOnly)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to unmarshal a row")
		}
		results = append(results, row)
	}
	log.Infof("rows %v", len(results))
	return results, nil
}

const analysisQuery = `WITH ippermissions AS (
	SELECT
		SG._id,
		bool_or(is_rfc1918block((IP.value->>'CidrIp')::cidr) = false AND masklen((IP.value->>'CidrIp')::cidr) BETWEEN 1 AND 23) AS is_large_public_block,
		bool_and((is_rfc1918block((IP.value->>'CidrIp')::cidr) OR masklen((IP.value->>'CidrIp')::cidr) != 0)) as internal_only,
		COUNT(*) AS range_count
	FROM
		aws_ec2_securitygroup AS SG
		CROSS JOIN LATERAL jsonb_array_elements(SG.ippermissions) AS P
		CROSS JOIN LATERAL jsonb_array_elements(P.value->'IpRanges') AS IP
	GROUP BY SG._id
), permissions AS (
SELECT
	SG._id,
	permissions.* AS permissions
FROM
	aws_ec2_securitygroup AS SG
	CROSS JOIN LATERAL jsonb_array_elements(SG.ippermissions) AS permissions
), raw_ranges AS (
SELECT
	P._id,
	P.value AS permission,
	(R.value ->> 'CidrIp')::cidr AS cidr,
	COALESCE(((P.value ->> 'FromPort')::int), 0) AS from_port,
	COALESCE(((P.value ->> 'ToPort')::int), 65535) AS to_port
FROM
	permissions as P
	CROSS JOIN LATERAL jsonb_array_elements(P.value->'IpRanges') AS R
), public_tcp_ranges AS (
SELECT
	R._id,
	ARRAY_AGG(int4range(R.from_port, R.to_port, '[]')) AS port_ranges
FROM
	raw_ranges AS R
WHERE
	R.from_port <= R.to_port
	AND R.cidr = '0.0.0.0/0'::cidr
	AND R.permission ->> 'IpProtocol' IN ('-1', 'tcp')
GROUP BY R._id
), security_group_attrs AS (
SELECT
	SG._id,
	SG._id IN (SELECT DISTINCT(securitygroup_id) FROM aws_ec2_networkinterface_securitygroup) AS in_use,
	SG.groupname = 'default' AS is_default,
	R.port_ranges,
	COALESCE(IP.is_large_public_block, false) AS is_large_public_block,
	COALESCE(IP.range_count, 0) > 50 AS large_range_count,
	COALESCE(IP.range_count, 0) = 0 AS is_restricted,
	COALESCE(IP.internal_only, true) AS internal_only
FROM
	aws_ec2_securitygroup AS SG
	LEFT JOIN ippermissions AS IP
		ON SG._id = IP._id
	LEFT JOIN public_tcp_ranges AS R
		ON SG._id = R._id
), publicips AS (
	SELECT
		SG._id,
		ARRAY_AGG((NI.association ->> 'PublicIp')::inet) AS ips
	FROM
		aws_ec2_securitygroup AS SG
		INNER JOIN aws_ec2_networkinterface_securitygroup AS NI2SG
			ON SG._id = NI2SG.securitygroup_id
		INNER JOIN aws_ec2_networkinterface AS NI
			ON NI2SG.networkinterface_id = NI._id
	WHERE
		NI.association IS NOT NULL
	GROUP BY
		SG._id
)
SELECT
	SG.uri AS arn,
	SG.groupname,
	COALESCE(P.ips, '{}') AS ips,
	Attrs.in_use,
	Attrs.is_default,
	Attrs.port_ranges,
	-- Attrs.allows_udp,
	-- SG.unsafe_ports,
	Attrs.is_large_public_block,
	Attrs.large_range_count,
	Attrs.is_restricted,
	Attrs.internal_only
	-- SG.ippermissions
FROM
	aws_ec2_securitygroup AS SG
	LEFT JOIN security_group_attrs AS Attrs
		ON SG._id = Attrs._id
	LEFT JOIN publicips AS P
		ON P._id = SG._id
`