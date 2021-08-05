WITH ippermissions AS (
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
), paired_groups AS (
	SELECT
		SG._id,
		G.value ->> 'UserId' AS paired_account,
		jsonb_AGG(jsonb_build_object(
			'Name',
			COALESCE(SG2.groupname, 'Security Group In Account '::text || (G.value ->> 'UserId')),
			'URI',
			SG2.uri,
			'ToPort',
			P.value -> 'ToPort',
			'FromPort',
			P.value -> 'FromPort',
			'IpProtocol',
			P.value -> 'IpProtocol',
			'GroupId',
			G.value -> 'GroupId'
		)) AS paired_security_groups
	FROM
		aws_ec2_securitygroup AS SG
		CROSS JOIN LATERAL jsonb_array_elements(SG.ippermissions) AS P
		CROSS JOIN LATERAL unpack_maybe_array(P.value -> 'UserIdGroupPairs') AS G
		LEFT JOIN aws_ec2_securitygroup AS SG2
			ON SG2.groupid = G.value ->> 'GroupId'
	GROUP BY SG._id, G.value ->> 'UserId'
), external_groups AS (
	SELECT
		PG._id,
		jsonb_object_agg(PG.paired_account, PG.paired_security_groups) AS external_groups
	FROM
		paired_groups AS PG
		INNER JOIN aws_ec2_securitygroup AS SG
			ON SG._id = PG._id
	WHERE
		PG.paired_account != arn_account_id(SG.uri)
	GROUP BY PG._id
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
		SG._id IN (
			SELECT DISTINCT(securitygroup_id) 
			FROM aws_ec2_networkinterface_securitygroup
			UNION
			SELECT DISTINCT(securitygroup_id)
			FROM aws_ec2_securitygroup_vpcpeeringconnection
		) AS in_use,
		SG.groupname = 'default' AS is_default,
		R.port_ranges,
		COALESCE(IP.is_large_public_block, false) AS is_large_public_block,
		COALESCE(IP.range_count, 0) > 50 AS large_range_count,
		COALESCE(IP.range_count, 0) = 0 AS is_restricted,
		COALESCE(IP.internal_only, true) AS internal_only,
		Internal.paired_security_groups,
		COALESCE(E.external_groups, '{}'::jsonb) AS external_groups
	FROM
		aws_ec2_securitygroup AS SG
		LEFT JOIN ippermissions AS IP
			ON SG._id = IP._id
		LEFT JOIN public_tcp_ranges AS R
			ON SG._id = R._id
		LEFT JOIN paired_groups AS Internal
			ON SG._id = Internal._id
			AND arn_account_id(SG.uri) = Internal.paired_account
		LEFT JOIN external_groups AS E
			ON SG._id = E._id
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
	Attrs.is_large_public_block,
	Attrs.large_range_count,
	Attrs.is_restricted,
	Attrs.internal_only,
	Attrs.paired_security_groups,
	Attrs.external_groups
FROM
	aws_ec2_securitygroup AS SG
	LEFT JOIN security_group_attrs AS Attrs
		ON SG._id = Attrs._id
	LEFT JOIN publicips AS P
		ON P._id = SG._id