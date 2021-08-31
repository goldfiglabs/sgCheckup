# sgCheckup - Check your Security Groups for Unexpected Open Ports & Generate nmap Output

![sgcheckup copy](https://user-images.githubusercontent.com/291215/131573778-34207ba3-35a1-4af4-b3a6-39e32cb806b0.png)

`sgCheckup` is a tool to scan your AWS Security Groups for a combination of open ports and attached Network Interfaces. The goal is to find anything listening on a port that you wouldn't consider safe. In addition to generating reports for security groups, `sgCheckup` can generate and run `nmap` to get specifics.

## Why?

Security Groups are an important line of defense for your infrastructure, but as you make changes, it's easy to forget to revert some quick fix that was made to get something working. Having a view into what ports are open and what's listening can help you prioritize locking down access. 

## Pre-requisites

* AWS Credentials (`~/.aws/`, `AWS_*` environment variables, metadata server, etc.)
* Docker
* If running from source, go version >= go1.15

## Installation Options

1. Download the latest [release](https://github.com/goldfiglabs/sgCheckup/releases):

Linux:
```
    curl -Lo sgCheckup https://github.com/goldfiglabs/sgCheckup/releases/latest/download/sgCheckup_linux
    chmod a+x ./sgCheckup
```

OSX x86:
```
    curl -Lo sgCheckup https://github.com/goldfiglabs/sgCheckup/releases/latest/download/sgCheckup_darwin_amd64
    chmod a+x ./sgCheckup
```
   
OSX M1/arm:
```
    curl -Lo sgCheckup https://github.com/goldfiglabs/sgCheckup/releases/latest/download/sgCheckup_darwin_arm64
    chmod a+x ./sgCheckup
```

2. Run from source:
    ```
    git clone https://github.com/goldfiglabs/sgCheckup.git
    cd sgCheckup
    go run main.go
    ```

## Usage

Run `./sgCheckup` and view the reports generated in `output/`.

<img width="1217" alt="Screen Shot 2021-08-31 at 3 08 35 PM" src="https://user-images.githubusercontent.com/291215/131582460-4a581540-2f11-4c96-af54-a1e39961e69d.png">

## Overview

sgCheckup uses [goldfiglabs/introspector](https://github.com/goldfiglabs/introspector) to snapshot the Security Groups and Network Interfaces from your AWS Account into a Postgres database. sgCheckup then runs SQL queries to look for Security Groups with open ports and attached Network Interfaces. This list is then used to configure running `nmap` against the targeted list of IPs and ports. The output of nmap is used to determine if a) anything is listening and b) what software is listening on open ports.

## Notes

1. 2 HTML and CSV reports are provided: one each organized by Security Group, and one each organized by IP/Port combination.

1. By default, sgCheckup considers ports 22, 80, and 443 to be open intentionally. You can use the flag `-safePorts <comma-separated port list>` to override this behavior according to your own policies. Use `--safe-ports ""` to mark all ports unsafe.

1. You can skip the nmap phase with `-skip-nmap`. You will still get the report focused on Security Groups, but not the report based on open IP/Port combinations.

## License

Copyright (c) 2021 [Gold Fig Labs Inc.](https://www.goldfiglabs.com/)

This Source Code Form is subject to the terms of the Mozilla Public License, v.2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

[Mozilla Public License v2.0](./LICENSE)
