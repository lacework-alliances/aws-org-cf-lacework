# Lacework AWS Organization Integration

<img src="https://techally-content.s3-us-west-1.amazonaws.com/public-content/lacework_logo_full.png" width="600">

## Overview

The CloudFormation resources deployed by this project allow for automatic on-boarding/off-boarding of AWS accounts within your Lacework tenant. As new AWS accounts are added/updated/deleted within your AWS organization, the appropriate roles and permissions will be provisioned, and Lacework will be notified of the event.

This code is designed for customers using AWS Organizations _without_ Control Tower - for Control Tower integrations, please follow the instructions [here](https://docs.lacework.com/aws-config-and-cloudtrail-integration-with-aws-control-tower-using-cloudformation#installing-the-lacework-aws-control-tower-integration).
