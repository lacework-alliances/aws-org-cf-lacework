# Lacework AWS Organization Integration

<img src="https://techally-content.s3-us-west-1.amazonaws.com/public-content/lacework_logo_full.png" width="600">

## Overview

The CloudFormation resources deployed by this project allow for automatic on-boarding/off-boarding of AWS accounts within your Lacework tenant. As new AWS accounts are added/updated/deleted within your AWS organization, the appropriate roles and permissions will be provisioned, and Lacework will be notified of the event.

This code is designed for customers using AWS Organizations _without_ Control Tower - for Control Tower integrations, please follow the instructions [here](https://docs.lacework.net/compliance/aws-config-and-cloudtrail-integration-with-aws-control-tower-using-cloudformation#docusaurus_skipToContent_fallback).

## How To Run

The master CloudFormation template sits in the following location:

`https://lacework-alliances.s3.us-west-2.amazonaws.com/lacework-organization-cfn/templates/lacework-aws-cfg-manage.template.yml`

Or you can simply click the button below to open the template in the AWS console.

[![Launch Stack](https://user-images.githubusercontent.com/6440106/153987820-e1f32423-1e69-416d-8bca-2ee3a1e85df1.png)](https://console.aws.amazon.com/cloudformation/home?#/stacks/create/review?templateURL=https://lacework-alliances.s3.us-west-2.amazonaws.com/lacework-organization-cfn/templates/lacework-aws-cfg-manage.template.yml)
