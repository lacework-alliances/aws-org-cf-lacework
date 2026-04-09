# This repo is deprecated. Please use FortiCNAPP console to access the FortiCNAPP AWS organization-level Configuration integration CloudFormation template:

1. Log in to the FortiCNAPP console.
2. Go to Settings > Integrations > Cloud accounts.
3. Click + Add New.
4. Click Amazon Web Services and select CloudFormation.
Click Next.
Select Configuration (Organization) and click Run CloudFormation Template. If you are already logged in to your AWS account, this redirects you to the Create stack page. The template populates the Amazon S3 template URL for you.


# Lacework FortiCNAPP AWS Organization Integration

![Fortinet-logo-rgb-black-red](https://github.com/user-attachments/assets/9e4ce8af-8090-40e2-a1e5-b6bf8ea157ac)

## Overview

The CloudFormation resources deployed by this project allow for automatic on-boarding/off-boarding of AWS accounts within your Lacework tenant. As new AWS accounts are added/updated/deleted within your AWS organization, the appropriate roles and permissions will be provisioned, and Lacework will be notified of the event.

This code is designed for customers using AWS Organizations _without_ Control Tower - for Control Tower integrations, please follow the instructions [here](https://docs.fortinet.com/document/lacework-forticnapp/latest/administration-guide/399671/aws-control-tower-integration-using-cloudformation).

## How To Run

The master CloudFormation template sits in the following location:

`https://lacework-alliances.s3.us-west-2.amazonaws.com/lacework-organization-cfn/templates/lacework-aws-cfg-manage.template.yml`

Or you can simply click the button below to open the template in the AWS console.

[![Launch Stack](https://user-images.githubusercontent.com/6440106/153987820-e1f32423-1e69-416d-8bca-2ee3a1e85df1.png)](https://console.aws.amazon.com/cloudformation/home?#/stacks/create/review?templateURL=https://lacework-alliances.s3.us-west-2.amazonaws.com/lacework-organization-cfn/templates/lacework-aws-cfg-manage.template.yml)
