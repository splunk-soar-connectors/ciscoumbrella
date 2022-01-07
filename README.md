[comment]: # "Auto-generated SOAR connector documentation"
# Cisco Umbrella

Publisher: Splunk  
Connector Version: 1\.1\.2  
Product Vendor: Cisco  
Product Name: Cisco Umbrella  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app allows management of a domain list on the Cisco Umbrella Security platform

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
This app implements actions that manage a Cisco Umbrella domain list. Cisco Umbrella allows
third-party implementations like Phantom Enterprise to create and manage a list of domains (i.e.
add, delete) via what it calls 'custom integrations'. The Phantom Cisco Umbrella App requires such
an integration to be pre-configured on Cisco Umbrella. The steps to do this are outlined below:

-   Login to your Cisco dashboard and go to Policies \> Policy Components \> Integrations and click
    the "Add" button.
-   Set the name of the custom integration to be "Phantom Orchestration Feed"
-   Expand your new custom integration, check "Enable", copy the integration URL and then click
    Save.
-   The integration URL will be of the form:
    **https://s-platform.api.opendns.com/1.0/events?customerKey=bac2bfa7-d134-4b85-a5ed-b1ffec027a91**
    One of the parameters to this URL is the customer key (GUID format). This value will be required
    while configuring the Cisco Umbrella asset on Phantom. The Cisco Umbrella App on Phantom will
    use this customer key while adding, listing, and deleting domains.
-   Go to Policies \> Policy Components \> Security Settings, click on add, and check the relevant
    security settings. Scroll down and under Integrations select 'Phantom Orchestration Feed'.

At the end of the above steps Cisco Umbrella has been configured to:  

-   Create a 'custom integration' domain list with a *customerKey* for Phantom to use.
-   Use the domains belonging to the 'Phantom Orchestration Feed' to block DNS requests.

The next step is to configure a 'Cisco Umbrella' app's asset on Phantom and specify the 'Cisco
Customer key' and click 'Test Connectivity' to validate the configuration.

More information about 'custom integrations' can be found
[here](https://support.umbrella.com/hc/en-us/articles/231248748) .  

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Cisco Umbrella server. Below are the
default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Cisco Umbrella asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**customer\_key** |  required  | password | Cisco Customer key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[list blocked domains](#action-list-blocked-domains) - Queries Cisco for the blocked domain list  
[block domain](#action-block-domain) - Block a domain  
[unblock domain](#action-unblock-domain) - Unblock a domain  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list blocked domains'
Queries Cisco for the blocked domain list

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.data\.\*\.name | string | 
action\_result\.data\.\*\.id | numeric |  `cisco domain id` 
action\_result\.data\.\*\.meta\.limit | numeric | 
action\_result\.data\.\*\.meta\.next | boolean | 
action\_result\.data\.\*\.meta\.page | numeric | 
action\_result\.data\.\*\.meta\.prev | boolean | 
action\_result\.data\.\*\.name | string |  `domain` 
action\_result\.summary\.total\_domains | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block domain'
Block a domain

Type: **contain**  
Read only: **False**

Cisco has many safeguards in place before adding a domain to a block list\. These are present to protect against accidentally submitting domains for highly popular or known sites like google\.com\. If the 'disable\_safeguards' parameter is set to True \(or checked\), those safeguards will be bypassed\. This could potentially allow adding a well\-known domain like google\.com to a domain block list\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to block | string |  `domain` 
**disable\_safeguards** |  optional  | Disable safeguards while blocking the domain | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.disable\_safeguards | boolean | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.id | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock domain'
Unblock a domain

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to unblock | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 