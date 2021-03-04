# -----------------------------------
#  Copyright IBM Corp. 2020. All rights reserved.
#  US Government Users Restricted Rights - Use, duplication or disclosure
#  restricted by GSA ADP Schedule Contract with IBM Corp.
# -----------------------------------

variable "region" {}
variable "apikey" {}

terraform {
  required_providers {
    ibm = {
      source = "localdomain/provider/ibm"
      version = "1.11.2"
    }
  }
}

# Or we can switch the region via export IC_REGION="eu-gb"
provider "ibm" {
ibmcloud_api_key    = var.apikey
generation = 2
region = var.region
}
