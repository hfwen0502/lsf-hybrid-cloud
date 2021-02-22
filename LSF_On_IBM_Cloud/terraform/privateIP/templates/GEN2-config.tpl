
GEN2_RESOURCE_GROUP_ID: "${g2rg_id}"
GEN2_Region: "${g2region}"
GEN2_Zone: "${g2zone}"
GEN2_VPC_ID: "${g2vpc_id}"
GEN2_Image_ID: "${g2img_id}"
GEN2_SUBNET_ID: "${g2sn_id}"
GEN2_SG_ID: "${g2sg_id}"
GEN2_PROFILE: "${g2profile}"
CORES_PER_SOCKET: 1
SOCKET_PER_NODE: ${g2ncores}
MEMORY_PER_NODE: "${g2worker_mem}"
GEN2_DNS_Instance_ID: "${g2dns_instance}"
GEN2_DNS_Zone_ID: "${g2dns_zone}"
GEN2_DNS_Domain_Name: "${g2domain_name}"

rc_maxNumber: ${g2cidr_size}

rc_master_key: ${rc_master_key}
