routes={
    "PUBLIC":[
        {
            "cidr_block": None,
            "description": "Traffic to/from internet",
            "destination": "0.0.0.0/0",
            "destination_type": "CIDR_BLOCK",
            "network_entity_id": "#VCN_DATA# INTERNET_GATEWAY_OCID", # Script vai alterar
            "route_type": "STATIC"
        },
        {
            "cidr_block": None,
            "description": "Traffic to OCI Object Storage",
            "destination": "#VCN_DATA# OCI_OBJECTSTORAGE", # Script vai alterar
            "destination_type": "SERVICE_CIDR_BLOCK",
            "network_entity_id": "#VCN_DATA# SERVICE_GATEWAY_OCID", # Script vai alterar
            "route_type": "STATIC"
        }
    ],
    "PRIVATE":[
        {
            "cidr_block": None,
            "description": "Traffic to the internet",
            "destination": "0.0.0.0/0",
            "destination_type": "CIDR_BLOCK",
            "network_entity_id": "#VCN_DATA# NAT_GATEWAY_OCID", # Script vai alterar
            "route_type": "STATIC"
        },
        {
            "cidr_block": None,
            "description": "Traffic to OCI services",
            "destination": "#VCN_DATA# ALL_SERVICES_IN_ORACLE_SERVICES_NETWORK", # Script vai alterar
            "destination_type": "SERVICE_CIDR_BLOCK",
            "network_entity_id": "#VCN_DATA# SERVICE_GATEWAY_OCID", # Script vai alterar
            "route_type": "STATIC"
        }
    ]
}
