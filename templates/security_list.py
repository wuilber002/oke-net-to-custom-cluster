GENERIC={
    "EGRESS_SECURITY_RULES": [],
    "INGRESS_SECURITY_RULES": []
}
LOADBALANCER={
    "EGRESS_SECURITY_RULES": [],
    "INGRESS_SECURITY_RULES": []
}
PODS={
    "EGRESS_SECURITY_RULES": [
        {
            "description": "Allow pods on one worker node to communicate with pods on other worker nodes",
            "destination": "#SUBNET_LIST# PODS",
            "destination-type": "CIDR_BLOCK",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": "all",
            "tcp-options": None,
            "udp-options": None
        }
    ],
    "INGRESS_SECURITY_RULES": [
        {
            "description": "Allow pods on one worker node to communicate with pods on other worker nodes",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": "all",
            "source": "#SUBNET_LIST# PODS",
            "source-type": "CIDR_BLOCK",
            "tcp-options": None,
            "udp-options": None
        }
    ]
}
WORKERNODE={
    "EGRESS_SECURITY_RULES": [
        {
            "description": "Allow pods on one worker node to communicate with pods on other worker nodes",
            "destination": "#SUBNET_LIST# WORKERNODE",
            "destination-type": "CIDR_BLOCK",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": "all",
            "tcp-options": None,
            "udp-options": None
        },
        {
            "description": "Access to Kubernetes API Endpoint",
            "destination": "#SUBNET_LIST# API_ENDPOINT",
            "destination-type": "CIDR_BLOCK",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": 6,
            "tcp-options": {
                "destination-port-range": {
                    "max": 6443,
                    "min": 6443
                },
                "source-port-range": None
            },
            "udp-options": None
        },
        {
            "description": "Kubernetes worker to control plane communication",
            "destination": "#SUBNET_LIST# API_ENDPOINT",
            "destination-type": "CIDR_BLOCK",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": 6,
            "tcp-options": {
                "destination-port-range": {
                    "max": 12250,
                    "min": 12250
                },
                "source-port-range": None
            },
            "udp-options": None
        },
        {
            "description": "Path discovery",
            "destination": "#SUBNET_LIST# API_ENDPOINT",
            "destination-type": "CIDR_BLOCK",
            "icmp-options": {
                "code": 4,
                "type": 3
            },
            "is-stateless": False,
            "protocol": 1,
            "tcp-options": None,
            "udp-options": None
        },
        {
            "description": "Allow nodes to communicate with OKE to ensure correct start-up and continued functioning",
            "destination": "#VCN_DATA# ALL_SERVICES_IN_ORACLE_SERVICES_NETWORK",
            "destination-type": "SERVICE_CIDR_BLOCK",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": 6,
            "tcp-options": {
                "destination-port-range": {
                    "max": 443,
                    "min": 443
                },
                "source-port-range": None
            },
            "udp-options": None
        },
        {
            "description": "ICMP Access from Kubernetes Control Plane",
            "destination": "0.0.0.0/0",
            "destination-type": "CIDR_BLOCK",
            "icmp-options": {
                "code": 4,
                "type": 3
            },
            "is-stateless": False,
            "protocol": 1,
            "tcp-options": None,
            "udp-options": None
        },
        {
            "description": "Worker Nodes access to Internet",
            "destination": "0.0.0.0/0",
            "destination-type": "CIDR_BLOCK",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": "all",
            "tcp-options": None,
            "udp-options": None
        }
    ],
    "INGRESS_SECURITY_RULES": [
        {
            "description": "Allow pods on one worker node to communicate with pods on other worker nodes",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": "all",
            "source": "#SUBNET_LIST# WORKERNODE",
            "source-type": "CIDR_BLOCK",
            "tcp-options": None,
            "udp-options": None
            },
        {
            "description": "Path discovery",
            "icmp-options": {
                "code": 4,
                "type": 3
            },
            "is-stateless": False,
            "protocol": 1,
            "source": "#SUBNET_LIST# API_ENDPOINT",
            "source-type": "CIDR_BLOCK",
            "tcp-options": None,
            "udp-options": None
        },
        {
            "description": "TCP access from Kubernetes Control Plane",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": 6,
            "source": "#SUBNET_LIST# API_ENDPOINT",
            "source-type": "CIDR_BLOCK",
            "tcp-options": None,
            "udp-options": None
        },
        {
            "description": "Inbound SSH traffic to worker nodes",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": 6,
            "source": "0.0.0.0/0",
            "source-type": "CIDR_BLOCK",
            "tcp-options": {
                "destination-port-range": {
                    "max": 22,
                    "min": 22
                },
                "source-port-range": None
            },
            "udp-options": None
        }
    ],
}
API_ENDPOINT={
    "EGRESS_SECURITY_RULES": [
        {
            "description": "Allow Kubernetes Control Plane to communicate with OKE",
            "destination": "#VCN_DATA# ALL_SERVICES_IN_ORACLE_SERVICES_NETWORK",
            "destination-type": "SERVICE_CIDR_BLOCK",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": 6,
            "tcp-options": {
                "destination-port-range": {
                    "max": 443,
                    "min": 443
                },
                "source-port-range": None
            },
            "udp-options": None
        },
        {
            "description": "All traffic to worker nodes",
            "destination": "#SUBNET_LIST# WORKERNODE",
            "destination-type": "CIDR_BLOCK",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": 6,
            "tcp-options": None,
            "udp-options": None
        },
        {
            "description": "Path discovery",
            "destination": "#SUBNET_LIST# WORKERNODE",
            "destination-type": "CIDR_BLOCK",
            "icmp-options": {
                "code": 4,
                "type": 3
            },
            "is-stateless": False,
            "protocol": 1,
            "tcp-options": None,
            "udp-options": None
        }
    ],
    "INGRESS_SECURITY_RULES": [
        {
            "description": "External access to Kubernetes API endpoint",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": 6,
            "source": "0.0.0.0/0",
            "source-type": "CIDR_BLOCK",
            "tcp-options": {
                "destination-port-range": {
                    "max": 6443,
                    "min": 6443
                },
                "source-port-range": None
            },
            "udp-options": None
        },
        {
            "description": "Kubernetes worker to Kubernetes API endpoint communication",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": 6,
            "source": "#SUBNET_LIST# WORKERNODE",
            "source-type": "CIDR_BLOCK",
            "tcp-options": {
                "destination-port-range": {
                    "max": 6443,
                    "min": 6443
                },
                "source-port-range": None
            },
            "udp-options": None
        },
        {
            "description": "Kubernetes worker to control plane communication",
            "icmp-options": None,
            "is-stateless": False,
            "protocol": 6,
            "source": "#SUBNET_LIST# WORKERNODE",
            "source-type": "CIDR_BLOCK",
            "tcp-options": {
                "destination-port-range": {
                    "max": 12250,
                    "min": 12250
                },
                "source-port-range": None
            },
            "udp-options": None
        },
        {
            "description": "Path discovery",
            "icmp-options": {
                "code": 4,
                "type": 3
            },
            "is-stateless": False,
            "protocol": 1,
            "source": "#SUBNET_LIST# WORKERNODE",
            "source-type": "CIDR_BLOCK",
            "tcp-options": None,
            "udp-options": None
        }
    ],
}