#!/bin/env python3
# ==============================================================================
#    Script destinado a criacao das subnets necessarias para o deploy do OKE em
# uma VCN  existente. O  script esta  preparado para  criar apenas  as subnets,
# route tables e security list necessarias para o funcionamento do Cluster OKE.
# A VCN alvo, deve estar funcional, com o Service/Nat/Internet Gateway criados.
#
# git clone https://github.com/wuilber002/create_network_for_custom_oke.git && cd create-network-for-custom-oke
# python create_network_for_custom_oke.py --vcn-ocid <ocid1.vcn.oc1...>
#
# Network Resource Configuration for Cluster Creation and Deployment:
# https://docs.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengnetworkconfig.htm#subnetconfig
#
# ==============================================================================
import oci
import sys
import re
import os
import json
import copy
import time
import importlib
import templates.route_table as route_table
security_list = importlib.import_module("templates.security_list") # security list template
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
# ==============================================================================

# ------------------------------------------------------------------------------
def save_resource_list(OUTPUT_FILE, DICT_TO_SAVE):
    """
    Grava i OCID recebio em uma lista que pode ser usada para fazer o processo
    de delecao dos objetos criados.
    """
    with open(OUTPUT_FILE, "w") as OUTPUT:
        json.dump(obj=DICT_TO_SAVE, fp=OUTPUT, indent=2)
        OUTPUT.close

# ------------------------------------------------------------------------------
def deleteResourcesFromList(core_client, RESOURCE_LIST_FILE):
    """
    """
    # Opening JSON file
    with open(RESOURCE_LIST_FILE) as json_file:
        data = json.load(json_file)
    
    json_file.close()
    
    # deleta as sub-redes primeiro:
    for subnet_ocid in data['subnet']:
        print(subnet_ocid, end='')
        delete_subnet_response = core_client.delete_subnet(
            subnet_id=subnet_ocid,
        )
        if delete_subnet_response.data == None:
            print(' [DELETED]')
        else:
            print(' [ERRO]')
            print(delete_subnet_response.data)

    # Depois das sub-redes, pode deletar qualquer um, entre SecList ou Route Table:
    for route_table_ocid in data['route_table']:
        print(route_table_ocid, end='')
        delete_route_table_response = core_client.delete_route_table(
            rt_id=route_table_ocid,
        )
        if delete_route_table_response.data == None:
            print(' [DELETED]')
        else:
            print(' [ERRO]')
            print(delete_route_table_response.data)

    # Depois das sub-redes, pode deletar qualquer um, entre SecList ou Route Table:
    for security_list_ocid in data['security_list']:
        print(security_list_ocid, end='')
        delete_security_list_response = core_client.delete_security_list(
            security_list_id=security_list_ocid,
        )
        if delete_security_list_response.data == None:
            print(' [DELETED]')
        else:
            print(' [ERRO]')
            print(delete_security_list_response.data)

# -----------------------------------------------------------------------------
#
resource_list = {
    "subnet":[],
    "route_table":[],
    "security_list":[]
}

# -----------------------------------------------------------------------------
# Prefixo para a criacao dos recursos de rede da VCN no OCI
perfix_names={
    "subnet":"SubNet_",
    "route_table":"Route_",
    "security_list":"SecList_"
}

# ------------------------------------------------------------------------------
# Conjunto de informacoes da VCN, necessarias para a criacao das novas
# subnets e suas route_tables e security_lists.
# >>> Todos os valores serao populados durante a execusao do script <<<
vcn_data = {
    "vcn_ocid": None,
    "cidr_block": None,
    "internet_gateway_ocid": None,
    "nat_gateway_ocid": None,
    "service_gateway_ocid": None,
    "vcn_compartment_ocid": None,
    "destination_compartment_ocid": None,
    "oci_objectstorage": None,
    "all_services_in_oracle_services_network": None,
}

# -----------------------------------------------------------------------------
# lista de cores para output do script:
color = {
    'yellow': '\033[33m',
    'green': '\033[32m',
    'blue': '\033[34m',
    'red': '\033[31m',
    'purple': '\033[35m' ,
    'clean': '\033[0m'
}

# ------------------------------------------------------------------------------
# Dicionario para coleta de statisticas do script:
statistics={
    "subnet":0,
    "route_table":0,
    "route":0,
    "security_list":0,
    "ingress":0,
    "egress":0
}

# ------------------------------------------------------------------------------
# Nome do arquivo de output com a lista do ocid dos objetos criados pelo script
CURRENT_DATE_AND_TIME=time.strftime("%Y_%m%d_%H%M_%S")
OUTPUT_OCID_FILE=("resources_created_in_%s.ocid" % (CURRENT_DATE_AND_TIME))

# -----------------------------------------------------------------------------
# Configuracao dos parametros do script:
parser = ArgumentParser(
    allow_abbrev=False,
    formatter_class=ArgumentDefaultsHelpFormatter,
    description="Script para a criacao das subredes necessarias para o deploy do servico de Kubernetes da Oracle Cloud (OKE).",
)

parser.add_argument('-r', '--rollback', default=None, help="Utilize o arquivo (resources_created_in_xxxx_xxxx_xxxx_xx.ocid) criado apos a execusao do script para remover os recursos criados.")
parser.add_argument('-c', '--config', default=None, help="O metodo padrao de autenticacao utilizado pelo script eh o token delegation (presente cloud shell) ou instace principal (policy.dynamic group). Para utilizar o arquivo de configuracao \"config\" do OCI CLI, defina o caminho do arquivo de configuracao (Ex: ~/.oci/config) com esse parametro.")
parser.add_argument('-o', '--vcn-ocid', default=None, help="OCID da VCN na qual as subredes, route tables e security list serao criadas.")
parser.add_argument('-i', '--input-file', default="./data_input_file.json", help="Arquivo com as informacoes de criacao das subnets do OKE. Exemplo no arquivo data_input_file.json")
parser.add_argument('-d', '--destination-compartment-ocid', default=None, help="OCID do compartment no qual os recursos (subnet, route table e security list) serao criados.")
args = parser.parse_args()

# -----------------------------------------------------------------------------
# Carrega o arquivo de configuracao do oci cli para ter acesso ao OCI:
if args.config != None:
    oci_config = oci.config.from_file(args.config, 'DEFAULT')
    tenancy_ocid = oci_config['tenancy']
else:

    try:
        # By default this will hit the auth service in the region returned by
        # http://169.254.169.254/opc/v2/instance/region on the instance.
        ### signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()

        # get the cloud shell delegated authentication token
        delegation_token=open('/etc/oci/delegation_token', 'r').read() # create the api request signer
        signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(
           delegation_token=delegation_token
        )
        tenancy_ocid = signer.tenancy_id

    except Exception:
        print("*********************************************************************")
        print("* Error obtaining instance principals certificate.                  *")
        print("* Aboting.                                                          *")
        print("*********************************************************************")
        print("")
        raise SystemExit

    # generate config info from signer
    oci_config = {'region': signer.region, 'tenancy': tenancy_ocid}

# ------------------------------------------------------------------------------
#
CUSTOM_RETRY_STRATEGY = oci.retry.RetryStrategyBuilder(
    # Make up to 10 service calls
    max_attempts_check=True,
    max_attempts=10,

    # Don't exceed a total of 600 seconds for all service calls
    total_elapsed_time_check=True,
    total_elapsed_time_seconds=600,

    # Wait 45 seconds between attempts
    retry_max_wait_between_calls_seconds=45,

    # Use 2 seconds as the base number for doing sleep time calculations
    retry_base_sleep_time_seconds=2,

    # Retry on certain service errors:
    #
    #   - 5xx code received for the request
    #   - Any 429 (this is signified by the empty array in the retry config)
    #   - 400s where the code is QuotaExceeded or LimitExceeded
    service_error_check=True,
    service_error_retry_on_any_5xx=True,
    service_error_retry_config={
        400: ['QuotaExceeded', 'LimitExceeded'],
        429: []
    },

    # Use exponential backoff and retry with full jitter, but on throttles use
    # exponential backoff and retry with equal jitter
    backoff_type=oci.retry.BACKOFF_FULL_JITTER_EQUAL_ON_THROTTLE_VALUE
).get_retry_strategy()

# -----------------------------------------------------------------------------
# Inicializa o client de rede para interacao com o OCI:
if args.config != None:
    core_client = oci.core.VirtualNetworkClient(config=oci_config, retry_strategy=CUSTOM_RETRY_STRATEGY)
    print('\n  >>> Authentication by Config file <<<\n')
else:
    core_client = oci.core.VirtualNetworkClient(config=oci_config, signer=signer, retry_strategy=CUSTOM_RETRY_STRATEGY)
    print('\n  >>> Authentication by Instance principal <<<\n')

# -----------------------------------------------------------------------------
#
if args.rollback != None:
    print("\n >>> Apagando os recursos da lista de rollback...\n")
    deleteResourcesFromList(core_client, args.rollback)
    sys.exit(0)

# -----------------------------------------------------------------------------
# Identifica qual sera o compartment utilizado para pesquisa.
vcn_data['vcn_ocid'] = args.vcn_ocid
if args.vcn_ocid == None:
    print("\n!!! Voce precisa informar o %sOCID da VCN%s que sera usada para criar !!!" % (color['red'], color['clean']))
    print("!!!           as subnets, route tables e security lists           !!!")
    print("!!!                   necessarias para o OKE...                   !!!\n\n")
    sys.exit(1)
else:
    # "ocid1.vcn.oc1.iad.amaaaaaact4jh4ia6qqwg4wq4k4eqjg7bofvhj4oiuixbqhhgyz6f4gkompq"
    if not re.match('^(ocid1\.vcn\.oc1\..*)', vcn_data['vcn_ocid']):
        print(' [%sERRO%s] O ocid especificado parece nao ter um formato valido.' % (color['red'],color['clean']))
        sys.exit(2)

if args.input_file == "":
    print(' [%sERRO%s] Voce precisa informar um arquivo valido com as configuracoes de subnet para o OKE.' % (color['red'], color['clean']))
    sys.exit(1)
else:
    if os.path.isfile(args.input_file):
        with open(args.input_file) as json_input_file:
            input_data = json.load(json_input_file)
        
            # ------------------------------------------------------------------
            # Colecao de informacoes sobre as subnets que serao criadas.
            # As informacoes desse "dicionario de dados", deve ser customizada 
            # conforme a necessidade do cliente no arquivo de "INPUT":
            SUBNET_LIST=input_data['SUBNET']

    else:
        print(' [%sERRO%s] O arquivo de imput "%s" nao foi encontrado.' % (color['red'], color['clean'], args.input_file))
        sys.exit(2)

# ------------------------------------------------------------------------------
# Dicionario de dados para armazenar as regras de seguranca customizadas 
# para o ambiente no qual sera criado o Custom Cluster OKE.
SECURITY_LISTS=dict()

# ------------------------------------------------------------------------------
# Coleta as informacoes da VCN
print(" * Coletando informacoes da VCN...")
VCN_RESPONSE = core_client.get_vcn(vcn_id=vcn_data["vcn_ocid"])
vcn_data["vcn_compartment_ocid"]=VCN_RESPONSE.data.compartment_id
vcn_data["cidr_block"] = VCN_RESPONSE.data.cidr_block
print(" | |-> CIDR Block: %s" % (vcn_data["cidr_block"]))

# ------------------------------------------------------------------------------
# Valida o OCID do compartment de destino:
if args.destination_compartment_ocid == None:
    vcn_data["destination_compartment_ocid"]=VCN_RESPONSE.data.compartment_id
else:
    vcn_data["destination_compartment_ocid"]=args.destination_compartment_ocid

if re.match('^(ocid1\.tenancy\.oc1\..*)', vcn_data['destination_compartment_ocid']):
    print(' [%sERRO%s] VCN CRIADA NO ROOT DO TENANCY. Nao eh recomendado que se utiliza o "root" do tenancy para criar recursos.' % (color['red'],color['clean']))
    sys.exit(2)
elif not re.match('^(ocid1\.compartment\.oc1\..*)', vcn_data['destination_compartment_ocid']):
    print(' [%sERRO%s] O ocid do "compartment" especificado parece nao ter um formato valido.' % (color['red'],color['clean']))
    print(vcn_data['destination_compartment_ocid'])
    sys.exit(2)

# ------------------------------------------------------------------------------
# Coleta as informacoes do Internet Gateway da VCN
INTERNET_GATEWAYS_RESPONSE = core_client.list_internet_gateways(
    compartment_id=vcn_data["vcn_compartment_ocid"],
    vcn_id=vcn_data["vcn_ocid"],
    lifecycle_state="AVAILABLE"
)
vcn_data["internet_gateway_ocid"] = INTERNET_GATEWAYS_RESPONSE.data[0].id
print(" | |-> Internet Gateway [%sOk%s]" % (color['green'], color['clean']))

# ------------------------------------------------------------------------------
# Coleta as informacoes do Nat Gateway da VCN
NAT_GATEWAYS_RESPONSE = core_client.list_nat_gateways(
    compartment_id=vcn_data["vcn_compartment_ocid"],
    vcn_id=vcn_data["vcn_ocid"],
    lifecycle_state="AVAILABLE"
)
vcn_data["nat_gateway_ocid"] = NAT_GATEWAYS_RESPONSE.data[0].id
print(" | |-> Nat Gateway [%sOk%s]" % (color['green'], color['clean']))

# ------------------------------------------------------------------------------
# Coleta as informacoes do Service Gateway da VCN
SERVICE_GATEWAYS_RESPONSE = core_client.list_service_gateways(
    compartment_id=vcn_data["vcn_compartment_ocid"],
    vcn_id=vcn_data["vcn_ocid"],
    lifecycle_state="AVAILABLE"
)
vcn_data["service_gateway_ocid"] = SERVICE_GATEWAYS_RESPONSE.data[0].id
print(" | `-> Service Gateway:")

# ------------------------------------------------------------------------------
# Coleta as informacoes dos Service Gateways disponiveis na reginao
SERVICES_RESPONSE = (core_client.list_services()).data
for service in SERVICES_RESPONSE:
    if re.match('^(oci-.*-objectstorage)$', service.cidr_block):
        vcn_data["oci_objectstorage"]=service.cidr_block
    if re.match('^(all-.*-services-in-oracle-services-network)$', service.cidr_block):
        vcn_data["all_services_in_oracle_services_network"]=service.cidr_block
print(" |     |-> %s [%sOk%s]" % (vcn_data["all_services_in_oracle_services_network"], color['green'], color['clean']))
print(" |     `-> %s [%sOk%s]" % (vcn_data["oci_objectstorage"], color['green'], color['clean']))

# ------------------------------------------------------------------------------
# Popula a lista de route tables com as informacoes do ambiente que sera
# customizado para a criacao do Cluster OKE Custom:
print(" * Contruindo os templates de regras e rotas...")
for route_type in route_table.routes:
    for index, route in enumerate(route_table.routes[route_type]):
        for key in route:
            if re.match("^(#VCN_DATA#)", str(route[key])):
                REPLACE_VALUE=((route[key]).split(" ")[1]).lower()
                route_table.routes[route_type][index][key]=vcn_data[REPLACE_VALUE]
print("   |-> Route table [%sOk%s]" % (color['green'], color['clean']))

# ------------------------------------------------------------------------------
# Popula a lista de security lists com as informacoes do ambiente que sera
# customizado para a criacao do Cluster OKE Custom:
for subnet in SUBNET_LIST:
    rules = copy.deepcopy(getattr(security_list, subnet["function"]))
    for type in rules:
        for index, rule in enumerate(rules[type]):
            for key in rule:
                if re.match("^(#VCN_DATA#)", str(rule[key])):
                    REPLACE_VALUE=((rule[key]).split(" ")[1]).lower()
                    rules[type][index][key]=vcn_data[REPLACE_VALUE]
                if re.match("^(#SUBNET_LIST#)", str(rule[key])):
                    SUBNET_TYPE=(rule[key]).split(" ")[1]
                    TARGET_SUBNET=list(filter(lambda network: network['function'] == SUBNET_TYPE, SUBNET_LIST))
                    rules[type][index][key]=TARGET_SUBNET[0]['cidr_block']
    SECURITY_LISTS[subnet["display_name"]]=rules
print("   `-> Security list [%sOk%s]\n" % (color['green'], color['clean']))

# ==============================================================================
# Inicia o processo de criacao dos recursos:
print(" * Iniciando processo de criacao dos recursos de rede...")
for subnet in SUBNET_LIST:

    # ==========================================================================
    # Cria as route tables na VCN especificada:
    print("<+> %s%s%s, Type: %s%s%s" % (
        color['red'], subnet["display_name"], color['clean'],
        color['blue'], subnet["function"], color['clean']
    ))
    if subnet["type"] == "public":
        SUBNET_TYPE="Public"
        PROHIBIT_INTERNET_INGRESS=False
        PROHIBIT_PUBLIC_IP_ON_VNIC=False
    elif subnet["type"] == "private":
        SUBNET_TYPE="Private"
        PROHIBIT_INTERNET_INGRESS=True
        PROHIBIT_PUBLIC_IP_ON_VNIC=True
    else:
        print(' [%sERRO%s] O "type" de rede (%s) nao eh suportado. Valores suportados (%spublic%s/%sprivate%s).' % (
            color['red'], color['clean'],
            subnet["type"],
            color['purple'], color['clean'],
            color['blue'], color['clean']
        ))
        sys.exit(2)
    
    route_list = route_table.routes[SUBNET_TYPE.upper()]
    
    print(" |  +-> Route Table(%s%s%s%s):" % (
        color['green'], perfix_names["route_table"],
        subnet["display_name"], color['clean']
    ))
    print(" |  |   `-> Type: %s%s%s, Rules: %s%s%s" % (
        color['purple'], SUBNET_TYPE, color['clean'],
        color['purple'], len(route_list), color['clean']
    ))
    
    # --------------------------------------------------------------------------
    # Monta os objetos de rules da route table
    route_rules=list()
    for route in route_list:
        statistics["route"]+=1
        route_rules.append(
            oci.core.models.RouteRule(
                cidr_block=route["cidr_block"],
                description=route["description"],
                destination=route["destination"],
                destination_type=route["destination_type"],
                network_entity_id=route["network_entity_id"],
                route_type=route["route_type"]
            )
        )
    # --------------------------------------------------------------------------
    # Executa a criacao da route table:
    route_table_response = core_client.create_route_table(
        create_route_table_details=oci.core.models.CreateRouteTableDetails(
            display_name=("%s%s" % (perfix_names["route_table"], subnet["display_name"])),
            vcn_id=vcn_data["vcn_ocid"],
            compartment_id=vcn_data["destination_compartment_ocid"],
            route_rules=route_rules,
        )
    )
    statistics["route_table"]+=1
    subnet["route_table_ocid"]=route_table_response.data.id
    resource_list['route_table'].append(route_table_response.data.id)
    save_resource_list(OUTPUT_OCID_FILE,resource_list)

    # ==========================================================================
    # Cria as regras de acesso (Security List)
    print(" |  `-> Security List(%s%s%s%s):" % (
        color['green'], perfix_names["security_list"],
        subnet["display_name"], color['clean']
    ))
    print(" |      `-> Egress: %s%s%s, Ingress: %s%s%s" % (
        color['purple'], len(SECURITY_LISTS[subnet["display_name"]]["EGRESS_SECURITY_RULES"]), color['clean'], 
        color['purple'], len(SECURITY_LISTS[subnet["display_name"]]["INGRESS_SECURITY_RULES"]), color['clean']
    ))

    EGRESS_SECURITY_RULES=list()
    INGRESS_SECURITY_RULES=list()

    for RULE_TYPE in SECURITY_LISTS[subnet["display_name"]]:
        for RULE in SECURITY_LISTS[subnet["display_name"]][RULE_TYPE]:
            # --------------------------------------------------------------
            # Configura a sessao ICMP_OPTIONS:
            if RULE["icmp-options"] != None:
                RULE["icmp-options"]=oci.core.models.IcmpOptions(
                    type=RULE["icmp-options"]["type"],
                    code=RULE["icmp-options"]["code"]
                )
            # --------------------------------------------------------------
            # Configura a sessao icmp-options:
            if RULE["tcp-options"] != None:
                if RULE["tcp-options"]["destination-port-range"] != None:
                    RULE["tcp-options"]=oci.core.models.TcpOptions(
                        destination_port_range=oci.core.models.PortRange(
                            max=RULE["tcp-options"]["destination-port-range"]["max"],
                            min=RULE["tcp-options"]["destination-port-range"]["min"]
                        ),
                        source_port_range=None
                    )

            # --------------------------------------------------------------
            # Configura a sessao udp-options:
            if RULE["udp-options"] != None:
                if RULE["udp-options"]["destination-port-range"] != None:
                    RULE["udp-options"]=oci.core.models.UdpOptions(
                        destination_port_range=oci.core.models.PortRange(
                            max=RULE["udp-options"]["destination-port-range"]["max"],
                            min=RULE["udp-options"]["destination-port-range"]["min"]
                        ),
                        source_port_range=None
                    )

            # --------------------------------------------------------------
            # Cria o objeto do tipo certo para cada tipo de rule
            if RULE_TYPE == "EGRESS_SECURITY_RULES":
                statistics["egress"]+=1
                EGRESS_SECURITY_RULES.append(
                    oci.core.models.EgressSecurityRule(
                        description=RULE["description"],
                        destination=RULE["destination"],
                        destination_type=RULE["destination-type"],
                        protocol=str(RULE["protocol"]),
                        is_stateless=bool(RULE["is-stateless"]),
                        icmp_options=RULE["icmp-options"],
                        tcp_options=RULE["tcp-options"],
                        udp_options=RULE["udp-options"]
                    )
                )
            elif RULE_TYPE == "INGRESS_SECURITY_RULES":
                statistics["ingress"]+=1
                INGRESS_SECURITY_RULES.append(
                    oci.core.models.IngressSecurityRule(
                        description=RULE["description"],
                        source=RULE["source"],
                        source_type=RULE["source-type"],
                        protocol=str(RULE["protocol"]),
                        is_stateless=bool(RULE["is-stateless"]),
                        icmp_options=RULE["icmp-options"],
                        tcp_options=RULE["tcp-options"],
                        udp_options=RULE["udp-options"]
                    )
                )
    # --------------------------------------------------------------------------
    # Executa a criacao da security List:
    security_list_response = core_client.create_security_list(
        create_security_list_details=oci.core.models.CreateSecurityListDetails(
            display_name=("%s%s" % (perfix_names["security_list"], subnet["display_name"])),
            vcn_id=vcn_data["vcn_ocid"],
            compartment_id=vcn_data["destination_compartment_ocid"],
            egress_security_rules=EGRESS_SECURITY_RULES,
            ingress_security_rules=INGRESS_SECURITY_RULES,
        )
    )
    statistics["security_list"]+=1
    subnet["security_list_ocid"]=security_list_response.data.id
    resource_list['security_list'].append(security_list_response.data.id)
    save_resource_list(OUTPUT_OCID_FILE,resource_list)

    # Send the request to service, some parameters are not required, see API
    # doc for more info
    print(" |  +-> Subnet(%s%s%s%s):" % (
        color['green'], perfix_names["subnet"],
        subnet["display_name"], color['clean']
    ))
    print(" |      `-> Type: %s%s%s, CIDR: %s%s%s" % (
        color['purple'], SUBNET_TYPE, color['clean'],
        color['purple'], subnet["cidr_block"], color['clean']
    ))
    create_subnet_response = core_client.create_subnet(
        create_subnet_details=oci.core.models.CreateSubnetDetails(
            display_name=("%s%s" % (perfix_names["subnet"], subnet["display_name"])),
            vcn_id=vcn_data["vcn_ocid"],
            compartment_id=vcn_data["destination_compartment_ocid"],
            prohibit_internet_ingress=PROHIBIT_INTERNET_INGRESS,
            prohibit_public_ip_on_vnic=PROHIBIT_PUBLIC_IP_ON_VNIC,
            cidr_block=subnet["cidr_block"],
            route_table_id=subnet["route_table_ocid"],
            security_list_ids=[subnet["security_list_ocid"]]
        )
    )
    statistics["subnet"]+=1
    subnet["subnet_ocid"]=create_subnet_response.data.id
    resource_list['subnet'].append(create_subnet_response.data.id)
    save_resource_list(OUTPUT_OCID_FILE,resource_list)

# Exibe a estatistica final de criacao de recursos:
print("`-> Quantidade de recursos criados:")
print("    |-> Subnets: %s%s%s" % (color['yellow'], statistics["subnet"], color['clean']))
print("    |-> Route tables: %s%s%s" % (color['yellow'], statistics["route_table"], color['clean']))
print("    |   `-> Routes: %s%s%s" % (color['yellow'], statistics["route"], color['clean']))
print("    `-> Security lists: %s%s%s" % (color['yellow'], statistics["security_list"], color['clean']))
print("        |-> Ingess: %s%s%s" % (color['yellow'], statistics["ingress"], color['clean']))
print("        |-> Egress: %s%s%s" % (color['yellow'], statistics["egress"], color['clean']))
print("        `-> Total Rules: %s%s%s" % (color['yellow'], (statistics["egress"]+ statistics["ingress"]), color['clean']))
