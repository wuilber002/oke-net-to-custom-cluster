#!/usr/bin/env python3
# ==============================================================================
#    Script destinado a criação das subnets necessárias para o deploy do OKE em
# uma VCN  existente. O  script esta  preparado para  criar apenas  as subnets,
# route tables e security list necessárias para o funcionamento do Cluster OKE.
# A VCN alvo, deve estar funcional, com o Service/Nat/Internet Gateway criados.
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Documentação Oficial Oracle sobre a construção da rede para o cluster OKE.
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
def save_resource_list(output_file, dict_to_save):
    """
    Grava o OCID recebido em uma lista que pode ser usada para fazer o processo
    de deleção dos objetos criados.
    """
    with open(output_file, "w") as OUTPUT:
        json.dump(obj=dict_to_save, fp=OUTPUT, indent=2)
        OUTPUT.close

# ------------------------------------------------------------------------------
def deleteResourcesFromList(oci_config, resource_list_file):
    """
    Executa a exclusão de recursos presentes no arquivo json criado 
    com a lista de recursos criados no OCI em uma exclusão anterior
    desse script.
    """
    # Abre o arquivo JSON
    with open(resource_list_file) as json_file:
        data = json.load(json_file)
    json_file.close()

    # Deleta as sub-redes primeiro e depois as SecList ou Route Table em qualquer ordem:
    core_client=None
    for resource_ocid in (data['subnet'] + (data['route_table'] + data['security_list'])):
        # ---------------------------------------------------------------------
        # Cria o client de conexão com o OCI, para a região do recurso que sera
        # deletado. O client sera criado, apenas 1 vez.
        if core_client == None:
            oci_config['region'] = ExtractRegionFromOCID(resource_ocid)
            if args.config != None:
                core_client = oci.core.VirtualNetworkClient(config=oci_config, retry_strategy=CUSTOM_RETRY_STRATEGY)
            else:
                core_client = oci.core.VirtualNetworkClient(config=oci_config, signer=signer, retry_strategy=CUSTOM_RETRY_STRATEGY)

        print(resource_ocid, end='')
        try:
            if re.match('^(ocid1\.subnet\.oc1\..*)', resource_ocid):
                delete_resource_response = core_client.delete_subnet(
                    subnet_id=resource_ocid,
                )   
            elif re.match('^(ocid1\.routetable\.oc1\..*)', resource_ocid):
                delete_resource_response = core_client.delete_route_table(
                    rt_id=resource_ocid
                )
            elif re.match('^(ocid1\.securitylist\.oc1\..*)', resource_ocid):
                delete_resource_response = core_client.delete_security_list(
                    security_list_id=resource_ocid
                )
            if delete_resource_response.data == None:
                print(' [%sDELETED%s]' % (color['green'], color['clean']))
            else:
                print('\n`-> [%sWARNING%s] %s' % (
                    color['yellow'],
                    color['clean'],
                    delete_resource_response.data
                ))

        except Exception as exc_error:
            print('\n`-> [%sERRO%s] (%s) %s' % (
                color['red'],
                color['clean'],
                exc_error.status,
                exc_error.message
            ))

# -----------------------------------------------------------------------------
#
def ExtractRegionFromOCID(ocid):
    """
    Returna a região a qual o OCID faz referencia.
    """
    return(((
        re.compile('ocid1\.[a-z]{1,}\.oc1.(.*)\..*([a-z 0-9]{60})+')
    ).search(ocid)).group(1))

# -----------------------------------------------------------------------------
#
def acceptSafeHarbor():
    print("""
                   %sAviso de Isenção de Responsabilidade%s

      Antes de continuar, voce precisa saber que a execução desse script, assim
    como a  manipulação dos  dados envolvidos é de total  responsabilidade  sua
    (usuário), ficando  assim  você (usuário)  responsável pela  sua execução e
    utilização.

      Teste adequadamente em recursos de  homologação antes de usar em produção
    para evitar interrupções indesejadas em serviços ou surpresas indesejadas.

      Este não é um  aplicativo oficial da  Oracle e por  isso, não conta com o
    seu suporte. A Oracle não se responsabiliza por este conteúdo.

    """ % (color['red'],color['clean']))

    count=0
    while count < 5:
        user_option = input('  Eu declaro que li e entendi essa mensagem: [%sSim%s/%sNao%s] ' % (
            color['green'],color['clean'],color['red'],color['clean']
        ))
        if not re.match('^(Sim|Nao)$', user_option):
            if count == 0 :
                print('\nVoce precisa informar uma opção valida:')
                print('  - "%sSim%s"' % (color['green'],color['clean']))
                print('  - "%sNao%s"\n' % (color['red'],color['clean']))
        else:
            if re.match('^(Nao)$', user_option):
                print('\n\n >>> A opção que voce escolheu foi <<<')
                print(' %sNão concordo%s! Pretendo fazer manualmente as configurações.\n' % (
                    color['red'],color['clean']
                ))
                print(' A configuração dos recursos de rede necessários pelo OKE, podem ser configurados\nmanualmente seguindo a documentação oficial da Oracle sobre o assunto.\n')
                print('  https://docs.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengnetworkconfig.htm\n')
                sys.exit(3)
            return(True)
        count+=1
    print("Script finalizado...")
    sys.exit(1)

# -----------------------------------------------------------------------------
#
resource_list = {
    "subnet":[],
    "route_table":[],
    "security_list":[]
}

# ------------------------------------------------------------------------------
# Conjunto de informações da VCN, necessárias para a criação das novas
# subnets e suas route_tables e security_lists.
# >>> Todos os valores serão populados durante a exclusão do script <<<
vcn_data = {
    "region": None,
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
    'clean': '\033[0m',
    'red_blink':'\x1b[6;37;41m'
}

# ------------------------------------------------------------------------------
# Dicionario para coleta de estatísticas do script:
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

# ==============================================================================
# função principal:
if __name__ == '__main__':

    # -----------------------------------------------------------------------------
    # solicita o aceite do usuário para a isenção de responsabilidade:
    acceptSafeHarbor()

    # -----------------------------------------------------------------------------
    # Configuração dos parâmetros do script:
    parser = ArgumentParser(
        allow_abbrev=False,
        formatter_class=ArgumentDefaultsHelpFormatter,
        description="Script para a criação das sub-redes necessárias para o deploy do serviço de Kubernetes da Oracle Cloud (OKE).",
    )

    parser.add_argument('-r', '--rollback', default=None, help="Utilize o arquivo (resources_created_in_xxxx_xxxx_xxxx_xx.ocid) criado apos a exclusão do script para remover os recursos criados.")
    parser.add_argument('-c', '--config', default=None, help="O método padrão de autenticação utilizado pelo script eh o token delegation (presente cloud shell) ou instance principal (policy.dynamic group). Para utilizar o arquivo de configuração \"config\" do OCI CLI, defina o caminho do arquivo de configuração (Ex: ~/.oci/config) com esse parâmetro.")
    parser.add_argument('-o', '--vcn-ocid', default=None, help="OCID da VCN na qual as sub-redes, route tables e security list serão criadas.")
    parser.add_argument('-i', '--input-file', default="./data_input_file.json", help="Arquivo com as informações de criação das subnets do OKE. Exemplo no arquivo data_input_file.json")
    parser.add_argument('-d', '--destination-compartment-ocid', default=None, help="OCID do compartment no qual os recursos (subnet, route table e security list) serão criados.")
    args = parser.parse_args()

    # -----------------------------------------------------------------------------
    # Carrega o arquivo de configuração do oci cli para ter acesso ao OCI:
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
            print("* Aborting.                                                         *")
            print("*********************************************************************")
            print("")
            raise SystemExit

        # generate config info from signer
        oci_config = {'region': signer.region, 'tenancy': tenancy_ocid}

    # -----------------------------------------------------------------------------
    # Executa a função de rollback e finaliza o script:
    if args.rollback != None:
        print("\n >>> %sApagando%s os recursos da lista de rollback...\n" % (
            color['red'],color["clean"]
        ))
        deleteResourcesFromList(oci_config, args.rollback)
        sys.exit(0)

    # -----------------------------------------------------------------------------
    # Identifica qual sera o compartment utilizado para pesquisa.
    vcn_data['vcn_ocid'] = args.vcn_ocid
    vcn_data['region'] = ExtractRegionFromOCID(args.vcn_ocid)

    if args.vcn_ocid == None:
        print("\n!!! Voce precisa informar o %sOCID da VCN%s que sera usada para criar !!!" % (color['red'], color['clean']))
        print("!!!           as subnets, route tables e security lists           !!!")
        print("!!!                   necessárias para o OKE...                   !!!\n\n")
        sys.exit(1)
    else:
        # "ocid1.vcn.oc1.iad.amaaaaaact4jh4ia6qqwg4wq4k4eqjg7bofvhj4oiuixbqhhgyz6f4gkompq"
        if not re.match('^(ocid1\.vcn\.oc1\..*)', vcn_data['vcn_ocid']):
            print(' [%sERRO%s] O ocid especificado parece nao ter um formato valido.' % (color['red'],color['clean']))
            sys.exit(2)

    # ------------------------------------------------------------------------------
    # Altera a configura de conexão com OCI para utilizar a região do OCID da VCN
    # especificada por parâmetro
    oci_config['region'] = vcn_data['region']

    # -----------------------------------------------------------------------------
    # Inicializa o client de rede para interação com o OCI:
    if args.config != None:
        core_client = oci.core.VirtualNetworkClient(config=oci_config, retry_strategy=CUSTOM_RETRY_STRATEGY)
    else:
        core_client = oci.core.VirtualNetworkClient(config=oci_config, signer=signer, retry_strategy=CUSTOM_RETRY_STRATEGY)

    # Verifica o arquivo de parâmetros:
    if args.input_file == "":
        print(' [%sERRO%s] Voce precisa informar um arquivo valido com as configurações de subnet para o OKE.' % (color['red'], color['clean']))
        sys.exit(1)
    else:
        if os.path.isfile(args.input_file):
            with open(args.input_file) as json_input_file:
                input_data = json.load(json_input_file)
            
                # ------------------------------------------------------------------
                # Coleção de informações sobre as subnets que serão criadas.
                # As informações desse "dicionario de dados", deve ser customizada 
                # conforme a necessidade do cliente no arquivo de "INPUT":
                SUBNET_LIST=input_data['SUBNET']

                # ------------------------------------------------------------------
                # Lista de valores para o prefixação dos nomes dos recursos que serão
                # criados pelo script:
                PREFIX_NAMES=input_data['PREFIX']

        else:
            print(' [%sERRO%s] O arquivo de input "%s" nao foi encontrado.' % (color['red'], color['clean'], args.input_file))
            sys.exit(2)

    # ------------------------------------------------------------------------------
    # Dicionario de dados para armazenar as regras de segurança customizadas 
    # para o ambiente no qual sera criado o Custom Cluster OKE.
    SECURITY_LISTS=dict()

    # ------------------------------------------------------------------------------
    # Coleta as informações da VCN
    print(" * Coletando informações da VCN...")
    print(" | |-> Region: %s" % (oci_config['region']))
    try:
        VCN_RESPONSE = core_client.get_vcn(vcn_id=vcn_data["vcn_ocid"])
    except Exception as exc_error:
        print(' `-> [%sERRO%s] Get VCN info: (%s) %s' % (
            color['red'],
            color['clean'],
            exc_error.status,
            exc_error.message
        ))
        sys.exit(2)
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
    # Coleta as informações do Internet Gateway da VCN
    INTERNET_GATEWAYS_RESPONSE = core_client.list_internet_gateways(
        compartment_id=vcn_data["vcn_compartment_ocid"],
        vcn_id=vcn_data["vcn_ocid"],
        lifecycle_state="AVAILABLE"
    )
    if len(INTERNET_GATEWAYS_RESPONSE.data) > 0:
        vcn_data["internet_gateway_ocid"] = INTERNET_GATEWAYS_RESPONSE.data[0].id
        print(' | |-> Internet Gateway [%sOk%s]' % (
            color['green'],
            color['clean']
        ))
        del(INTERNET_GATEWAYS_RESPONSE)
    else:
        print(' | |-> Internet Gateway [%sError%s]' % (color['red'],color['clean']))
        print('       `-> %sNot Found%s' % (color['red_blink'],color['clean']))
        sys.exit(2)

    # ------------------------------------------------------------------------------
    # Coleta as informações do Nat Gateway da VCN
    NAT_GATEWAYS_RESPONSE = core_client.list_nat_gateways(
        compartment_id=vcn_data["vcn_compartment_ocid"],
        vcn_id=vcn_data["vcn_ocid"],
        lifecycle_state="AVAILABLE"
    )
    if len(NAT_GATEWAYS_RESPONSE.data) > 0:
        vcn_data["nat_gateway_ocid"] = NAT_GATEWAYS_RESPONSE.data[0].id
        print(' | |-> Nat Gateway [%sOk%s]' % (
            color['green'],
            color['clean']
        ))
        del(NAT_GATEWAYS_RESPONSE)
    else:
        print(' | |-> Nat Gateway [%sError%s]' % (color['red'],color['clean']))
        print('       `-> %sNot Found%s' % (color['red_blink'],color['clean']))
        sys.exit(2)

    # ------------------------------------------------------------------------------
    # Coleta as informações do Service Gateway da VCN
    SERVICE_GATEWAYS_RESPONSE = core_client.list_service_gateways(
        compartment_id=vcn_data["vcn_compartment_ocid"],
        vcn_id=vcn_data["vcn_ocid"],
        lifecycle_state="AVAILABLE"
    )
    if len(SERVICE_GATEWAYS_RESPONSE.data) > 0:
        vcn_data["service_gateway_ocid"] = SERVICE_GATEWAYS_RESPONSE.data[0].id
        print(' | |-> Service Gateway [%sOk%s]' % (
            color['green'],
            color['clean']
        ))
        del(SERVICE_GATEWAYS_RESPONSE)
    else:
        print(' | |-> Service Gateway [%sError%s]' % (color['red'],color['clean']))
        print('       `-> %sNot Found%s' % (color['red_blink'],color['clean']))
        sys.exit(2)

    # ------------------------------------------------------------------------------
    # Coleta as informações dos Service Gateways disponíveis na região
    SERVICES_RESPONSE = (core_client.list_services()).data
    for service in SERVICES_RESPONSE:
        if re.match('^(oci-.*-objectstorage)$', service.cidr_block):
            vcn_data["oci_objectstorage"]=service.cidr_block
        if re.match('^(all-.*-services-in-oracle-services-network)$', service.cidr_block):
            vcn_data["all_services_in_oracle_services_network"]=service.cidr_block
    print(" |     |-> %s [%sOk%s]" % (vcn_data["all_services_in_oracle_services_network"], color['green'], color['clean']))
    print(" |     `-> %s [%sOk%s]" % (vcn_data["oci_objectstorage"], color['green'], color['clean']))

    # ------------------------------------------------------------------------------
    # Popula a lista de route tables com as informações do ambiente que sera
    # customizado para a criação do Cluster OKE Custom:
    print(" * Construindo os templates de regras e rotas...")
    for route_type in route_table.routes:
        for index, route in enumerate(route_table.routes[route_type]):
            for key in route:
                if re.match("^(#VCN_DATA#)", str(route[key])):
                    REPLACE_VALUE=((route[key]).split(" ")[1]).lower()
                    route_table.routes[route_type][index][key]=vcn_data[REPLACE_VALUE]
    print("   |-> Route table [%sOk%s]" % (color['green'], color['clean']))

    # ------------------------------------------------------------------------------
    # Popula a lista de security lists com as informações do ambiente que sera
    # customizado para a criação do Cluster OKE Custom:
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
    # Inicia o processo de criação dos recursos:
    print(" * Iniciando processo de criação dos recursos de rede...")
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
            color['green'], PREFIX_NAMES["route_table"],
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
        # Executa a criação da route table:
        route_table_response = core_client.create_route_table(
            create_route_table_details=oci.core.models.CreateRouteTableDetails(
                display_name=("%s%s" % (PREFIX_NAMES["route_table"], subnet["display_name"])),
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
            color['green'], PREFIX_NAMES["security_list"],
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
                # Configura a sessão ICMP_OPTIONS:
                if RULE["icmp-options"] != None:
                    RULE["icmp-options"]=oci.core.models.IcmpOptions(
                        type=RULE["icmp-options"]["type"],
                        code=RULE["icmp-options"]["code"]
                    )
                # --------------------------------------------------------------
                # Configura a sessão icmp-options:
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
                # Configura a sessão udp-options:
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
        # Executa a criação da security List:
        security_list_response = core_client.create_security_list(
            create_security_list_details=oci.core.models.CreateSecurityListDetails(
                display_name=("%s%s" % (PREFIX_NAMES["security_list"], subnet["display_name"])),
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
            color['green'], PREFIX_NAMES["subnet"],
            subnet["display_name"], color['clean']
        ))
        print(" |      `-> Type: %s%s%s, CIDR: %s%s%s" % (
            color['purple'], SUBNET_TYPE, color['clean'],
            color['purple'], subnet["cidr_block"], color['clean']
        ))
        create_subnet_response = core_client.create_subnet(
            create_subnet_details=oci.core.models.CreateSubnetDetails(
                display_name=("%s%s" % (PREFIX_NAMES["subnet"], subnet["display_name"])),
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

    # Exibe a estatística final de criação de recursos:
    print("`-> Quantidade de recursos criados:")
    print("    |-> Subnets: %s%s%s" % (color['yellow'], statistics["subnet"], color['clean']))
    print("    |-> Route tables: %s%s%s" % (color['yellow'], statistics["route_table"], color['clean']))
    print("    |   `-> Routes: %s%s%s" % (color['yellow'], statistics["route"], color['clean']))
    print("    `-> Security lists: %s%s%s" % (color['yellow'], statistics["security_list"], color['clean']))
    print("        |-> Ingess: %s%s%s" % (color['yellow'], statistics["ingress"], color['clean']))
    print("        |-> Egress: %s%s%s" % (color['yellow'], statistics["egress"], color['clean']))
    print("        `-> Total Rules: %s%s%s\n" % (color['yellow'], (statistics["egress"]+ statistics["ingress"]), color['clean']))
