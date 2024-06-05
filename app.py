from flask import Flask, render_template, request, session, redirect, url_for
import requests
import urllib3
import json
import os
import getpass
import xml.etree.ElementTree as ET
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        app_value = request.form.get('app')
        if app_value == 'juniper':
            return redirect(url_for('s2smain'))
    return render_template('index.html')
    
@app.route('/s2s', methods=['GET', 'POST'])
def s2smain():
    if request.method == 'POST':
        provider = request.form['provider']
        if provider == "aws":
            return redirect(url_for('aws_config'))
        elif provider == "azure":
            return redirect(url_for('azure_config'))
    return render_template('s2smain.html')


def psk(file_path):
    pre_shared_keys = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            # Remove the - and spaces from the PSK
            stripped_line = line.lstrip('- ').strip()
            if stripped_line.startswith("Pre-Shared Key"):
                # Finds the first PSK
                first_colon_index = stripped_line.find(':')
                # Takes value of PSK removing proigoumena spaces
                value = stripped_line[first_colon_index + 1:].strip()
                # Add value to the list
                pre_shared_keys.append(value)
                # Set nax vakue to 2
                if len(pre_shared_keys) == 2:
                    break
    return pre_shared_keys

def vpg(file_path):
    vpg_pip_list = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            # Remove the - and spaces from the PSK
            stripped_line = line.lstrip('- ').strip()
            if stripped_line.startswith("Virtual Private Gateway"):
                # Finds the first PSK
                first_colon_index = stripped_line.find(':')
                # Takes value of PSK removing proigoumena spaces
                value = stripped_line[first_colon_index + 1:].strip()
                if '/' in value:
                    value = value.split('/')[0]
                # Add value to the list
                vpg_pip_list.append(value)
                # Set nax vakue to 2
                if len(vpg_pip_list) == 4:
                    break
    return vpg_pip_list

def cgw(file_path):
    cgw_list = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            # Remove the - and spaces from the PSK
            stripped_line = line.lstrip('- ').strip()
            if stripped_line.startswith("Customer Gateway"):
                # Finds the first PSK
                first_colon_index = stripped_line.find(':')
                # Takes value of PSK removing proigoumena spaces
                value = stripped_line[first_colon_index + 1:].strip()
                # Add value to the list
                cgw_list.append(value)
                # Set nax vakue to 2
                if len(cgw_list) == 10:
                    break
    return cgw_list

def vpg_internal(file_path):
    vpg_internal_list = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            # Remove the - and spaces from the PSK
            stripped_line = line.lstrip('- ').strip()
            if stripped_line.startswith("Virtual Private Gateway"):
                # Finds the first PSK
                first_colon_index = stripped_line.find(':')
                # Takes value of PSK removing proigoumena spaces
                value = stripped_line[first_colon_index + 1:].strip()
                # Add value to the list
                vpg_internal_list.append(value)
                # Set nax vakue to 2
                if len(vpg_internal_list) == 10:
                    break
    return vpg_internal_list

app.config['UPLOAD_FOLDER'] = '/tmp/'
@app.route('/s2s/aws', methods=['GET', 'POST'])
def aws_config():
    if request.method == 'POST':
        zone = request.form['zone']
        log1 = request.form['log1']
        log2 = request.form['log2']
        cidr = request.form['cidr']
        name = request.form['name']
        file = request.files['file']
        if file.filename != '':
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            pre_shared_keys = psk(file_path)
            vpg_pip_list = vpg(file_path)
            cgw_list = cgw(file_path)
            vpg_internal_list = vpg_internal(file_path)
        
            if len(pre_shared_keys) >= 2:
                pska = pre_shared_keys[0]
                pskb = pre_shared_keys[1]
                print(f"PSK (a): {pska}")
                print(f"PSK (b): {pskb}")
            else:
                print("This is not a valid AWS Generic Extract - Check again or ask your fcking manager")

            if len(vpg_pip_list) >= 2:
                pipa = vpg_pip_list[0]
                pipb = vpg_pip_list[2]
                print(f"AWS Public IP (a): {pipa}")
                print(f"AWS Public IP (b): {pipb}")
            else:
                print("This is not a valid AWS Generic Extract - Check again or ask your fcking manager")


            if len(vpg_pip_list) >= 2:
                cgwa = cgw_list[3]
                cgwb = cgw_list[6]
                print(f"CGW-Internal (a): {cgwa}")
                print(f"CGW-Internal (b): {cgwb}")
            else:
                print("This is not a valid AWS Generic Extract - Check again or ask your fcking manager")


            if len(vpg_internal_list) >= 2:
                vpga = vpg_internal_list[1]
                vpgb = vpg_internal_list[3]
                print(f"VPG-Internal (a): {vpga}")
                print(f"VPG-Internal (b): {vpgb}")
            else:
                print("This is not a valid AWS Generic Extract - Check again or ask your fcking manager")


            aws_config = generate_aws_config( zone, log1, log2, cidr, name, file_path, pska, pskb, vpga, vpgb, cgwa, cgwb, pipa, pipb)
            return aws_config

    return render_template('aws.html')

@app.route('/s2s/error_log')
def error_log():
    with open('error.log', 'r') as log_file:
        lines = log_file.readlines()[-20:]  # Read the last 20 lines
    return render_template('error_log.html', lines=lines)

@app.route('/s2s/azure', methods=['GET', 'POST'])
def azure_config():
    if request.method == 'POST':
        psk1 = request.form['psk1']
        exip1 = request.form['exip1']
        zone = request.form['zone']
        log1 = request.form['log1']
        cidr = request.form['cidr']
        name = request.form['name']

        azure_config = generate_azure_config(psk1, exip1, zone, log1, cidr, name)
        return azure_config

    return render_template('azure.html')



def generate_aws_config( zone, log1, log2, cidr, name, file_path, pska, pskb, vpga, vpgb, cgwa, cgwb, pipa, pipb):
    config = f'''


set security ike proposal {name}-ike-proposal-1 authentication-method pre-shared-keys
set security ike proposal {name}-ike-proposal-1 dh-group group2
set security ike proposal {name}-ike-proposal-1 authentication-algorithm sha-256
set security ike proposal {name}-ike-proposal-1 encryption-algorithm aes-256-cbc
set security ike proposal {name}-ike-proposal-1 lifetime-seconds 28800

set security ike proposal {name}-ike-proposal-2 authentication-method pre-shared-keys
set security ike proposal {name}-ike-proposal-2 dh-group group2
set security ike proposal {name}-ike-proposal-2 authentication-algorithm sha-256
set security ike proposal {name}-ike-proposal-2 encryption-algorithm aes-256-cbc
set security ike proposal {name}-ike-proposal-2 lifetime-seconds 28800

set security ike policy {name}-ike-policy-1 mode main
set security ike policy {name}-ike-policy-1 proposals {name}-ike-proposal-1
set security ike policy {name}-ike-policy-1 pre-shared-key ascii-text "{pska}"

set security ike policy {name}-ike-policy-2 mode main
set security ike policy {name}-ike-policy-2 proposals {name}-ike-proposal-2
set security ike policy {name}-ike-policy-2 pre-shared-key ascii-text "{pskb}"

set security ike gateway {name}-ike-gw-1 ike-policy {name}-ike-policy-1
set security ike gateway {name}-ike-gw-1 address {pipa}
set security ike gateway {name}-ike-gw-1 dead-peer-detection interval 10
set security ike gateway {name}-ike-gw-1 dead-peer-detection threshold 3
set security ike gateway {name}-ike-gw-1 no-nat-traversal
set security ike gateway {name}-ike-gw-1 external-interface reth0.0
set security ike gateway {name}-ike-gw-1 version v2-only

set security ike gateway {name}-ike-gw-2 ike-policy {name}-ike-policy-2
set security ike gateway {name}-ike-gw-2 address {pipb}
set security ike gateway {name}-ike-gw-2 dead-peer-detection interval 10
set security ike gateway {name}-ike-gw-2 dead-peer-detection threshold 3
set security ike gateway {name}-ike-gw-2 no-nat-traversal
set security ike gateway {name}-ike-gw-2 external-interface reth0.0
set security ike gateway {name}-ike-gw-2 version v2-only

set security ipsec proposal {name}-ipsec-proposal-1 protocol esp
set security ipsec proposal {name}-ipsec-proposal-1 authentication-algorithm hmac-sha-256-128
set security ipsec proposal {name}-ipsec-proposal-1 encryption-algorithm aes-256-cbc
set security ipsec proposal {name}-ipsec-proposal-1 lifetime-seconds 3600

set security ipsec proposal {name}-ipsec-proposal-2 protocol esp
set security ipsec proposal {name}-ipsec-proposal-2 authentication-algorithm hmac-sha-256-128
set security ipsec proposal {name}-ipsec-proposal-2 encryption-algorithm aes-256-cbc
set security ipsec proposal {name}-ipsec-proposal-2 lifetime-seconds 3600

set security ipsec policy {name}-ipsec-policy-1 perfect-forward-secrecy keys group2
set security ipsec policy {name}-ipsec-policy-1 proposals {name}-ipsec-proposal-1

set security ipsec policy {name}-ipsec-policy-2 perfect-forward-secrecy keys group2
set security ipsec policy {name}-ipsec-policy-2 proposals {name}-ipsec-proposal-2

set security ipsec vpn {name}-ipsec-vpn-1 bind-interface st0.{log1}
set security ipsec vpn {name}-ipsec-vpn-1 df-bit clear
set security ipsec vpn {name}-ipsec-vpn-1 vpn-monitor source-interface st0.{log1}
set security ipsec vpn {name}-ipsec-vpn-1 vpn-monitor destination-ip {vpga}
set security ipsec vpn {name}-ipsec-vpn-1 ike gateway {name}-ike-gw-1
set security ipsec vpn {name}-ipsec-vpn-1 ike ipsec-policy {name}-ipsec-policy-1
set security ipsec vpn {name}-ipsec-vpn-1 establish-tunnels immediately

set security ipsec vpn {name}-ipsec-vpn-2 bind-interface st0.{log2}
set security ipsec vpn {name}-ipsec-vpn-2 df-bit clear
set security ipsec vpn {name}-ipsec-vpn-2 vpn-monitor source-interface st0.{log2}
set security ipsec vpn {name}-ipsec-vpn-2 vpn-monitor destination-ip {vpgb}
set security ipsec vpn {name}-ipsec-vpn-2 ike gateway {name}-ike-gw-2
set security ipsec vpn {name}-ipsec-vpn-2 ike ipsec-policy {name}-ipsec-policy-2
set security ipsec vpn {name}-ipsec-vpn-2 establish-tunnels immediately

set security zones security-zone {zone} interfaces st0.{log1}
set security zones security-zone {zone} interfaces st0.{log2}

set interfaces st0 unit {log1} description {name}-AWS-1
set interfaces st0 unit {log2} description {name}-AWS-2
set interfaces st0 unit {log1} family inet address {cgwa}
set interfaces st0 unit {log2} family inet address {cgwb}

set security address-book global address s.{cidr} {cidr}

set routing-options static route {cidr} next-hop st0.{log1}
set routing-options static route {cidr} qualified-next-hop st0.{log2} preference 100
'''

    return render_template('result.html', config=config)

def generate_azure_config(psk1, exip1, zone, log1, cidr, name):
    config = f'''

set security ike proposal {name}-ike-proposal authentication-method pre-shared-keys
set security ike proposal {name}-ike-proposal dh-group group2
set security ike proposal {name}-ike-proposal authentication-algorithm sha-256
set security ike proposal {name}-ike-proposal encryption-algorithm aes-256-cbc
set security ike proposal {name}-ike-proposal lifetime-seconds 28800

set security ike policy {name}-ike-policy mode main
set security ike policy {name}-ike-policy proposals {name}-ike-proposal
set security ike policy {name}-ike-policy pre-shared-key ascii-text "{psk1}"

set security ike gateway {name}-ike-gw ike-policy {name}-ike-policy
set security ike gateway {name}-ike-gw address {exip1}
set security ike gateway {name}-ike-gw external-interface reth0.0
set security ike gateway {name}-ike-gw version v2-only

set security ipsec proposal {name}-ipsec-proposal protocol esp
set security ipsec proposal {name}-ipsec-proposal authentication-algorithm hmac-sha-256-128
set security ipsec proposal {name}-ipsec-proposal encryption-algorithm aes-256-cbc
set security ipsec proposal {name}-ipsec-proposal lifetime-seconds 3600

set security ipsec policy {name}-ipsec-policy proposals {name}-ipsec-proposal

set security ipsec vpn {name}-ipsec bind-interface st0.{log1}
set security ipsec vpn {name}-ipsec df-bit clear
set security ipsec vpn {name}-ipsec ike gateway {name}-ike-gw
set security ipsec vpn {name}-ipsec ike ipsec-policy {name}-ipsec-policy
set security ipsec vpn {name}-ipsec establish-tunnels immediately

set security zones security-zone {zone} interface st0.{log1}

set interface st0 unit {log1} description {name}
set interfaces st0 unit {log1} family inet mtu 1436

set routing-options static route {cidr} next-hop st0.{log1}
'''

    return render_template('result.html', config=config)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5010)
