# app.py

from flask import Flask, render_template, request, session, redirect, url_for
import requests
import urllib3
import json
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

@app.route('/s2s/aws', methods=['GET', 'POST'])
def aws_config():
    if request.method == 'POST':
        psk1 = request.form['psk1']
        psk2 = request.form['psk2']
        exip1 = request.form['exip1']
        exip2 = request.form['exip2']
        zone = request.form['zone']
        int1 = request.form['int1']
        int2 = request.form['int2']
        int3 = request.form['int3']
        int4 = request.form['int4']
        log1 = request.form['log1']
        log2 = request.form['log2']
        cidr = request.form['cidr']
        name = request.form['name']

        aws_config = generate_aws_config(psk1, psk2, exip1, exip2, zone, int1, int2, int3, int4, log1, log2, cidr, name)
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

def generate_aws_config(psk1, psk2, exip1, exip2, zone, int1, int2, int3, int4, log1, log2, cidr, name):
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
set security ike policy {name}-ike-policy-1 pre-shared-key ascii-text "{psk1}"

set security ike policy {name}-ike-policy-2 mode main
set security ike policy {name}-ike-policy-2 proposals {name}-ike-proposal-2
set security ike policy {name}-ike-policy-2 pre-shared-key ascii-text "{psk2}"

set security ike gateway {name}-ike-gw-1 ike-policy {name}-ike-policy-1
set security ike gateway {name}-ike-gw-1 address {exip1}
set security ike gateway {name}-ike-gw-1 dead-peer-detection interval 10
set security ike gateway {name}-ike-gw-1 dead-peer-detection threshold 3
set security ike gateway {name}-ike-gw-1 no-nat-traversal
set security ike gateway {name}-ike-gw-1 external-interface reth0.0
set security ike gateway {name}-ike-gw-1 version v2-only

set security ike gateway {name}-ike-gw-2 ike-policy {name}-ike-policy-2
set security ike gateway {name}-ike-gw-2 address {exip2}
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
set security ipsec vpn {name}-ipsec-vpn-1 vpn-monitor destination-ip {int1}
set security ipsec vpn {name}-ipsec-vpn-1 ike gateway {name}-ike-gw-1
set security ipsec vpn {name}-ipsec-vpn-1 ike ipsec-policy {name}-ipsec-policy-1
set security ipsec vpn {name}-ipsec-vpn-1 establish-tunnels immediately

set security ipsec vpn {name}-ipsec-vpn-2 bind-interface st0.{log2}
set security ipsec vpn {name}-ipsec-vpn-2 df-bit clear
set security ipsec vpn {name}-ipsec-vpn-2 vpn-monitor source-interface st0.{log2}
set security ipsec vpn {name}-ipsec-vpn-2 vpn-monitor destination-ip {int2}
set security ipsec vpn {name}-ipsec-vpn-2 ike gateway {name}-ike-gw-2
set security ipsec vpn {name}-ipsec-vpn-2 ike ipsec-policy {name}-ipsec-policy-2
set security ipsec vpn {name}-ipsec-vpn-2 establish-tunnels immediately

set security zones security-zone {zone} interfaces st0.{log1}
set security zones security-zone {zone} interfaces st0.{log2}

set interfaces st0 unit {log1} description {name}-AWS-1
set interfaces st0 unit {log2} description {name}-AWS-2
set interfaces st0 unit {log1} family inet address {int3}
set interfaces st0 unit {log2} family inet address {int4}

set security address-book global address s.{cidr} {cidr}

set routing-options static route {cidr} next-hop st0.{log1}
set routing-options static route {cidr} qualified-next-hop st0.{log2}
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
    app.run(host='0.0.0.0', debug=True, port=5001)


