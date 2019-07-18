#!/usr/bin/env python

'''
Copyright (c) 2011-2018, Hortonworks Inc.  All rights reserved.
Except as expressly permitted in a written agreement between you
or your company and Hortonworks, Inc, any use, reproduction,
modification,
redistribution, sharing, lending or other exploitation
of all or any part of the contents of this file is strictly prohibited.
For any questions or suggestions please contact : ayusuf@hortonworks.com
'''

import sys
import os
import re
import json
import cStringIO
import getpass
import argparse
import pycurl

# curl -ik -u admin:admin -H 'X-Requested-By: ambari' -X DELETE http://vb-atlas-ambari.openstacklocal:8080/api/v1/clusters/vinod/privileges/###

version = '1.0'
username = 'admin'
port = '8080'
ssl_enabled = False

def run_curl(url, username, password, http_method = 'GET', json_data = None):
    c = pycurl.Curl()
    c.setopt(pycurl.URL, url)
    c.setopt(pycurl.HTTPHEADER, ['X-Requested-By: ambari'])
    if http_method == 'POST':
        c.setopt(pycurl.POST, 1)
        c.setopt(pycurl.POSTFIELDS, json_data)
    elif http_method == 'DELETE':
        c.setopt(pycurl.CUSTOMREQUEST, 'DELETE')
    s = cStringIO.StringIO()
    c.setopt(c.WRITEFUNCTION, s.write)
    c.setopt(pycurl.SSL_VERIFYPEER, 0)
    c.setopt(pycurl.SSL_VERIFYHOST, 0)
    c.setopt(pycurl.USERPWD, (username + ':' + password))
    c.perform()
    return c.getinfo(pycurl.HTTP_CODE), s.getvalue()

def get_entity_role_mapping(conf_file):
    if not os.path.isfile(conf_file):
        parser.error('please provide a valid file for --users and --groups parameters.')

    entity_role_map = { 'CLUSTER.ADMINISTRATOR': [], 'CLUSTER.OPERATOR': [], 'CLUSTER.USER': [],
                        'SERVICE.ADMINISTRATOR': [], 'SERVICE.OPERATOR': [] }
    regex = re.compile('\[\[(.+)\]\]')
    current_role = ''
    with open(conf_file) as file:
        for line in file:
            line = line.strip()
            if line and line[0] != '#':
                match = regex.search(line)
                if match:
                    role = match.group(1)
                    if role in entity_role_map:
                        current_role = role
                    else:
                        sys.stderr.write("Invalid role : '%s' in the config file %s\n" % (role, conf_file))
                        current_role = ''
                elif current_role != '':
                    entity_role_map[current_role].append(line)
    return entity_role_map

def get_configured_roles(url, username, password):
    previleges = []
    resp_code, result = run_curl(url, username, password)
    if resp_code == 200:
        roles = json.loads(result)['items']
        for role in roles:
            previlege_id = role['PrivilegeInfo']['privilege_id']
            status, response = run_curl(url + '/' + str(previlege_id), username, password)
            if status == 200:
                info = json.loads(response)['PrivilegeInfo']
                previlege = {}
                previlege['id'] = previlege_id
                previlege['principal_type'] = info['principal_type']
                previlege['principal_name'] = info['principal_name']
                previlege['permission_name'] = info['permission_name']
                previleges.append(previlege)
    return previleges

def delete_all_roles(url, previleges):
    for previlege in previleges:
        role_url = url + '/' + str(previlege['id'])
        resp_code, result = run_curl(role_url, username, password, 'DELETE')
        if resp_code != 200:
            print 'Unable to delete : ' + role_url
        else:
            print "Deleted -> %s : '%s' as '%s'" % (previlege['principal_type'], previlege['principal_name'],
                                                    previlege['permission_name'])

def get_role_url(ambari_server, port, clustername, ssl_enabled = False):
    if (ssl_enabled):
        url = 'https://%s:%s/api/v1/clusters/%s/privileges' % (ambari_server, port, clustername)
    else:
        url = 'http://%s:%s/api/v1/clusters/%s/privileges' % (ambari_server, port, clustername)
    return url

def configure_users_or_groups(principal_type, role_entity_mapping_dict):
    error_str = 'Could not find %s' % principal_type
    for role in role_entity_mapping_dict:
        for entity in role_entity_mapping_dict[role]:
            payload = { 'PrivilegeInfo': { 'permission_name': role, 'principal_name': entity, 'principal_type': principal_type } }
            resp_code, message = run_curl(url, username, password, 'POST', json.dumps(payload))
            if resp_code == 201:
                print "Succeeded -> %s : '%s' as '%s'\n" % (principal_type, entity, role)
            elif resp_code == 409 or (resp_code == 500 and error_str in message):	
                print "Failed -> %s : '%s' as '%s' :\n%s\n" % (principal_type, entity, role, message)
            else:
                errorString = "Error executing the URL: '%s' for the username: '%s'\n" % (url, username)
                sys.stderr.write(errorString)
                sys.stderr.write(message + '\n')
                sys.exit(1)

def confirm_action(principal_type, role_entity_mapping_dict):
    atleast_one = False
    print '\nBelow are all the %s(s) and ROLEs to be updated:' % principal_type
    for role in role_entity_mapping_dict:
        for entity in role_entity_mapping_dict[role]:
            atleast_one = True
            print '- ' + entity + ' : ' + role
    if atleast_one:
        response = raw_input("Do you want to proceed (y/n)? [n] : ")
        if response.strip().lower() == 'y':
            return True
    else:
        print 'There are no valid %s(s) to update.\n' % principal_type
    return False

## Program Start ##
description = 'Version %s. \nScript to configure service and cluster roles for users and groups in Ambari' % version
parser = argparse.ArgumentParser(description=description)
parser.add_argument('-a', '--ambari_host', help='IP/Hostname of the Ambari Server', required=True)
parser.add_argument('-p', '--port', help='Port number for Ambari Server. Default: 8080', required=False)
parser.add_argument('-u', '--username', help='Username for Ambari UI. Default: admin. Will be prompted for the password', required=False)
parser.add_argument('-c', '--clustername', help='Name of the cluster. Default: First available cluster name in Ambari', required=True)
parser.add_argument('-s', '--ssl_enabled', help='Whether SSL is enabled for Ambari URL.', action='store_true')
parser.add_argument('--users', help='Text file containing user <-> role mapping', required=False, metavar='USERS_FILE')
parser.add_argument('--groups', help='Text file containing group <-> role mapping', required=False, metavar='GROUPS_FILE')
parser.add_argument('--remove_all_roles', help='Flag to remove all configured roles. \
                            If this option is provided, --users/--groups will be ignored', action='store_true')
args = parser.parse_args()
if not (args.remove_all_roles or args.users or args.groups):
    parser.error('atleast one of --users/--groups/--remove_all_roles is required.')

ambari_server = args.ambari_host
if args.port:
    port = args.port
if args.username:
    username = args.username
if args.clustername:
    clustername = args.clustername
if args.ssl_enabled:
    ssl_enabled = True
password = getpass.getpass('Ambari password for username [%s]: ' % (username))
if not password:
    password = 'admin'

url = get_role_url(ambari_server, port, clustername, ssl_enabled)
if args.remove_all_roles:
    configured_roles = get_configured_roles(url, username, password)
    if configured_roles:
        print 'Below are the configured roles:'
        for role in configured_roles:
            print '- ' + role['principal_type'] + ' : ' + "'%s' as '%s'" % (role['principal_name'], role['permission_name'])
        response = raw_input("Are you sure you want to remove all the above roles (y/n)? [n] : ")
        if response.strip().lower() == 'y':
            delete_all_roles(url, configured_roles)
    else:
        print 'There are no roles configured.'
        sys.exit(1)
else:
    if args.users:
        role_users_dict = get_entity_role_mapping(args.users)
        if confirm_action('USER', role_users_dict):
            configure_users_or_groups('USER', role_users_dict)
    if args.groups:
        role_groups_dict = get_entity_role_mapping(args.groups)
        if confirm_action('GROUP', role_groups_dict):
            configure_users_or_groups('GROUP', role_groups_dict)




