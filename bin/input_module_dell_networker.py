import datetime
import os
import json
import requests
import sys
import time
from requests.auth import HTTPBasicAuth

def validate_input(helper, definition):
    pass

def collect_events(helper, ew):

    # Get input settings
    global_account = helper.get_arg('global_account')
    nw_user = global_account['username']
    nw_password = global_account['password']
    nw_ip = helper.get_arg('nw_ip')
    nw_port = helper.get_arg('nw_port')
    
    # What to collect
    nw_dropdown  = helper.get_arg('nw_dropdown')

    # Starter log for error checking   
    helper.log_info("START: Beginning Networker collection for: " + nw_ip)
    start = time.time()
    try:
        for option in nw_dropdown:
            if option == 'alerts':
                alerts_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/alerts'
                alerts_response = requests.get(alerts_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                alerts_count = json.loads(alerts_response.text)['count']
                helper.log_info("Networker alerts: FOUND " + str(alerts_count) + "alerts for: " + nw_ip)
                alerts_counter = 0

                while alerts_counter < alerts_count:
                    alerts_path = json.loads(alerts_response.text)['alerts'][alerts_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:alerts", data=json.dumps(alerts_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker alerts: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker alerts: Cannot write alerts events for: " + nw_ip)    
                    alerts_counter += 1
 
            if option == 'auditlogconfig':
                auditlogconfig_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/auditlogconfig'
                auditlogconfig_response = requests.get(auditlogconfig_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                helper.log_info("Networker auditlogconfig: FOUND auditlogconfig for: " + nw_ip)
                try:
                    auditlogconfig_path = json.loads(auditlogconfig_response.text)
                    event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:auditlogconfig", data=json.dumps(auditlogconfig_path), done=True, unbroken=False)
                    ew.write_event(event)
                    helper.log_info("Networker auditlogconfig: Overview event data created for: " + nw_ip)
                except:
                    helper.log_error("Networker auditlogconfig: Cannot write auditlogconfig events for: " + nw_ip)   
 
            if option == 'backups':
                backups_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/backups'
                backups_response = requests.get(backups_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                backups_count = json.loads(backups_response.text)['count']
                helper.log_info("Networker backups: FOUND " + str(backups_count) + " backups for: " + nw_ip)
                backups_counter = 0

                while backups_counter < backups_count:
                    backups_path = json.loads(backups_response.text)['backups'][backups_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:backups", data=json.dumps(backups_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker backups: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker backups: Cannot write backups events for: " + nw_ip)    
                    backups_counter += 1

            if option == 'clients':
                clients_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/clients'
                clients_response = requests.get(clients_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                clients_count = json.loads(clients_response.text)['count']
                helper.log_info("Networker clients: FOUND " + str(clients_count) + " clients for: " + nw_ip)
                clients_counter = 0

                while clients_counter < clients_count:
                    clients_path = json.loads(clients_response.text)['clients'][clients_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:clients", data=json.dumps(clients_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker clients: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker clients: Cannot write clients events for: " + nw_ip)    
                    clients_counter += 1
                    
 #########not tested########
            if option == 'cloudboostappliances':
                cloudboostappliances_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/cloudboostappliances'
                cloudboostappliances_response = requests.get(cloudboostappliances_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                cloudboostappliances_count = json.loads(cloudboostappliances_response.text)['count']
                helper.log_info("Networker cloudboostappliances: FOUND " + str(cloudboostappliances_count) + "cloudboostappliances for: " + nw_ip)
                cloudboostappliances_counter = 0

                while cloudboostappliances_counter < cloudboostappliances_count:
                    cloudboostappliances_path = json.loads(cloudboostappliances_response.text)['cloudboostappliances'][cloudboostappliances_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:cloudboostappliances", data=json.dumps(cloudboostappliances_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker cloudboostappliances: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker cloudboostappliances: Cannot write cloudboostappliances events for: " + nw_ip)    
                    cloudboostappliances_counter += 1

            if option == 'datadomainsystems':
                datadomainsystems_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/datadomainsystems'
                datadomainsystems_response = requests.get(datadomainsystems_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                datadomainsystems_count = json.loads(datadomainsystems_response.text)['count']
                helper.log_info("Networker datadomainsystems: FOUND " + str(datadomainsystems_count) + " datadomainsystems for: " + nw_ip)
                datadomainsystems_counter = 0

                while datadomainsystems_counter < datadomainsystems_count:
                    datadomainsystems_path = json.loads(datadomainsystems_response.text)['dataDomainSystems'][datadomainsystems_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:datadomainsystems", data=json.dumps(datadomainsystems_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker datadomainsystems: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker datadomainsystems: Cannot write datadomainsystems events for: " + nw_ip)    
                    datadomainsystems_counter += 1

            if option == 'devices':
                devices_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/devices'
                devices_response = requests.get(devices_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                devices_count = json.loads(devices_response.text)['count']
                helper.log_info("Networker devices: FOUND " + str(devices_count) + " devices for: " + nw_ip)
                devices_counter = 0

                while devices_counter < devices_count:
                    devices_path = json.loads(devices_response.text)['devices'][devices_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:devices", data=json.dumps(devices_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker devices: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker devices: Cannot write devices events for: " + nw_ip)    
                    devices_counter += 1

            if option == 'directives':
                directives_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/directives'
                directives_response = requests.get(directives_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                directives_count = json.loads(directives_response.text)['count']
                helper.log_info("Networker directives: FOUND " + str(directives_count) + " directives for: " + nw_ip)
                directives_counter = 0

                while directives_counter < directives_count:
                    directives_path = json.loads(directives_response.text)['directives'][directives_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:directives", data=json.dumps(directives_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker directives: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker directives: Cannot write directives events for: " + nw_ip)    
                    directives_counter += 1

            if option == 'jobgroups':
                jobgroups_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/jobgroups'
                jobgroups_response = requests.get(jobgroups_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                jobgroups_count = json.loads(jobgroups_response.text)['count']
                helper.log_info("Networker jobgroups: FOUND " + str(jobgroups_count) + " jobgroups for: " + nw_ip)
                jobgroups_counter = 0

                while jobgroups_counter < jobgroups_count:
                    jobgroups_path = json.loads(jobgroups_response.text)['jobs'][jobgroups_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:jobgroups", data=json.dumps(jobgroups_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker jobgroups: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker jobgroups: Cannot write jobgroups events for: " + nw_ip)    
                    jobgroups_counter += 1

            if option == 'jobindications':
                jobindications_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/jobindications'
                jobindications_response = requests.get(jobindications_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                jobindications_count = json.loads(jobindications_response.text)['count']
                helper.log_info("Networker jobindications: FOUND " + str(jobindications_count) + " jobindications for: " + nw_ip)
                jobindications_counter = 0

                while jobindications_counter < jobindications_count:
                    jobindications_path = json.loads(jobindications_response.text)['jobIndications'][jobindications_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:jobindications", data=json.dumps(jobindications_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker jobindications: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker jobindications: Cannot write jobindications events for: " + nw_ip)    
                    jobindications_counter += 1

            if option == 'jobs':
                jobs_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/jobs'
                jobs_response = requests.get(jobs_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                jobs_count = json.loads(jobs_response.text)['count']
                helper.log_info("Networker jobs: FOUND " + str(jobs_count) + " jobs for: " + nw_ip)
                jobs_counter = 0

                while jobs_counter < jobs_count:
                    jobs_path = json.loads(jobs_response.text)['jobs'][jobs_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:jobs", data=json.dumps(jobs_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker jobs: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker jobs: Cannot write jobs events for: " + nw_ip)    
                    jobs_counter += 1

            if option == 'labels':
                labels_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/labels'
                labels_response = requests.get(labels_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                labels_count = json.loads(labels_response.text)['count']
                helper.log_info("Networker labels: FOUND " + str(labels_count) + " labels for: " + nw_ip)
                labels_counter = 0

                while labels_counter < labels_count:
                    labels_path = json.loads(labels_response.text)['labels'][labels_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:labels", data=json.dumps(labels_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker labels: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker labels: Cannot write labels events for: " + nw_ip)    
                    labels_counter += 1

            if option == 'licenses':
                licenses_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/licenses'
                licenses_response = requests.get(licenses_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                licenses_count = json.loads(licenses_response.text)['count']
                helper.log_info("Networker licenses: FOUND " + str(licenses_count) + " licenses for: " + nw_ip)
                licenses_counter = 0

                while licenses_counter < licenses_count:
                    licenses_path = json.loads(licenses_response.text)['licenses'][licenses_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:licenses", data=json.dumps(licenses_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker licenses: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker licenses: Cannot write licenses events for: " + nw_ip)    
                    licenses_counter += 1

            if option == 'lockbox':
                lockbox_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/lockbox'
                lockbox_response = requests.get(lockbox_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                lockbox_count = json.loads(lockbox_response.text)['count']
                helper.log_info("Networker lockbox: FOUND " + str(lockbox_count) + " lockbox for: " + nw_ip)
                lockbox_counter = 0

                while lockbox_counter < lockbox_count:
                    lockbox_path = json.loads(lockbox_response.text)['lockboxes'][lockbox_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:lockbox", data=json.dumps(lockbox_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker lockbox: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker lockbox: Cannot write lockbox events for: " + nw_ip)    
                    lockbox_counter += 1
###Test this one 
            if option == 'nasdevices':
                nasdevices_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/nasdevices'
                nasdevices_response = requests.get(nasdevices_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                nasdevices_count = json.loads(nasdevices_response.text)['count']
                helper.log_info("Networker nasdevices: FOUND " + str(nasdevices_count) + " nasdevices for: " + nw_ip)
                nasdevices_counter = 0

                while nasdevices_counter < nasdevices_count:
                    nasdevices_path = json.loads(nasdevices_response.text)['nasDevices'][nasdevices_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:nasdevices", data=json.dumps(nasdevices_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker nasdevices: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker nasdevices: Cannot write nasdevices events for: " + nw_ip)    
                    nasdevices_counter += 1

            if option == 'notifications':
                notifications_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/notifications'
                notifications_response = requests.get(notifications_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                notifications_count = json.loads(notifications_response.text)['count']
                helper.log_info("Networker notifications: FOUND " + str(notifications_count) + "notifications for: " + nw_ip)
                notifications_counter = 0

                while notifications_counter < notifications_count:
                    notifications_path = json.loads(notifications_response.text)['notifications'][notifications_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:notifications", data=json.dumps(notifications_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker notifications: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker notifications: Cannot write notifications events for: " + nw_ip)    
                    notifications_counter += 1

            if option == 'pools':
                pools_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/pools'
                pools_response = requests.get(pools_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                pools_count = json.loads(pools_response.text)['count']
                helper.log_info("Networker pools: FOUND " + str(pools_count) + " pools for: " + nw_ip)
                pools_counter = 0

                while pools_counter < pools_count:
                    pools_path = json.loads(pools_response.text)['pools'][pools_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:pools", data=json.dumps(pools_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker pools: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker pools: Cannot write pools events for: " + nw_ip)    
                    pools_counter += 1
###test this one
            if option == 'probes':
                probes_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/probes'
                probes_response = requests.get(probes_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                probes_count = json.loads(probes_response.text)['count']
                helper.log_info("Networker probes: FOUND " + str(probes_count) + " probes for: " + nw_ip)
                probes_counter = 0

                while probes_counter < probes_count:
                    probes_path = json.loads(probes_response.text)['probes'][probes_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:probes", data=json.dumps(probes_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker probes: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker probes: Cannot write probes events for: " + nw_ip)    
                    probes_counter += 1

            if option == 'protectiongroups':
                protectiongroups_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/protectiongroups'
                protectiongroups_response = requests.get(protectiongroups_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                protectiongroups_count = json.loads(protectiongroups_response.text)['count']
                helper.log_info("Networker protectiongroups: FOUND " + str(protectiongroups_count) + " protectiongroups for: " + nw_ip)
                protectiongroups_counter = 0

                while protectiongroups_counter < protectiongroups_count:
                    protectiongroups_path = json.loads(protectiongroups_response.text)['protectionGroups'][protectiongroups_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:protectiongroups", data=json.dumps(protectiongroups_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker protectiongroups: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker protectiongroups: Cannot write protectiongroups events for: " + nw_ip)    
                    protectiongroups_counter += 1

            if option == 'protectionpolicies':
                protectionpolicies_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/protectionpolicies'
                protectionpolicies_response = requests.get(protectionpolicies_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                protectionpolicies_count = json.loads(protectionpolicies_response.text)['count']
                helper.log_info("Networker protectionpolicies: FOUND " + str(protectionpolicies_count) + " protectionpolicies for: " + nw_ip)
                protectionpolicies_counter = 0

                while protectionpolicies_counter < protectionpolicies_count:
                    protectionpolicies_path = json.loads(protectionpolicies_response.text)['protectionPolicies'][protectionpolicies_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:protectionpolicies", data=json.dumps(protectionpolicies_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker protectionpolicies: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker protectionpolicies: Cannot write protectionpolicies events for: " + nw_ip)    
                    protectionpolicies_counter += 1
###dive into this one. going to need subsearches
            if option == 'recoverapps':
                recoverappssap_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/recoverapps/saphana'
                recoverappssql_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/recoverapps/sqlvdi'
                recoverappssap_response = requests.get(recoverappssap_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                recoverappssql_response = requests.get(recoverappssql_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                recoverappssap_count = json.loads(recoverappssap_response.text)['count']
                recoverappssql_count = json.loads(recoverappssql_response.text)['count']
                helper.log_info("Networker recoverappssap: FOUND " + str(recoverappssap_count) + " recoverapps for: " + nw_ip)
                helper.log_info("Networker recoverappssql: FOUND " + str(recoverappssql_count) + " recoverapps for: " + nw_ip)
                recoverappssap_counter = 0
                recoverappssql_counter = 0

                while recoverappssap_counter < recoverappssap_count:
                    recoverappssap_path = json.loads(recoverappssap_response.text)['recovers'][recoverappssap_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:recoverapps", data=json.dumps(recoverappssap_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker recoverappssap: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker recoverappssap: Cannot write recoverapps events for: " + nw_ip)    
                    recoverappssap_counter += 1

                while recoverappssql_counter < recoverappssql_count:
                    recoverappssql_path = json.loads(recoverappssql_response.text)['recovers'][recoverappssql_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:recoverapps", data=json.dumps(recoverappssql_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker recoverappssql: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker recoverappssql: Cannot write recoverapps events for: " + nw_ip)    
                    recoverappssql_counter += 1
###test this one
            if option == 'recovers':
                recovers_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/recovers'
                recovers_response = requests.get(recovers_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                recovers_count = json.loads(recovers_response.text)['count']
                helper.log_info("Networker recovers: FOUND " + str(recovers_count) + " recovers for: " + nw_ip)
                recovers_counter = 0

                while recovers_counter < recovers_count:
                    recovers_path = json.loads(recovers_response.text)['recovers'][recovers_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:recovers", data=json.dumps(recovers_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker recovers: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker recovers: Cannot write recovers events for: " + nw_ip)    
                    recovers_counter += 1
###test this one
            if option == 'rules':
                rules_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/rules'
                rules_response = requests.get(rules_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                rules_count = json.loads(rules_response.text)['count']
                helper.log_info("Networker rules: FOUND " + str(rules_count) + " rules for: " + nw_ip)
                rules_counter = 0

                while rules_counter < rules_count:
                    rules_path = json.loads(rules_response.text)['rules'][rules_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:rules", data=json.dumps(rules_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker rules: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker rules: Cannot write rules events for: " + nw_ip)    
                    rules_counter += 1

            if option == 'schedules':
                schedules_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/schedules'
                schedules_response = requests.get(schedules_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                schedules_count = json.loads(schedules_response.text)['count']
                helper.log_info("Networker schedules: FOUND " + str(schedules_count) + " schedules for: " + nw_ip)
                schedules_counter = 0

                while schedules_counter < schedules_count:
                    schedules_path = json.loads(schedules_response.text)['schedules'][schedules_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:schedules", data=json.dumps(schedules_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker schedules: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker schedules: Cannot write schedules events for: " + nw_ip)    
                    schedules_counter += 1

            if option == 'serverconfig':
                serverconfig_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/serverconfig'
                serverconfig_response = requests.get(serverconfig_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                serverconfig_count = json.loads(serverconfig_response.text)
                helper.log_info("Networker serverconfig: FOUND " + str(serverconfig_count) + " serverconfig for: " + nw_ip)

                serverconfig_path = json.loads(serverconfig_response.text)
                try:
                    event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:serverconfig", data=json.dumps(serverconfig_path), done=True, unbroken=False)
                    ew.write_event(event)
                    helper.log_info("Networker serverconfig: Overview event data created for: " + nw_ip)
                except:
                    helper.log_error("Networker serverconfig: Cannot write serverconfig events for: " + nw_ip)    

            if option == 'servermessages':
                servermessages_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/servermessages'
                servermessages_response = requests.get(servermessages_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                servermessages_count = json.loads(servermessages_response.text)['count']
                helper.log_info("Networker servermessages: FOUND " + str(servermessages_count) + " servermessages for: " + nw_ip)
                servermessages_counter = 0

                while servermessages_counter < servermessages_count:
                    servermessages_path = json.loads(servermessages_response.text)['serverMessages'][servermessages_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:servermessages", data=json.dumps(servermessages_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker servermessages: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker servermessages: Cannot write servermessages events for: " + nw_ip)    
                    servermessages_counter += 1

            if option == 'serverstatistics':
                serverstatistics_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/serverstatistics'
                serverstatistics_response = requests.get(serverstatistics_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                serverstatistics_count = json.loads(serverstatistics_response.text)
                helper.log_info("Networker serverstatistics: FOUND " + str(serverstatistics_count) + " serverstatistics for: " + nw_ip)

                serverstatistics_path = json.loads(serverstatistics_response.text)
                try:
                    event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:serverstatistics", data=json.dumps(serverstatistics_path), done=True, unbroken=False)
                    ew.write_event(event)
                    helper.log_info("Networker serverstatistics: Overview event data created for: " + nw_ip)
                except:
                    helper.log_error("Networker serverstatistics: Cannot write serverstatistics events for: " + nw_ip)    
                    
            if option == 'sessions':
                sessions_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/sessions'
                sessions_response = requests.get(sessions_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                sessions_count = json.loads(sessions_response.text)['count']
                helper.log_info("Networker sessions: FOUND " + str(sessions_count) + " sessions for: " + nw_ip)
                sessions_counter = 0

                while sessions_counter < sessions_count:
                    sessions_path = json.loads(sessions_response.text)['sessions'][sessions_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:sessions", data=json.dumps(sessions_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker sessions: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker sessions: Cannot write sessions events for: " + nw_ip)    
                    sessions_counter += 1

            if option == 'storagenodes':
                storagenodes_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/storagenodes'
                storagenodes_response = requests.get(storagenodes_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                storagenodes_count = json.loads(storagenodes_response.text)['count']
                helper.log_info("Networker storagenodes: FOUND " + str(storagenodes_count) + " storagenodes for: " + nw_ip)
                storagenodes_counter = 0

                while storagenodes_counter < storagenodes_count:
                    storagenodes_path = json.loads(storagenodes_response.text)['storageNodes'][storagenodes_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:storagenodes", data=json.dumps(storagenodes_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker storagenodes: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker storagenodes: Cannot write storagenodes events for: " + nw_ip)    
                    storagenodes_counter += 1
###test this one
            if option == 'tenants':
                tenants_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/tenants'
                tenants_response = requests.get(tenants_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                tenants_count = json.loads(tenants_response.text)['count']
                helper.log_info("Networker tenants: FOUND " + str(tenants_count) + " tenants for: " + nw_ip)
                tenants_counter = 0

                while tenants_counter < tenants_count:
                    tenants_path = json.loads(tenants_response.text)['tenants'][tenants_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:tenants", data=json.dumps(tenants_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker tenants: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker tenants: Cannot write tenants events for: " + nw_ip)    
                    tenants_counter += 1

            if option == 'timepolicies':
                timepolicies_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/timepolicies'
                timepolicies_response = requests.get(timepolicies_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                timepolicies_count = json.loads(timepolicies_response.text)['count']
                helper.log_info("Networker timepolicies: FOUND " + str(timepolicies_count) + " timepolicies for: " + nw_ip)
                timepolicies_counter = 0

                while timepolicies_counter < timepolicies_count:
                    timepolicies_path = json.loads(timepolicies_response.text)['timepolicies'][timepolicies_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:timepolicies", data=json.dumps(timepolicies_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker timepolicies: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker timepolicies: Cannot write timepolicies events for: " + nw_ip)    
                    timepolicies_counter += 1

            if option == 'usergroups':
                usergroups_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/usergroups'
                usergroups_response = requests.get(usergroups_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                usergroups_count = json.loads(usergroups_response.text)['count']
                helper.log_info("Networker usergroups: FOUND " + str(usergroups_count) + " usergroups for: " + nw_ip)
                usergroups_counter = 0

                while usergroups_counter < usergroups_count:
                    usergroups_path = json.loads(usergroups_response.text)['userGroups'][usergroups_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:usergroups", data=json.dumps(usergroups_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker usergroups: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker usergroups: Cannot write usergroups events for: " + nw_ip)    
                    usergroups_counter += 1

            if option == 'vmware':
                #protected vms scan
                protectedvms_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/vmware/protectedvms'
                protectedvms_response = requests.get(protectedvms_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                protectedvms_count = json.loads(protectedvms_response.text)['count']
                helper.log_info("Networker protectedvms: FOUND " + str(protectedvms_count) + " protectedvms for: " + nw_ip)
                protectedvms_counter = 0
                while protectedvms_counter < protectedvms_count:
                    protectedvms_path = json.loads(protectedvms_response.text)['vms'][protectedvms_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:protectedvms", data=json.dumps(protectedvms_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker protectedvms: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker protectedvms: Cannot write protectedvms events for: " + nw_ip)    
                    protectedvms_counter += 1
                
                #vCenter scan
                vcenters_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/vmware/vcenters'
                vcenters_response = requests.get(vcenters_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                vcenters_count = json.loads(vcenters_response.text)['count']
                helper.log_info("Networker vcenters: FOUND " + str(vcenters_count) + " vcenters for: " + nw_ip)
                vcenters_counter = 0

                while vcenters_counter < vcenters_count:
                    vcenters_path = json.loads(vcenters_response.text)['vCenters'][vcenters_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:vcenters", data=json.dumps(vcenters_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker vcenters: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker vcenters: Cannot write vcenters events for: " + nw_ip)    
                    vcenters_counter += 1
                
                #individual vm scan
                vms_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/vmware/vms'
                vms_response = requests.get(vms_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                vms_count = json.loads(vms_response.text)['count']
                helper.log_info("Networker vms: FOUND " + str(vms_count) + " vms for: " + nw_ip)
                vms_counter = 0

                while vms_counter < vms_count:
                    vms_path = json.loads(vms_response.text)['vms'][vms_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:vms", data=json.dumps(vms_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker vms: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker vms: Cannot write vms events for: " + nw_ip)    
                    vms_counter += 1
                
                #vproxies scan
                vproxies_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/vmware/vproxies'
                vproxies_response = requests.get(vproxies_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                vproxies_count = json.loads(vproxies_response.text)['count']
                helper.log_info("Networker vproxies: FOUND " + str(vproxies_count) + " vproxies for: " + nw_ip)
                vproxies_counter = 0

                while vproxies_counter < vproxies_count:
                    vproxies_path = json.loads(vproxies_response.text)['vProxies'][vproxies_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:vproxies", data=json.dumps(vproxies_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker vproxies: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker vproxies: Cannot write vproxies events for: " + nw_ip)    
                    vproxies_counter += 1

            if option == 'volumes':
                volumes_url = 'https://' + nw_ip + ':' + nw_port + '/nwrestapi/v3/global/volumes'
                volumes_response = requests.get(volumes_url, auth=HTTPBasicAuth(nw_user, nw_password),  verify=False)
                volumes_count = json.loads(volumes_response.text)['count']
                helper.log_info("Networker volumes: FOUND " + str(volumes_count) + " volumes for: " + nw_ip)
                volumes_counter = 0

                while volumes_counter < volumes_count:
                    volumes_path = json.loads(volumes_response.text)['volumes'][volumes_counter]
                    try:
                        event = helper.new_event(host=nw_ip, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="dell:networker:volumes", data=json.dumps(volumes_path), done=True, unbroken=False)
                        ew.write_event(event)
                        helper.log_info("Networker volumes: Overview event data created for: " + nw_ip)
                    except:
                        helper.log_error("Networker volumes: Cannot write volumes events for: " + nw_ip)    
                    volumes_counter += 1

    except:
        helper.log_error("Dell EMC Networker: URL not found for: " + nw_ip)
        
    # Finish up
    helper.log_info("FINISH: Ending collection for: " + nw_ip)
    end_time = round(time.time()-start,2)
    helper.log_info("FINISH: Dell EMC Networker collection took: " + str(end_time) + " secs to collect data for: " + nw_ip)