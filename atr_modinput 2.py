#!/usr/bin/env python3
"""
ATR Modular Input Script - Refactored for Modularity

This script has been refactored to support modular usage of token generation and checkpoint functions.

Key Changes:
1. Global configuration variables are now set up once using setup_global_variables()
2. Token generation functions can be called from anywhere after setup
3. Checkpoint functions can be called from anywhere after setup
4. New utility functions for easier integration:
   - get_token_for_ticket_type(ticketType)
   - process_tickets_for_type(ticketType, sourcetype, index, ew)

Usage:
1. Call setup_global_variables(index, sourcetype) first
2. Then use any of the utility functions or main functions

Example:
    setup_global_variables("my_index", "my_sourcetype")
    token = get_token_for_ticket_type("incident")
    process_tickets_for_type("incident", "my_sourcetype", "my_index")
"""

import sys
import datetime
import calendar
import requests
import csv
from os import remove
from json import dumps as dict_to_json
from requests.auth import HTTPBasicAuth
from os.path import isfile as IfFileExists
from logging.handlers import RotatingFileHandler
import json
import pprint
from time import sleep
import requests
import json
import time
from os.path import isfile as file_exists
import urllib
import httplib2
import splunk_config as sconf
import os
from splunklib.modularinput import *
import ast
from configparser import SafeConfigParser
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from http.client import HTTPSConnection
import platform
import datetime
import time
from datetime import datetime
from datetime import timedelta
from aesUtil import AESCipher

import traceback
import logging
import custom_log
#Setting up the logger
custom_log.default_root_logger(file=__file__, level=logging.DEBUG)
logger = logging.getLogger(__name__)
logging.Formatter.converter = time.gmtime
logger.info("ATR Modinput started.")


warnings.simplefilter("ignore", InsecureRequestWarning)

try:
    # For c speedups
    from simplejson import loads, dumps
except ImportError:
    from json import loads, dumps

app_name = os.path.realpath(__file__).split(os.sep)[-3]
pull_sla = False

# Global variables for configuration
config = {}
sys_os = ""
atr_token_directory = ""
logging_directory = ""
checkpoint_directory = ""
BASE_TICKET_SYS_URL = ""
ATR_User = ""
ATR_Pass = ""
key = ""
start_date = ""
sortBy = ""
sortDirection = ""
record_count = ""

def setup_global_variables(index, sourcetype):
    """
    Initialize global configuration variables from splunk config.
    This function should be called before using any other functions that depend on these variables.
    """
    global config, sys_os, atr_token_directory, logging_directory, checkpoint_directory
    global BASE_TICKET_SYS_URL, ATR_User, ATR_Pass, key, start_date, sortBy, sortDirection, record_count

    logger.info("Setting up global configuration variables")

    # Get config details from splunk config script
    splunk_config = sconf.get_splunk_config(index, sourcetype)
    config = splunk_config["config"]

    # System OS detection
    sys_os = platform.system()
    logger.info(f"Operating System: {sys_os}")

    # Set directory paths based on OS
    if sys_os == 'Windows':
        atr_token_directory = "C:\\Program Files\\Splunk\\etc\\apps\\myWizardAiOps-atr-modular-input\\bin\\token\\"
        logging_directory = "C:\\Program Files\\Splunk\\etc\\apps\\myWizardAiOps-atr-modular-input\\bin\\logs\\"
        checkpoint_directory = "C:\\Program Files\\Splunk\\etc\\apps\\myWizardAiOps-atr-modular-input\\bin\\checkpoint_files\\"
    else:
        atr_token_directory = str(config["atr_token_directory"])
        logging_directory = str(config["logging_directory"])
        checkpoint_directory = str(config["checkpoint_directory"])

    # ATR configuration
    BASE_TICKET_SYS_URL = str(config["URL"])
    ATR_User = str(config["Username"])
    ATR_Pass = config["Password"]
    key = config["key"]
    ATR_Pass = AESCipher(key).decrypt(ATR_Pass)

    # Query parameters
    start_date = str(config["startDate"])
    sortBy = str(config["sortBy"])
    sortDirection = str(config["sortDirection"])
    record_count = str(config["recordCount"])

    logger.info("Global configuration variables setup completed")

def check_token(ticketType):
    """
    Check if token exists and is valid, using global configuration variables.
    """
    global BASE_TICKET_SYS_URL, ATR_User, ATR_Pass, atr_token_directory, logging_directory

    logger.info('###################### Check Token if exists #########################')
    logger.info('Checking API token.')

    #Number of days after which token will be re-generated from created_on
    TOKEN_VALIDITY_DAYS = 2

    # Construct token file path
    url = BASE_TICKET_SYS_URL + "/atr-gateway/identity-management/api/v1/auth/token"
    atr_token_file = atr_token_directory + 'atr_' + ticketType + '.json'

    if not file_exists(atr_token_file):
        # If token is not found, generate new token.
        logger.info('No API token found. Starting token generation.')
        generate_token(ticketType)
    else:
        logger.info('API token found. Checking token age.')

        try:
            token_dict = load_token(ticketType)
            if token_dict is None:
                logger.info("Failed to load token. Regenerating token.")
                generate_token(ticketType)
                return

            created_on = token_dict.get('created_on')

            if created_on is None:
                logger.info("No 'created_on' field found in token. Regenerating token.")
                generate_token(ticketType)
                return

            current_time = int(time.time())
            age_seconds = current_time - int(created_on)
            max_age_seconds = TOKEN_VALIDITY_DAYS * 24 * 60 * 60

            if age_seconds > max_age_seconds:
                logger.info(f'Token is older than {TOKEN_VALIDITY_DAYS} Days. Regenerating token.')
                generate_token(ticketType)
            else:
                logger.info(f'Token is still valid. Age: {age_seconds} seconds.')
        except Exception as e:
            logger.info(f"Error checking token age: {str(e)}. Regenerating token.")
            generate_token(ticketType)


def generate_token(ticketType):
    """
    Generate a new token using global configuration variables.
    """
    global BASE_TICKET_SYS_URL, ATR_User, ATR_Pass, atr_token_directory, logging_directory

    logger.info('######################### Generate Token ###################################')

    # Construct URLs and file paths
    url = BASE_TICKET_SYS_URL + "/atr-gateway/identity-management/api/v1/auth/token"
    atr_token_file = atr_token_directory + 'atr_' + ticketType + '.json'

    logger.info("Token URL : " + str(url))

    try:
        headers = {'Content-Type': 'application/json;charset=utf-8', 'Accept': '*/*'}
        ATR_data = '{"username": "' + ATR_User + '", "password":"' + ATR_Pass + '"}'
    except Exception as e:
        logger.info("Error in getting details" + str(e))

    try:
        response = requests.post(url, headers=headers, data=ATR_data, verify=False)
        response_code = str(response.status_code)

        if response_code == "200":
            res_body = response.json()

            # Add the current time in epoch format
            res_body['created_on'] = int(time.time())

            # Write to file
            with open(atr_token_file, "w") as f:
                json.dump(res_body, f)

            logger.info('Token generation successful and written to a file: ' + str(atr_token_file))
        elif response_code == "504":
            logger.info("Didn't receive a token from API. Timed Out..")
        else:
            logger.info("API didn't respond with a token. Failed...")
    except Exception as e:
        logger.info('Token request generation unsuccessful. Error: ' + str(e))


def load_token(ticketType):
    """
    Load token from file using global configuration variables.
    """
    global atr_token_directory

    logger.info('######################### Load Token ###################################')

    # Construct token file path
    atr_token_file = atr_token_directory + 'atr_' + ticketType + '.json'

    try:
        with open(atr_token_file) as f:
            config = json.load(f)
            token_detail = {}
            token_detail['token'] = config['token']
            token_detail['expirationDate'] = config['expirationDate']
            token_detail['created_on'] = config['created_on']
            logger.info('token loaded successful returning token')
        return token_detail
    except Exception as e:
        logger.info('Error in accessing token. Error: ' + str(e))
        return None


def check_point(Token, ticketType):
    """
    Handle checkpoint logic using global configuration variables.
    """
    global BASE_TICKET_SYS_URL, sortBy, sortDirection, record_count, start_date, checkpoint_directory

    response_body = json.dumps(Token)

    ATR_token = Token['token']
    ATR_token_exp_date = Token['expirationDate']
    logger.info("Token extracted from file")

    # Construct checkpoint file path
    checkpoint_file = checkpoint_directory + ticketType + "_cp_timestamp.json"

    cp_ticket_id = " "
    num_records = 0
    page_num = 0
    ticketDumpResponseContent = []

    if IfFileExists(checkpoint_file):
        logger.info('######################### Check point file exists ###################################')
        with open(checkpoint_file) as data:
            checkpoint_data = json.load(data)
            cp_value = checkpoint_data["timestamp"]
            logger.info('Check point file found = ' + cp_value)
            cp_value = datetime.strptime(cp_value, "%Y-%m-%d %H:%M:%S")
            cp_value = (cp_value - timedelta(minutes=1))
            cp_value = cp_value.strftime("%Y-%m-%d %H:%M:%S")
            logger.info('Check point file after 1 min behind = ' + str(cp_value))
            cp_value = str(cp_value)
    else:
        cp_value = start_date
        logger.info("No check point file found")
    cp_value = cp_value.replace(" ", "+")
    ticketSysHeaders = {'Accept': '*/*', 'apiToken': ATR_token}
    logger.info('API token for get request')

    APPEND_TICKET_SYS_URL = "/atr-gateway/ticket-management/api/v1/tickets?ticketType=" + ticketType + "&sortBy=" + sortBy + "&sortDirection=" + sortDirection + "&start=" + cp_value + "&perPage=" + record_count
    URL = BASE_TICKET_SYS_URL + APPEND_TICKET_SYS_URL
    logger.info(URL)
    try:
        ticketDumpResponse = requests.get(URL, headers=ticketSysHeaders, verify=False, timeout=60)
        DumpResponse_code = str(ticketDumpResponse.status_code)

        if DumpResponse_code == "200":
            logger.info("Ticket dump received successfully")
        elif DumpResponse_code == "403":
            logger.info("Token expired, regenerating token and retrying...")

            # Regenerate token
            try:
                generate_token(ticketType)

                # Load new token
                new_token = load_token(ticketType)
                if new_token is None:
                    logger.error("Failed to load new token after regeneration")
                    return [[], cp_value, checkpoint_file, ticketType]

                # Update headers with new token
                new_ATR_token = new_token['token']
                ticketSysHeaders = {'Accept': '*/*', 'apiToken': new_ATR_token}
                logger.info("Updated headers with new token")

                # Retry the API call when Response code is 403
                logger.info("Retrying API call with new token...")
                try:
                    ticketDumpResponse = requests.get(URL, headers=ticketSysHeaders, verify=False, timeout=60)
                    DumpResponse_code = str(ticketDumpResponse.status_code)
                    logger.info(f"Retry: Response received.")

                    if DumpResponse_code == "200":
                        logger.info(f"Retry: Ticket dump received.")
                    elif DumpResponse_code == "403":
                        logger.error("Still getting 403 after token regeneration. There might be an authentication issue.")
                        return [[], cp_value, checkpoint_file, ticketType]
                    elif DumpResponse_code != "200" and DumpResponse_code != "403":
                        logger.error(f"Unexpected response code after retry: {DumpResponse_code}")
                        return [[], cp_value, checkpoint_file, ticketType]

                except Exception as e:
                    logger.error(f"Error during retry API call: {str(e)}")
                    logger.error(f"Traceback: {traceback.format_exc()}")
                    return [[], cp_value, checkpoint_file, ticketType]

            except Exception as e:
                logger.error(f"Error during token regeneration: {str(e)}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                return [[], cp_value, checkpoint_file, ticketType]
        elif DumpResponse_code == "500":
            logger.error(f"ATR Seems Down.. Check ATR instance.")
            return [[], cp_value, checkpoint_file, ticketType]
        elif DumpResponse_code != "200" and DumpResponse_code != "403" and DumpResponse_code != "500":
            logger.error(f"Unexpected Error occured.")
            return [[], cp_value, checkpoint_file, ticketType]

    except Exception as e:
        logger.error(f"Ticket dump not received: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return [[], cp_value, checkpoint_file, ticketType]

    # Parse response
    try:
        tempTickets = ticketDumpResponse.json()
        ticketDumpResponseContent.extend(tempTickets)
        logger.info(f"Successfully parsed {len(tempTickets)} tickets from API response")
    except Exception as e:
        logger.error(f"Error parsing JSON response: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return [[], cp_value, checkpoint_file, ticketType]

    # Return the ticket data, checkpoint value, and checkpoint file
    return [ticketDumpResponseContent, cp_value, checkpoint_file, ticketType]

def tic_data(token_data, chkpoint_value, chk_file, ticketType, sourcetype, ew, index, splunk_service_object):
    """
    Process ticket data using global configuration variables.
    """
    global start_date

    num_records = len(token_data)
    logger.info(f"Number of tickets found after timestamp - {str(num_records)} For Ticket Type: {ticketType}")
    num_tickets = 0
    if num_records == 0:
        timestamp = start_date
        logger.info("Number of tickets found is 0")

    else:
        timestamp = token_data[num_records - 1]["allFields"]["lastUpdateDate"]
        logger.info(f"timestamp of last ticket : {str(timestamp)}")
        ticket_id = token_data[num_records - 1]["allFields"]["id"]
        logger.info(f"ticket_id of last ticket : {str(ticket_id)}")
        cp_value = chkpoint_value.replace("+", " ")
        logger.info(f"cp_value : {str(cp_value)}")

        if timestamp == cp_value:
            logger.info(f"timestamp = {str(timestamp)}  cp_value = {str(cp_value)}")
            logger.info("Timestamp of the last ticket is same as the checkpoint file timestamp")
            logger.info("No new tickets to fetch from ATR.")
        else:
            logger.info(f"Timestamp of first ticket : {str(token_data[0]['allFields']['lastUpdateDate'])}")
            lastUpdateDate = (token_data[0]["allFields"]["lastUpdateDate"])
            logger.info(f"lastUpdateDate : {str(lastUpdateDate)}")
            if lastUpdateDate == cp_value:
                del token_data[0]
                logger.info("Timestamp of check point file and first ticket are same deleting the first ticket data to avoid duplicates")
            for i in token_data:
                for field, dic_data in i.items():
                    if field == "allFields":
                        if "comments_and_work_notes" in dic_data:
                            if len(dic_data["comments_and_work_notes"]) >= 50:
                                dic_data["comments_and_work_notes"] = (dic_data["comments_and_work_notes"][:50].splitlines())
                                logger.info("comments_and_work_notes limiting to 50 characters")
                        if "description" in dic_data:
                            if len(dic_data["description"]) >= 50:
                                dic_data["description"] = (dic_data["description"][:50].splitlines())
                                logger.info("description limiting to 50 characters")
                        if "close_notes" in dic_data:
                            if len(dic_data["close_notes"]) >= 50:
                                dic_data["close_notes"] = (dic_data["close_notes"][:50].splitlines())
                                logger.info("close_notes limiting to 50 characters")
                        if "work_notes" in dic_data:
                            if len(dic_data["work_notes"]) >= 50:
                                dic_data["work_notes"] = (dic_data["work_notes"][:50].splitlines())
                                logger.info("work_notes limiting to 50 characters")
                        if "work_notes_list" in dic_data:
                            if len(dic_data["work_notes_list"]) >= 50:
                                dic_data["work_notes_list"] = (dic_data["work_notes_list"][:50].splitlines())
                                logger.info("work_notes_list limiting to 50 characters")
                        if "longDescription" in dic_data:
                            if len(dic_data["longDescription"]) >= 50:
                                dic_data["longDescription"] = (dic_data["longDescription"][:50].splitlines())
                                logger.info("longDescription limiting to 50 characters")
                        if "source" in dic_data:
                            del dic_data["source"]
                        dic_data = json.dumps(dic_data, sort_keys=True, indent=4)
                        dic_data = json.loads(dic_data)
                        dic_data = {k: 'Not Defined' if not v else v for k, v in dic_data.items()}
                        dic_data = json.dumps(dic_data, sort_keys=True, indent=4)
                        dic_data = dic_data.replace('\r', '')
                        dic_data = dic_data.replace('\n', '')
                        dic_data = dic_data.replace('\t', '')
                        dic_data = dic_data.replace('UNKNOWN', 'Not Defined')

                        # ...existing HTTP Event Writer code...

                        if (splunk_service_object is not None):
                            # New Method - using splunk service object for direct connection
                            try:
                                index_to_write = splunk_service_object.indexes[index]
                            except Exception as e:
                                logger.error(f"Index {index} not found or not accessible: {e}")
                                return
                            try:
                                # Submit the event to Splunk
                                index_to_write.submit(dic_data, sourcetype=sourcetype)
                                num_tickets += 1
                                logger.info(f"Total number of tickets indexed to splunk : {num_tickets}")
                            except Exception as e:
                                logger.error(f"Failed to index event: {e}, Traceback: {traceback.format_exc()}")

                        # ...existing commented code...

                        json_data = {'ticket_id': ticket_id, 'timestamp': timestamp}
                        with open(chk_file, 'w') as outfile:
                            json.dump(json_data, outfile)

    logger.info('Events are indexed to splunk')
    logger.info('timestamp written to checkpoint file')
    logger.info('Exiting script')
    logger.info('#################################################################################################')


def sla_tic_data(token_data, chkpoint_value, chk_file, ticketType, sourcetype, ew, index, splunk_service_object):
    """
    SLA Version Of Tic-Data using global configuration variables.
    """
    global start_date

    num_records = len(token_data)
    logger.info('Number of tickets found after timestamp: ' + str(num_records))
    logger.info("Ticket Type is: " + str(ticketType))
    num_tickets = 0

    if num_records == 0:
        timestamp = start_date
        logger.info('Number of tickets found is 0')

    else:
        timestamp = token_data[num_records - 1]["allFields"]["lastUpdateDate"]
        logger.info('Timestamp of last ticket: ' + str(timestamp))
        ticket_id = token_data[num_records - 1]["allFields"]["id"]
        logger.info('Ticket ID of last ticket: ' + str(ticket_id))
        cp_value = chkpoint_value.replace("+", " ")
        logger.info("Checkpoint value: " + str(cp_value))

        if timestamp == cp_value:
            logger.info("Timestamp of the last ticket matches the checkpoint file timestamp. No new tickets to fetch.")
        else:
            logger.info("Timestamp of the first ticket: " + str(token_data[0]["allFields"]["lastUpdateDate"]))
            lastUpdateDate = token_data[0]["allFields"]["lastUpdateDate"]
            logger.info("Last update date: " + str(lastUpdateDate))
            if lastUpdateDate == cp_value:
                del token_data[0]
                logger.info("Deleted first ticket data to avoid duplicates.")

            for i in token_data:
                record = {}
                for field, dic_data in i.items():
                    if field == "allFields":
                        # Process large fields for truncation
                        for key in ["comments_and_work_notes", "description", "close_notes", "work_notes", "work_notes_list", "longDescription"]:
                            if key in dic_data and len(dic_data[key]) >= 5000:
                                dic_data[key] = (dic_data[key][:5000].splitlines())
                                logger.info(f"{key} limited to 5000 characters")

                        # Remove unnecessary fields
                        for key in ["source"]:
                            if key in dic_data:
                                del dic_data[key]

                        # Normalize missing values and clean strings
                        dic_data = {k: 'Not Defined' if not v else v for k, v in dic_data.items()}
                        dic_data = json.dumps(dic_data, sort_keys=True, indent=4).replace('\r', '').replace('\n', '').replace('\t', '').replace('UNKNOWN', 'Not Defined')
                        dic_data = json.loads(dic_data)

                        record["allData"] = dic_data  # Append allData to the record dictionary

                    if field == "slaData":
                        record["slaData"] = dic_data  # Append slaData to the record dictionary

                # SLA Data Handling: Create multiple JSON objects if SLA records exist
                json_sla_data = []
                if "slaData" in record and record["slaData"]:
                    for sla_record in record["slaData"]:  # Process each SLA record
                        new_sla_record = {}
                        for k, v in sla_record.items():
                            key = "sla_{}".format(k)  # Prefix SLA fields
                            new_sla_record[key] = v
                        new_sla_record.update(record["allData"])  # Merge SLA data with allData
                        json_sla_data.append(new_sla_record)
                else:
                    json_sla_data.append(record["allData"])  # Single record if no SLA data exists

                # Submit each JSON object to Splunk
                for json_obj in json_sla_data:
                    json_obj_str = json.dumps(json_obj)  # Convert to JSON string for indexing
                    if splunk_service_object is not None:
                        try:
                            index_to_write = splunk_service_object.indexes[index]
                            index_to_write.submit(json_obj_str, sourcetype=sourcetype)
                            num_tickets += 1
                            logger.info(f"Total number of tickets indexed to Splunk: {num_tickets}")
                        except Exception as e:
                            logger.error(f"Failed to index event: {e}, Traceback: {traceback.format_exc()}")

                # Update checkpoint file with the last processed ticket details
                json_data = {'ticket_id': ticket_id, 'timestamp': timestamp}
                with open(chk_file, 'w') as outfile:
                    json.dump(json_data, outfile)

    logger.info('Events are indexed to Splunk')
    logger.info('Timestamp written to checkpoint file')
    logger.info('Exiting script')
    logger.info('#################################################################################################')



def get_token_for_ticket_type(ticketType):
    """
    Utility function to get token for a specific ticket type.
    Can be called from anywhere after setup_global_variables() is called.
    """
    check_token(ticketType)
    return load_token(ticketType)

def process_tickets_for_type(ticketType, sourcetype, index, ew=None):
    """
    Utility function to process tickets for a specific ticket type.
    Can be called from anywhere after setup_global_variables() is called.
    """
    # Initialize splunk service object
    splunk_service_object = sconf.initialize_splunk_service()
    logger.info(f"Service Object created for ticket type: {ticketType}")

    # Get token
    Token = get_token_for_ticket_type(ticketType)

    # Get checkpoint and ticket data
    token_data, chkpoint_value, chk_file, ticketType = check_point(Token, ticketType)

    # Process tickets
    try:
        if pull_sla == False:
            records = tic_data(token_data, chkpoint_value, chk_file, ticketType, sourcetype, ew, index, splunk_service_object)
        else:
            records = sla_tic_data(token_data, chkpoint_value, chk_file, ticketType, sourcetype, ew, index, splunk_service_object)
        return records
    except Exception as e:
        logger.error(f"Error occurred while processing tickets for {ticketType}: {e}, traceback: {traceback.format_exc()}")
        return None

def get_data_main(index, sourcetype, ticketType, ew):
    """
    Main function to get data - now uses global configuration variables.
    """
    # Setup global configuration variables
    try:
        setup_global_variables(index, sourcetype)
        logger.info("Global configuration variables setup completed successfully")
    except Exception as e:
        logger.error(f"Error occurred while setting up global configuration variables: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return

    # Process tickets using the utility function
    try:
        process_tickets_for_type(ticketType, sourcetype, index, ew)
        logger.info("Ticket processing completed successfully")
    except Exception as e:
        logger.error(f"Error occurred while processing tickets for {ticketType}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")

################################################################################


def main(argv):
    try:
        get_data_main("mywiz360_itsm_ticket_idx", "atr_incidents", "incident", None)
    except Exception as e:
        logger.info(f"Error occured : {e} :: Traceback : {traceback.format_exc()}")


if __name__ == "__main__":
    main(sys.argv[1:])
