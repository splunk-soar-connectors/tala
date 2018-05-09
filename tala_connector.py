# File: tala_connector.py
# Copyright (c) 2018 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.# Phantom App imports

import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault as Vault

# Usage of the consts file is recommended
from tala_consts import *
import uuid
import os
# import shutil
import requests
import json
import datetime
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TalaConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(TalaConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        if 200 <= status_code < 399:
            return RetVal(phantom.APP_SUCCESS, json.loads(response.text))

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, json=None, data=None, method="get"):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            json=json,
                            data=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _download_file_to_vault(self, action_result, endpoint, json, file_name):
        """ Download a file and add it to the vault """

        guid = uuid.uuid4()
        tmp_dir = "/vault/tmp/{}".format(guid)
        zip_path = "{}/{}".format(tmp_dir, file_name)

        try:
            os.makedirs(tmp_dir)
        except Exception as e:
            msg = "Unable to create temporary folder '{}': ".format(tmp_dir)
            return action_result.set_status(phantom.APP_ERROR, msg, e)

        url = self._base_url + endpoint
        try:
            r = requests.post(
                str(url),
                json=json,
                headers={ 'Content-Type': 'application/json' }
            )
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "{}".format(str(e)))

        with open(zip_path, 'wb') as f:
            f.write(r.content)
            f.close()

        vault_path = "{}/{}".format(tmp_dir, file_name)

        vault_ret = Vault.add_attachment(vault_path, self.get_container_id(), file_name=file_name)
        if vault_ret.get('succeeded'):
            action_result.set_status(phantom.APP_SUCCESS, "Transferred file")
            summary = {
                    phantom.APP_JSON_VAULT_ID: vault_ret[phantom.APP_JSON_HASH],
                    phantom.APP_JSON_NAME: file_name,
                    phantom.APP_JSON_SIZE: vault_ret.get(phantom.APP_JSON_SIZE)}
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS, "Successfully added file to vault")
        else:
            action_result.set_status(phantom.APP_ERROR, "Error adding file to vault")

        return action_result.get_status()

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        headers = { 'auth-token': self._auth_token }

        self.save_progress("Connecting to endpoint /project to test connectivity")
        # make rest call
        ret_val, response = self._make_rest_call('/project', action_result, params=None, headers=headers)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_project(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        name = param['name']
        url = param['url']

        request = {
            "auth-token": self._auth_token,
            "name": name,
            "url": url
        }

        # make rest call
        ret_val, response = self._make_rest_call('/project', action_result, json=request, method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['project_id'] = response['id']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_project(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        id_param = param.get('project_ids', None)

        ids = dict()
        id_list = []
        if id_param:
            id_list = [int(i) for i in id_param.split(',')]
            ids['ids'] = ','.join([str(i) for i in id_list])

        headers = { 'auth-token': self._auth_token }

        # make rest call
        ret_val, response = self._make_rest_call('/project', action_result, params=ids, headers=headers)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        data = dict()
        for item in response:
            data.update({ item['id']: item })

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_projects'] = len(response)

        # Get project settings (triggered or manual)
        if not id_list:
            for item in response:
                id_list.append(item['id'])

        for project_id in id_list:
            params = { 'id': project_id }
            # make rest call
            ret_val, response = self._make_rest_call('/project/settings', action_result, params=params, headers=headers)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            data[project_id].update(response)

        # Add the response into the data section
        for item in data:
            action_result.add_data(data[item])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, TALA_GET_PROJECT_SUCC)

    def _handle_update_project(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        project_id = param['project_id']
        name = param.get('name', '')
        url = param.get('url', '')
        automation_mode = param.get('automation_mode')

        data = dict()
        if name or url:
            request = {
                "auth-token": self._auth_token,
                "id": project_id,
                "name": name,
                "url": url
            }

            # make rest call
            ret_val, response = self._make_rest_call('/project', action_result, json=request, method='put')

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            data.update(response)

        if automation_mode:
            settings_request = {
                'auth-token': self._auth_token,
                'automation-mode': automation_mode,
                'project-id': project_id
            }

            # make rest call
            ret_val, response = self._make_rest_call('/project/settings', action_result, json=settings_request, method='put')

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            data.update(response)

        if not name and not url and not automation_mode:
            return action_result.set_status(phantom.APP_ERROR, TALA_UPDATE_PROJECT_ERR)

        # Add the response into the data section
        action_result.add_data(data)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, TALA_UPDATE_PROJECT_SUCC)

    def _handle_delete_project(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        project_id = param['project_id']

        params = { 'id': project_id }
        headers = { 'auth-token': self._auth_token }

        # make rest call
        ret_val, response = self._make_rest_call('/project', action_result, params=params, headers=headers, method='delete')

        if (phantom.is_fail(ret_val)):
            message = action_result.get_message()
            if 'project not found' in message.lower():
                return action_result.set_status(phantom.APP_SUCCESS, TALA_ALREADY_DELETED_PROJECT_SUCC)
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, TALA_DELETE_PROJECT_SUCC)

    def _handle_create_scan(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        project_ids = param.get('project_ids', None)
        project_ids_list = [int(x) for x in project_ids.split(",")]

        request = {
            "auth-token": self._auth_token,
            "projectIDs": project_ids_list
        }

        # make rest call
        ret_val, response = self._make_rest_call('/scan', action_result, json=request, method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        for item in response['scan-initiation-status']:
            data = {"project-id": item}
            data.update(response['scan-initiation-status'][item])
            action_result.add_data(data)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['message'] = response['message']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_scan_setting(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        project_id = param['project_id']

        params = { 'project-id': project_id }
        headers = { 'auth-token': self._auth_token }

        # make rest call
        ret_val, response = self._make_rest_call('/scan/settings', action_result, params=params, headers=headers)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, TALA_GET_SCAN_SETTINGS_SUCC)

    def _handle_get_status(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        request = { 'auth-token': self._auth_token }

        # make rest call
        ret_val, response = self._make_rest_call('/scan/status', action_result, json=request, method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        for item in response:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_projects'] = len(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_summary(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        project_id = param['project_id']

        request = {
            'auth-token': self._auth_token,
            'projectID': project_id
        }

        # make rest call
        ret_val, response = self._make_rest_call('/scan/summary', action_result, json=request, method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['important_data'] = "value"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_download_policy_bundle(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        project_id = param['project_ids']
        tracking_id = param['tracking_id']

        request = {
            'auth-token': self._auth_token,
            'project': project_id,
            'tracking-id': tracking_id
        }

        file_name = "tala_AIM_bundle_ids{}_{}.zip".format(project_id.replace(',', '-'), tracking_id)

        # make rest call
        return self._download_file_to_vault(action_result, '/bundle', json=request, file_name=file_name)

    def _handle_synchronize_projects(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        scan_id = param['scan_id']
        project_ids = param['project_ids']

        request = {
            "auth-token": self._auth_token,
            "projects": [
                {
                    "scan-id": scan_id,
                    "ts": str(datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S"))
                }
            ],
            "projectIDs": [ int(x) for x in project_ids.split(',') ]
        }

        file_name = "tala_bundle_ids{}_{}.zip".format(project_ids.replace(',', '-'), scan_id)

        # make rest call
        return self._download_file_to_vault(action_result, '/sync', json=request, file_name=file_name)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'create_project':
            ret_val = self._handle_create_project(param)

        elif action_id == 'get_project':
            ret_val = self._handle_get_project(param)

        elif action_id == 'update_project':
            ret_val = self._handle_update_project(param)

        elif action_id == 'delete_project':
            ret_val = self._handle_delete_project(param)

        elif action_id == 'create_scan':
            ret_val = self._handle_create_scan(param)

        elif action_id == 'get_scan_setting':
            ret_val = self._handle_get_scan_setting(param)

        elif action_id == 'get_status':
            ret_val = self._handle_get_status(param)

        elif action_id == 'get_summary':
            ret_val = self._handle_get_summary(param)

        elif action_id == 'download_policy_bundle':
            ret_val = self._handle_download_policy_bundle(param)

        elif action_id == 'synchronize_projects':
            ret_val = self._handle_synchronize_projects(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config.get('base_url').rstrip('/')
        self._auth_token = config.get('auth_token')

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TalaConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
