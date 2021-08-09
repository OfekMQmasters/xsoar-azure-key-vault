import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests

'''CONSTANTS'''
APP_NAME = 'azure-key-vault'

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

API_VERSION = '2019-09-01'

# AUTHORIZATION_CODE = 'client_credentials'
MANAGEMENT_RESOURCE = 'https://management.azure.com'
VAULT_RESOURCE = 'https://vault.azure.net'


class Client:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 subscription_id: str, resource_group_name: str,
                 verify: bool, proxy: bool):
        self._headers = {
            'Content-Type': 'application/json'
        }
        base_url = f'https://management.azure.com/subscriptions/{subscription_id}/' \
                   f'resourceGroups/{resource_group_name}/providers/Microsoft.KeyVault'
        self.ms_client = MicrosoftClient(
            self_deployed=True,
            auth_id=client_id,
            enc_key=client_secret,
            token_retrieval_url=f'https://login.microsoftonline.com/{tenant_id}/oauth2/token',
            grant_type='client_credentials',
            app_name=APP_NAME,
            base_url=base_url,
            verify=verify,
            # resources=[MANAGEMENT_RESOURCE, VAULT_RESOURCE],
            resource=MANAGEMENT_RESOURCE,
            tenant_id=tenant_id,
            ok_codes=(200, 201, 202, 204, 400, 401, 403, 404)
        )
    def _http_request(self, method, url_suffix=None, full_url=None, params=None, data=None):
        if not params:
            params = {}
        if not full_url:
            params['api-version'] = API_VERSION

        res = self.ms_client.http_request(method=method,  # disable-secrets-detection
                                          url_suffix=url_suffix,
                                          full_url=full_url,
                                          json_data=data,
                                          params=params,
                                          resp_type='response'
                                    )
        res_json = res.json()

        return res_json

    """ Helper integration commands"""

    def create_or_update_key_vault_request(self, tenant_id, location, properties, tags, family, name, object_id, keys,
                                           secrets, certificates, enabled_for_deployment, enabled_for_disk_encryption,
                                           enabled_for_template_deployment):
        # TODO: think about how to enter the body from command line
        data = {"location": location, "properties": {"accessPolicies": [
            {"objectId": object_id, "permissions": {"certificates": certificates, "keys": keys, "secrets": secrets},
             "tenantId": tenant_id}],
            "enabledForDeployment": enabled_for_deployment,
            "enabledForDiskEncryption": enabled_for_disk_encryption,
            "enabledForTemplateDeployment": enabled_for_template_deployment,
            "sku": {"family": family, "name": name}, "tenantId": tenant_id}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', '?api-version=2019-09-01', json_data=data, headers=headers)

        return response

    def delete_key_vault_request(self, vault_name):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('DELETE', '', headers=headers)

        return response

    def get_key_vault_request(self, vault_name: str):
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        response = self._http_request('GET', '', headers=headers)

        return response

    def list_key_vaults_request(self):
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        url_suffix = '/vaults'
        response = self._http_request('GET', url_suffix=url_suffix)

        return response

    def update_access_policy_request(self, tenant_id, location, properties, tags, family, name, object_id, keys,
                                     secrets, certificates, enabled_for_deployment, enabled_for_disk_encryption,
                                     enabled_for_template_deployment):
        data = {"properties": {"accessPolicies": [{"objectId": object_id, "permissions": {
            "certificates": [], "keys": [], "secrets": []}, "tenantId": tenant_id}]}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', '', json_data=data, headers=headers)

        return response

    def get_key_request(self, vault_name, key_name):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', '/keys/?api-version=7.2', headers=headers)

        return response

    def list_keys_request(self, vault_name):
        url = f'https://{vault_name}.vault.azure.net/keys?api-version=7.2'
        response = self.ms_client.http_request('GET', full_url=url, resource=VAULT_RESOURCE)

        return response

    def delete_key_request(self, vault_name, key_name):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'DELETE', f'https://{vault_name}.vault.azure.net/keys/{key_name}?api-version=7.2', headers=headers)

        return response

    def get_secret_request(self, vault_name, secret_name):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'GET', f'?api-version=7.2', headers=headers)

        return response

    def list_secrets_request(self, vault_name):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', f'/secrets?api-version=7.2', headers=headers)

        return response

    def delete_secret_request(self, vault_name, secret_name):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'DELETE', f'https://{vault_name}.vault.azure.net/secret/{secret_name}?api-version=7.2', headers=headers)

        return response

    def get_certificate_request(self, vault_name, certificate_name):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'GET', f'/certificates/?api-version=7.2',
            headers=headers)

        return response

    def list_certificates_request(self, vault_name, max_results):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', f'/certificates?api-version=7.2', headers=headers)

        return response

    def delete_certificate_request(self, vault_name, certificate_name):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'DELETE', f'https://{vault_name}.vault.azure.net/certificate/{certificate_name}?api-version=7.2',
            headers=headers)

        return response


def create_or_update_key_vault_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    tenant_id = args.get('tenant_id')
    location = args.get('location', 'westus')
    properties = args.get('properties')
    tags = args.get('tags')
    family = args.get('family')
    name = args.get('name')
    object_id = args.get('object_id')
    keys = args.get('keys')
    secrets = args.get('secrets')
    certificates = args.get('certificates')
    enabled_for_deployment = args.get('enabled_for_deployment')
    enabled_for_disk_encryption = args.get('enabled_for_disk_encryption')
    enabled_for_template_deployment = args.get('enabled_for_template_deployment')

    response = client.create_or_update_key_vault_request(tenant_id, location, properties, tags, family, name, object_id,
                                                         keys, secrets, certificates, enabled_for_deployment,
                                                         enabled_for_disk_encryption, enabled_for_template_deployment)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.KeyVault',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_key_vault_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    vault_name = args.get('vault_name')

    response = client.delete_key_vault_request(vault_name)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.KeyVault',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_key_vault_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    vault_name = args.get('vault_name')

    response = client.get_key_vault_request(vault_name)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.KeyVault',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def list_key_vaults_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    response = client.list_key_vaults_request()
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.KeyVault',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_access_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    tenant_id = args.get('tenant_id')
    location = args.get('location')
    properties = args.get('properties')
    tags = args.get('tags')
    family = args.get('family')
    name = args.get('name')
    object_id = args.get('object_id')
    keys = args.get('keys')
    secrets = args.get('secrets')
    certificates = args.get('certificates')
    enabled_for_deployment = argToBoolean(args.get('enabled_for_deployment'))
    enabled_for_disk_encryption = argToBoolean(args.get('enabled_for_disk_encryption'))
    enabled_for_template_deployment = argToBoolean(args.get('enabled_for_template_deployment'))

    response = client.update_access_policy_request(tenant_id, location, properties, tags, family, name, object_id, keys,
                                                   secrets, certificates, enabled_for_deployment,
                                                   enabled_for_disk_encryption, enabled_for_template_deployment)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.VaultAccessPolicy',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_key_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    vault_name = args.get('vault_name')
    key_name = args.get('key_name')

    response = client.get_key_request(vault_name, key_name)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Key',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def list_keys_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    vault_name = args.get('vault_name')

    response = client.list_keys_request(vault_name)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Key',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_key_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    vault_name = args.get('vault_name')
    key_name = args.get('key_name')

    response = client.delete_key_request(vault_name, key_name)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Key',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_secret_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    vault_name = args.get('vault_name')
    secret_name = args.get('secret_name')

    response = client.get_secret_request(vault_name, secret_name)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Secret',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def list_secrets_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    vault_name = args.get('vault_name')

    response = client.list_secrets_request(vault_name)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Key',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_secret_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    vault_name = args.get('vault_name')
    secret_name = str(args.get('secret_name'))

    response = client.delete_secret_request(vault_name, secret_name)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Secret',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_certificate_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    vault_name = args.get('vault_name')
    certificate_name = args.get('certificate_name')

    response = client.get_certificate_request(vault_name, certificate_name)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Certificate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def list_certificates_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    vault_name = args.get('vault_name')
    max_results = int(args.get('max_results', 10))

    response = client.list_certificates_request(vault_name, max_results)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Certificate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_certificate_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    vault_name = args.get('vault_name')
    certificate_name = args.get('certificate_name')

    response = client.delete_certificate_request(vault_name, certificate_name)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Certificate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    # Test functions here
    return_results('ok')


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    headers = {}

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(tenant_id=params.get('tenant_id', None),
                                client_id=params.get('client_id', None),
                                client_secret=params.get('client_secret', None),
                                subscription_id=params.get('subscription_id', None),
                                resource_group_name=params.get('resource_group_name', None),
                                verify=params.get('verify'),
                                proxy=params.get('proxy'))

        commands = {
            'azure-key-vault-create-or-update-key-vault': create_or_update_key_vault_command,
            'azure-key-vault-delete-key-vault': delete_key_vault_command,
            'azure-key-vault-get-key-vault': get_key_vault_command,
            'azure-key-vault-list-key-vaults': list_key_vaults_command,
            'azure-key-vault-update-access-policy': update_access_policy_command,
            'azure-key-vault-get-key': get_key_command,
            'azure-key-vault-list-keys': list_keys_command,
            'azure-key-vault-delete-key': delete_key_command,
            'azure-key-vault-get-secret': get_secret_command,
            'azure-key-vault-list-secrets': list_secrets_command,
            'azure-key-vault-delete-secret': delete_secret_command,
            'azure-key-vault-get-certificate': get_certificate_command,
            'azure-key-vault-list-certificates': list_certificates_command,
            'azure-key-vault-delete-certificate': delete_certificate_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


##### Microdosft client code ########

import traceback

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import re
import base64
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict, Tuple, List, Optional


class Scopes:
    graph = 'https://graph.microsoft.com/.default'
    security_center = 'https://api.securitycenter.windows.com/.default'


# authorization types
OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'

# grant types in self-deployed authorization
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'  # guardrails-disable-line
DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code'
REGEX_SEARCH_URL = r'(?P<url>https?://[^\s]+)'
SESSION_STATE = 'session_state'


class MicrosoftClient(BaseClient):
    def __init__(self, tenant_id: str = '',
                 auth_id: str = '',
                 enc_key: str = '',
                 token_retrieval_url: str = 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
                 app_name: str = '',
                 refresh_token: str = '',
                 auth_code: str = '',
                 scope: str = 'https://graph.microsoft.com/.default',
                 grant_type: str = CLIENT_CREDENTIALS,
                 redirect_uri: str = 'https://localhost/myapp',
                 resource: Optional[str] = '',
                 multi_resource: bool = False,
                 resources: List[str] = None,
                 verify: bool = True,
                 self_deployed: bool = False,
                 azure_ad_endpoint: str = 'https://login.microsoftonline.com',
                 *args, **kwargs):
        """
        Microsoft Client class that implements logic to authenticate with oproxy or self deployed applications.
        It also provides common logic to handle responses from Microsoft.
        Args:
            tenant_id: If self deployed it's the tenant for the app url, otherwise (oproxy) it's the token
            auth_id: If self deployed it's the client id, otherwise (oproxy) it's the auth id and may also
            contain the token url
            enc_key: If self deployed it's the client secret, otherwise (oproxy) it's the encryption key
            scope: The scope of the application (only if self deployed)
            resource: The resource of the application (only if self deployed)
            multi_resource: Where or not module uses a multiple resources (self-deployed, auth_code grant type only)
            resources: Resources of the application (for multi-resource mode)
            verify: Demisto insecure parameter
            self_deployed: Indicates whether the integration mode is self deployed or oproxy
        """
        super().__init__(verify=verify, *args, **kwargs)  # type: ignore[misc]
        if not self_deployed:
            auth_id_and_token_retrieval_url = auth_id.split('@')
            auth_id = auth_id_and_token_retrieval_url[0]
            if len(auth_id_and_token_retrieval_url) != 2:
                self.token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token'  # guardrails-disable-line
            else:
                self.token_retrieval_url = auth_id_and_token_retrieval_url[1]

            self.app_name = app_name
            self.auth_id = auth_id
            self.enc_key = enc_key
            self.tenant_id = tenant_id
            self.refresh_token = refresh_token

        else:
            self.token_retrieval_url = token_retrieval_url.format(tenant_id=tenant_id)
            self.client_id = auth_id
            self.client_secret = enc_key
            self.tenant_id = tenant_id
            self.auth_code = auth_code
            self.grant_type = grant_type
            self.resource = resource
            self.scope = scope
            self.redirect_uri = redirect_uri

        self.auth_type = SELF_DEPLOYED_AUTH_TYPE if self_deployed else OPROXY_AUTH_TYPE
        self.verify = verify
        self.azure_ad_endpoint = azure_ad_endpoint

        self.multi_resource = multi_resource
        if self.multi_resource:
            self.resources = resources if resources else []
            self.resource_to_access_token: Dict[str, str] = {}

    def http_request(
            self, *args, resp_type='json', headers=None,
            return_empty_response=False, scope: Optional[str] = None,
            resource: str = '', **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.
        Args:
            resp_type: Type of response to return. will be ignored if `return_empty_response` is True.
            headers: Headers to add to the request.
            return_empty_response: Return the response itself if the return_code is 206.
            scope: A scope to request. Currently will work only with self-deployed app.
            resource (str): The resource identifier for which the generated token will have access to.
        Returns:
            Response from api according to resp_type. The default is `json` (dict or list).
        """
        if 'ok_codes' not in kwargs:
            kwargs['ok_codes'] = (200, 201, 202, 204, 206, 404)
        token = self.get_access_token(resource=resource, scope=scope)

        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if headers:
            default_headers.update(headers)
        response = super()._http_request(  # type: ignore[misc]
            *args, resp_type="response", headers=default_headers, **kwargs)

        # 206 indicates Partial Content, reason will be in the warning header.
        # In that case, logs with the warning header will be written.
        if response.status_code == 206:
            demisto.debug(str(response.headers))
        is_response_empty_and_successful = (response.status_code == 204)
        if is_response_empty_and_successful and return_empty_response:
            return response

        # Handle 404 errors instead of raising them as exceptions:
        if response.status_code == 404:
            try:
                error_message = response.json()
            except Exception:
                error_message = 'Not Found - 404 Response'
            raise NotFoundError(error_message)

        try:
            if resp_type == 'json':
                return response.json()
            if resp_type == 'text':
                return response.text
            if resp_type == 'content':
                return response.content
            if resp_type == 'xml':
                ET.parse(response.text)
            return response
        except ValueError as exception:
            raise DemistoException('Failed to parse json object from response: {}'.format(response.content), exception)

    def get_access_token(self, resource: str = '', scope: Optional[str] = None) -> str:
        """
        Obtains access and refresh token from oproxy server or just a token from a self deployed app.
        Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.
        Args:
            resource (str): The resource identifier for which the generated token will have access to.
            scope (str): A scope to get instead of the default on the API.
        Returns:
            str: Access token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        print("context:", integration_context)
        refresh_token = integration_context.get('current_refresh_token', '')
        # Set keywords. Default without the scope prefix.
        access_token_keyword = f'{scope}_access_token' if scope else 'access_token'
        valid_until_keyword = f'{scope}_valid_until' if scope else 'valid_until'

        if self.multi_resource:
            access_token = integration_context.get(resource)
        else:
            access_token = integration_context.get(access_token_keyword)

        valid_until = integration_context.get(valid_until_keyword)
        print('access token:', access_token)
        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        auth_type = self.auth_type
        if auth_type == OPROXY_AUTH_TYPE:
            if self.multi_resource:
                for resource_str in self.resources:
                    access_token, expires_in, refresh_token = self._oproxy_authorize(resource_str)
                    self.resource_to_access_token[resource_str] = access_token
                    self.refresh_token = refresh_token
            else:
                access_token, expires_in, refresh_token = self._oproxy_authorize(scope=scope)

        else:
            access_token, expires_in, refresh_token = self._get_self_deployed_token(
                refresh_token, scope, integration_context)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer
        valid_until = time_now + expires_in
        integration_context.update({
            access_token_keyword: access_token,
            valid_until_keyword: valid_until,
            'current_refresh_token': refresh_token
        })

        # Add resource access token mapping
        if self.multi_resource:
            integration_context.update(self.resource_to_access_token)

        set_integration_context(integration_context)

        if self.multi_resource:
            return self.resource_to_access_token[resource]

        return access_token

    def _oproxy_authorize(self, resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing with oproxy.
        Args:
            scope: A scope to add to the request. Do not use it.
            resource: Resource to get.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        content = self.refresh_token or self.tenant_id
        headers = self._add_info_headers()
        oproxy_response = requests.post(
            self.token_retrieval_url,
            headers=headers,
            json={
                'app_name': self.app_name,
                'registration_id': self.auth_id,
                'encrypted_token': self.get_encrypted(content, self.enc_key),
                'scope': scope
            },
            verify=self.verify
        )

        if not oproxy_response.ok:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    oproxy_response.status_code, oproxy_response.reason, oproxy_response.text))
                err_response = oproxy_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                    elif detail:
                        server_msg = detail
                if server_msg:
                    msg += ' Server message: {}'.format(server_msg)
            except Exception as ex:
                demisto.error('Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)
        try:
            gcloud_function_exec_id = oproxy_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = oproxy_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Oproxy server did not contain the expected content.'
            )

        return (parsed_response.get('access_token', ''), parsed_response.get('expires_in', 3595),
                parsed_response.get('refresh_token', ''))

    def _get_self_deployed_token(self,
                                 refresh_token: str = '',
                                 scope: Optional[str] = None,
                                 integration_context: Optional[dict] = None
                                 ) -> Tuple[str, int, str]:
        if self.grant_type == AUTHORIZATION_CODE:
            if not self.multi_resource:
                return self._get_self_deployed_token_auth_code(refresh_token, scope=scope)
            else:
                expires_in = -1  # init variable as an int
                for resource in self.resources:
                    access_token, expires_in, refresh_token = self._get_self_deployed_token_auth_code(refresh_token,
                                                                                                      resource)
                    self.resource_to_access_token[resource] = access_token

                return '', expires_in, refresh_token
        elif self.grant_type == DEVICE_CODE:
            return self._get_token_device_code(refresh_token, scope, integration_context)
        else:
            # by default, grant_type is CLIENT_CREDENTIALS
            return self._get_self_deployed_token_client_credentials(scope=scope)

    def _get_self_deployed_token_client_credentials(self, scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application in client credentials grant type.
        Args:
            scope; A scope to add to the headers. Else will get self.scope.
        Returns:
            tuple: An access token and its expiry.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': CLIENT_CREDENTIALS
        }

        # Set scope.
        if self.scope or scope:
            data['scope'] = scope if scope else self.scope

        if self.resource:
            data['resource'] = self.resource

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))

        return access_token, expires_in, ''

    def _get_self_deployed_token_auth_code(
            self, refresh_token: str = '', resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            resource=self.resource if not resource else resource,
            redirect_uri=self.redirect_uri
        )

        if scope:
            data['scope'] = scope

        refresh_token = refresh_token or self._get_refresh_token_from_auth_code_param()
        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            if SESSION_STATE in self.auth_code:
                raise ValueError('Malformed auth_code parameter: Please copy the auth code from the redirected uri '
                                 'without any additional info and without the "session_state" query parameter.')
            data['grant_type'] = AUTHORIZATION_CODE
            data['code'] = self.auth_code

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_token_device_code(
            self, refresh_token: str = '', scope: Optional[str] = None, integration_context: Optional[dict] = None
    ) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = {
            'client_id': self.client_id,
            'scope': scope
        }

        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            data['grant_type'] = DEVICE_CODE
            if integration_context:
                data['code'] = integration_context.get('device_code')

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_refresh_token_from_auth_code_param(self) -> str:
        refresh_prefix = "refresh_token:"
        if self.auth_code.startswith(refresh_prefix):  # for testing we allow setting the refresh token directly
            demisto.debug("Using refresh token set as auth_code")
            return self.auth_code[len(refresh_prefix):]
        return ''

    @staticmethod
    def error_parser(error: requests.Response) -> str:
        """
        Args:
            error (requests.Response): response with error
        Returns:
            str: string of error
        """
        try:
            response = error.json()
            demisto.error(str(response))
            inner_error = response.get('error', {})
            if isinstance(inner_error, dict):
                err_str = f"{inner_error.get('code')}: {inner_error.get('message')}"
            else:
                err_str = inner_error
            if err_str:
                return err_str
            # If no error message
            raise ValueError
        except ValueError:
            return error.text

    @staticmethod
    def epoch_seconds(d: datetime = None) -> int:
        """
        Return the number of seconds for given date. If no date, return current.
        Args:
            d (datetime): timestamp
        Returns:
             int: timestamp in epoch
        """
        if not d:
            d = MicrosoftClient._get_utcnow()
        return int((d - MicrosoftClient._get_utcfromtimestamp(0)).total_seconds())

    @staticmethod
    def _get_utcnow() -> datetime:
        return datetime.utcnow()

    @staticmethod
    def _get_utcfromtimestamp(_time) -> datetime:
        return datetime.utcfromtimestamp(_time)

    @staticmethod
    def get_encrypted(content: str, key: str) -> str:
        """
        Encrypts content with encryption key.
        Args:
            content: Content to encrypt
            key: encryption key from oproxy
        Returns:
            timestamp: Encrypted content
        """

        def create_nonce():
            return os.urandom(12)

        def encrypt(string, enc_key):
            """
            Encrypts string input with encryption key.
            Args:
                string: String to encrypt
                enc_key: Encryption key
            Returns:
                bytes: Encrypted value
            """
            # String to bytes
            try:
                enc_key = base64.b64decode(enc_key)
            except Exception as err:
                return_error(f"Error in Microsoft authorization: {str(err)}"
                             f" Please check authentication related parameters.", error=traceback.format_exc())

            # Create key
            aes_gcm = (enc_key)
            # Create nonce
            nonce = create_nonce()
            # Create ciphered data
            data = string.encode()
            ct = aes_gcm.encrypt(nonce, data, None)
            return base64.b64encode(nonce + ct)

        now = MicrosoftClient.epoch_seconds()
        encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
        return encrypted

    @staticmethod
    def _add_info_headers() -> Dict[str, str]:
        # pylint: disable=no-member
        headers = {}
        try:
            headers = get_x_content_info_headers()
        except Exception as e:
            demisto.error('Failed getting integration info: {}'.format(str(e)))

        return headers

    def device_auth_request(self) -> dict:
        response_json = {}
        try:
            response = requests.post(
                url=f'{self.azure_ad_endpoint}/organizations/oauth2/v2.0/devicecode',
                data={
                    'client_id': self.client_id,
                    'scope': self.scope
                },
                verify=self.verify
            )
            if not response.ok:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')
        set_integration_context({'device_code': response_json.get('device_code')})
        return response_json

    def start_auth(self, complete_command: str) -> str:
        response = self.device_auth_request()
        message = response.get('message', '')
        re_search = re.search(REGEX_SEARCH_URL, message)
        url = re_search.group('url') if re_search else None
        user_code = response.get('user_code')

        return f"""### Authorization instructions
1. To sign in, use a web browser to open the page [{url}]({url})
and enter the code **{user_code}** to authenticate.
2. Run the **{complete_command}** command in the War Room."""


class NotFoundError(Exception):
    """Exception raised for 404 - Not Found errors.
    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message

if __name__ in ["builtins", "__main__"]:
    main()
