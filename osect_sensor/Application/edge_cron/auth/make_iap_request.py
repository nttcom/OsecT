import google.auth
import google.auth.app_engine
import google.auth.compute_engine.credentials
import google.auth.iam
from google.auth.transport.requests import Request
import google.oauth2.credentials
from google.oauth2 import service_account
import requests
from auth.google_account import OAUTH_TOKEN_URI, SERVICE_ACCOUNT_JSON
from common.common_config import TIME_OUT_VAL


def make_iap_request(url, client_id, **kwargs):
    """
    IAP認証を行い、引数で指定されたファイルを送信する。
    :param url: 送付先のURL
    :param client_id: 認証に使うIAP_CLIENTT_ID
    :return: レスポンスコード
    """
    credentials = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_JSON)
    bootstrap_credentials = credentials.with_scopes(['https://www.googleapis.com/auth/cloud-platform'])

    bootstrap_credentials.refresh(Request())

    signer_email = bootstrap_credentials.service_account_email
    if isinstance(bootstrap_credentials,
                  google.auth.compute_engine.credentials.Credentials):
        signer = google.auth.iam.Signer(
            Request(), bootstrap_credentials, signer_email)
    else:
        signer = bootstrap_credentials.signer

    service_account_credentials = google.oauth2.service_account.Credentials(
        signer, signer_email, token_uri=OAUTH_TOKEN_URI, additional_claims={
            'target_audience': client_id
        })

    # OpenID Connect tokenを取得する
    google_open_id_connect_token = get_google_open_id_connect_token(
        service_account_credentials)

    # タイムアウト値が引数で指定されていない場合、デフォルト値を設定する
    if 'timeout' not in kwargs:
        kwargs['timeout'] = TIME_OUT_VAL

    # IAPで保護されたAPIに接続し、引数で指定されたファイルを送信する
    resp = requests.post(
        url, headers={'Authorization': 'Bearer {}'.format(google_open_id_connect_token)}, **kwargs)
    if resp.status_code == 403:
        raise Exception('Service account {} does not have permission to '
                        'access the IAP-protected application.'.format(signer_email))
    elif resp.status_code != 200:
        raise Exception(
            'Bad response from application: {!r} / {!r} / {!r}'.format(
                resp.status_code, resp.headers, resp.text))
    else:
        return resp.text


def get_google_open_id_connect_token(service_account_credentials):
    """
    OpenID Connect tokenを取得する
    :param service_account_credentials: サービスアカンとの資格情報
    :return : OpenID Connect token
    """

    service_account_jwt = (
        service_account_credentials._make_authorization_grant_assertion())
    request = google.auth.transport.requests.Request()
    body = {
        'assertion': service_account_jwt,
        'grant_type': google.oauth2._client._JWT_GRANT_TYPE,
    }
    token_response = google.oauth2._client._token_endpoint_request(request, OAUTH_TOKEN_URI, body)
    return token_response['id_token']


