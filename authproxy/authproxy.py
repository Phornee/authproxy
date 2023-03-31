""" Class to perform authentication using the synology authmethods """
import os
import time
from urllib import parse
import json
from pathlib import Path
import secrets
import jinja2
import requests
from flask import request, make_response, Response, send_from_directory

from .auth_config import mapping


COOKIE_LIFE_MINUTES = 15


class AuthProxy():
    """ 
    Class to manage the authentication. 
    The path_redirect function should be called from a '/<path:path>' flask rule
    Also a rule '/' should call this function like this:  return self.auth_proxy.path_redirect("/")
    """
    def __init__(self) -> None:
        """
        """
        self.cookie_folder = os.path.join(Path(__file__).parent.resolve(), 'cookies')

    def _build_cookie(self, req: request) -> tuple:
        host = mapping.get(req.host).get('host')
        endpoint = mapping.get(req.host).get('endpoint')
        method = mapping.get(req.host).get('method')
        params = req.query_string.decode("utf-8")

        # Stores the internal URL into a cookie file to be read later
        cookie_name = secrets.token_urlsafe(16)
        ser_head = {}
        for head in req.headers:
            ser_head[head[0]] = head[1]
        headers = json.dumps(ser_head)
        content = str(req.data)
        cookie = {'host': host,
                  'endpoint': endpoint, 
                  'method': method,
                  'params': params, 
                  'headers': headers,
                  'content': content}

        return cookie, cookie_name

    def _write_cookie(self, cookie: dict, cookie_name: str):
        cookie_path = os.path.join(self.cookie_folder, cookie_name)
        with open(cookie_path, 'w', encoding="utf-8") as cookie_file:
            json.dump(cookie, cookie_file)

    def _clear_expired_cookies(self):
        for filename in os.listdir(self.cookie_folder):
            filepath = os.path.join(self.cookie_folder, filename)
            # checking if it is a file
            if os.path.isfile(filepath):
                age = time.time() - os.path.getmtime(filepath)
                if age > COOKIE_LIFE_MINUTES*60:
                    os.remove(filepath)

    def _build_auth_popup(self, cookie_name: str):
        # Get the auth html form template and send back to the user, so he can authenticate
        form_path = os.path.join(Path(__file__).parent.resolve(), 'templates', 'form.html')
        with open(form_path, 'r', encoding="utf8") as form:
            buff = form.read()
            # replace the cookie name
            env = jinja2.Environment()
            template = env.from_string(buff)
            content = template.render(token=cookie_name)
            return make_response(content)

    def _get_local_cookie(self, token:str = None):
        cookie = None
        if token:
            cookie_path = os.path.join(self.cookie_folder, token)
            if os.path.exists(cookie_path):
                with open(cookie_path, 'r', encoding="utf-8") as cookie_file:
                    cookie = json.load(cookie_file)

                    cookie['headers'] = json.loads(cookie['headers'])
        return cookie

    def _credentials_valid(self, form):
        token = form.get('token', None)
        if token:
            user = form.get('user', None)
            password = form.get('password', None)
            otp = form.get('OTP', None)
            url = (f'https://phornee.synology.me:6121/webapi/entry.cgi?api=SYNO.API.Auth&version=6&method=login'
                  f'&account={user}&passwd={password}&otp_code={otp}')
            auth_response = requests.get(url, timeout=10)
            # Verify authentication
            return True
            return auth_response.json()['success']
        return False

    def _get_inner_get_response(self, host, endpoint, params, headers):
        fullpath = parse.urljoin(host, endpoint)
        resp = requests.get(fullpath,
                            params=params,
                            headers = headers,
                            timeout=10)
        return Response(resp.text, status=resp.status_code, content_type=resp.headers['content-type'])

    def _get_inner_post_response(self, host, endpoint, data, headers):
        fullpath = parse.urljoin(host, endpoint)
        resp = requests.post(fullpath,
                             data = data,
                             headers = headers,
                             timeout=10)
        return Response(resp.text, status=resp.status_code, content_type=resp.headers['content-type']) 

    def _reask_credentials(self, req: request, old_cookie_name: str = None) -> Response:
        new_cookie, new_cookie_name = self._build_cookie(req)
        self._clear_expired_cookies() # Housekeeping
        print(f'Creating new cookie {new_cookie_name}')
        self._write_cookie(new_cookie, new_cookie_name)
        response = self._build_auth_popup(new_cookie_name)
        if old_cookie_name:
            print(f'Deleting cookie in response: {old_cookie_name}')
            response.delete_cookie('token', req.host)
        return response

    def path_redirect(self, path) -> Response:
        """Main entry point
        Returns:
            http_response: response string
        """
        print(f'---------------------- Path requested: {path} --------------------')
        if path == 'favicon.ico':
            cookie, cookie_name = self._build_cookie(request)
            print(f"favicon.ico requested: Directly returning from inner endpoint {cookie['host']}")
            return self._get_inner_get_response(host=cookie['host'],
                                                endpoint=path,
                                                params=request.query_string.decode("utf-8"),
                                                headers=request.headers)

        if path == 'authproxy_static/css/view.css':
            full_path = os.path.join(Path(__file__).parent.resolve())
            return send_from_directory(full_path, path)

        # Try to get authentication from the cookie
        cookie_name = request.cookies.get('token', None)
        print(f'Incomming Cookie name: {cookie_name}')
        if cookie_name:  # We get a token... lets verify if its legitimate, and still alive
            cookie = self._get_local_cookie(cookie_name)
            if cookie: # Already authenticated --> Lets tunnel info back to client
                print(f'AUTHENTICATED: Cookie {cookie_name} exists in local')
                if path == '/': # If path is the root, lets go to the configured initial entrypoint.
                    method = cookie['method']
                    path = cookie['endpoint']
                    headers = {}
                    if method == 'GET':
                        params = cookie['params']
                    else:
                        data = cookie['content']
                else:
                    method = request.method
                    headers = request.headers
                    params = request.query_string.decode("utf-8")
                    data = request.get_data()
                # Lets get the response from the internal host, and tunnel it back to client
                if method == 'GET':
                    response = self._get_inner_get_response(host=cookie['host'],
                                                            endpoint=path,
                                                            params=params,
                                                            headers=headers)
                else:
                    response = self._get_inner_post_response(host=cookie['host'],
                                                             endpoint=path,
                                                             data=data,
                                                             headers=headers)
            else: # We got a token, but its no longer valid --> ask again for credentials
                print(f'NOT AUTHENTICATED: Cookie {cookie_name} DOESNT exist in local')
                response = self._reask_credentials(request, cookie_name)
        else:  # Not authenticated yet... lets pop the authentication popup to the user
            print('Not authenticated yet')
            cookie_name = request.form.get('token', None) if request.form.get('from_auth') else None
            cookie = self._get_local_cookie(cookie_name)
            if cookie:
                print(f'Local cookie {cookie_name} still alive')
                if self._credentials_valid(request.form):
                    print('Credentials validated by synology NAS')
                    # Search for the cookie and redirect to related URL if present
                    if cookie['method'] == 'GET':
                        response = self._get_inner_get_response(cookie['host'],
                                                                cookie['endpoint'],
                                                                cookie['params'],
                                                                {})
                    else:
                        response = self._get_inner_post_response(cookie['host'],
                                                                    cookie['endpoint'],
                                                                    cookie['content'],
                                                                    {})
                    response.set_cookie('token', cookie_name, max_age=COOKIE_LIFE_MINUTES*60)
                else: # We come from the auth popup, but credentials are invalid --> ask again for credentials
                    print('Credentials rejected by synology NAS. Reopening auth popup')
                    response = self._build_auth_popup(cookie_name)
            else: # We got a token, but its no longer valid --> ask again for credentials
                print('Local cookie expired. Reopening auth popup')
                response = self._reask_credentials(request, cookie_name)

        return response
