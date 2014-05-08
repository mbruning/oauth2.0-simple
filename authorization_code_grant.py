import ssl
import urlparse
import signal

from multiprocessing.process import Process
from wsgiref.simple_server import make_server, WSGIRequestHandler
import httplib2

from oauth2 import Provider
from oauth2.error import UserNotAuthenticated
from oauth2.store.memory import ClientStore, TokenStore
from oauth2.tokengenerator import Uuid4
from oauth2.web import SiteAdapter, Wsgi
from oauth2.grant import AuthorizationCodeGrant
from oauth2client.client import OAuth2WebServerFlow


class ClientRequestHandler(WSGIRequestHandler):
    """
    Request handler that enables formatting of the log messages on the console.
    
    This handler is used by the client application.
    """

    def address_string(self):
        return "client app"


class OAuthRequestHandler(WSGIRequestHandler):
    """
    Request handler that enables formatting of the log messages on the console.
    
    This handler is used by the python-oauth2 application.
    """

    def address_string(self):
        return "python-oauth2"


class TestSiteAdapter(SiteAdapter):
    """
    This adapter renders a confirmation page so the user can confirm the auth
    request.
    """

    CONFIRMATION_TEMPLATE = """
<html>
    <body>
        <form method="POST" name="confirmation_form">
            <input name="confirm" type="hidden" value="1" />
            <div>
                <input type="submit" value="confirm" />
            </div>
        </form>
        <form method="POST" name="confirmation_form">
            <input name="confirm" type="hidden" value="0" />
            <div>
                <input type="submit" value="deny" />
            </div>
        </form>
    </body>
</html>
    """

    def render_auth_page(self, request, response, environ, scopes):
        response.body = self.CONFIRMATION_TEMPLATE

        return response

    def authenticate(self, request, environ, scopes):
        if request.method == "POST":
            if request.post_param("confirm") is "1":
                return
        raise UserNotAuthenticated

    def user_has_denied_access(self, request):
        if request.method == "POST":
            if request.post_param("confirm") is "0":
                return True
        return False


class ClientApplication(object):
    """
    Very basic application that simulates calls to the oauth server
    """
    client_id = "abc"
    client_secret = "xyz"
    api_server_url = "http://localhost:8080"
    scope = "somescope"
    redirect_uri = "http://localhost:8081/callback"
    auth_uri = "https://localhost:8080/authorize"
    token_uri = "https://localhost:8080/token"

    def __init__(self):
        self.access_token = None
        self.auth_code = None
        self.token_type = ""
        # instantiate the oauth2.0 flow
        self.flow = OAuth2WebServerFlow(client_id=self.client_id,
                                        client_secret=self.client_secret,
                                        scope="somescope",
                                        redirect_uri=self.redirect_uri,
                                        auth_uri=self.auth_uri,
                                        token_uri=self.token_uri)

    def __call__(self, env, start_response):
        if env["PATH_INFO"] == "/app":
            status, body, headers = self._serve_application()
        elif env["PATH_INFO"] == "/callback":
            status, body, headers = self._read_auth_token(env)
        else:
            status = "301 Moved"
            body = ""
            headers = {"Location": "/app"}

        start_response(status,
                       [(header, val) for header, val in headers.iteritems()])
        return body

    def _request_access_token(self):
        print("Requesting access token...")

        http = httplib2.Http(disable_ssl_certificate_validation=True)
        # 2nd step of oauth flow: exchange auth token for access token
        credentials = self.flow.step2_exchange(self.auth_code, http)

        self.access_token = credentials.access_token
        self.token_type = credentials.token_response["token_type"]

        confirmation = "Received access token '%s' of type '%s'" % (self.access_token, self.token_type)
        print(confirmation)
        return "302 Found", "", {"Location": "/app"}

    def _read_auth_token(self, env):
        print("Receiving authorization code...")

        query_params = urlparse.parse_qs(env["QUERY_STRING"])
        if query_params.get("error"):
            return "302 Found", "", {"Location": "/app"}
        self.auth_code = query_params["code"][0]

        print("Received temporary authorization token '%s'" % (self.auth_code,))

        return "302 Found", "", {"Location": "/app"}

    def _request_auth_token(self):
        print("Requesting authorization code...")
        # this is step 1 of the oauth2.0 flow, get the code
        auth_uri = self.flow.step1_get_authorize_url()

        return "302 Found", "", {"Location": auth_uri}

    def _serve_application(self):
        if self.access_token is None:
            if self.auth_code is None:
                return self._request_auth_token()
            else:
                return self._request_access_token()
        else:
            confirmation = "Current access token '%s' of type '%s'" % (self.access_token, self.token_type)
            return "200 OK", str(confirmation), {}


def run_app_server():
    app = ClientApplication()

    try:
        httpd = make_server('', 8081, app, handler_class=ClientRequestHandler)

        print("Starting Authorization Code Grant client app on http://localhost:8081/...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()


def run_auth_server():
    try:
        client_store = ClientStore()
        client_store.add_client(client_id="abc", client_secret="xyz",
                                redirect_uris=["http://localhost:8081/callback"])

        token_store = TokenStore()

        auth_controller = Provider(
            access_token_store=token_store,
            auth_code_store=token_store,
            client_store=client_store,
            site_adapter=TestSiteAdapter(),
            token_generator=Uuid4())
        auth_controller.add_grant(AuthorizationCodeGrant())

        app = Wsgi(server=auth_controller)

        httpd = make_server('', 8080, app, handler_class=OAuthRequestHandler)
        httpd.socket = ssl.wrap_socket(httpd.socket, certfile='/home/marc/server.pem', server_side=True)

        print("Starting implicit_grant oauth2 server on https://localhost:8080/...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()


def main():
    auth_server = Process(target=run_auth_server)
    auth_server.start()
    app_server = Process(target=run_app_server)
    app_server.start()
    print("Access http://localhost:8081/app in your browser")

    def sigint_handler(signal, frame):
        print("Terminating servers...")
        auth_server.terminate()
        auth_server.join()
        app_server.terminate()
        app_server.join()

    signal.signal(signal.SIGINT, sigint_handler)


if __name__ == "__main__":
    main()
