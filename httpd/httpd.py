import asyncio
import os

try:
    from aiohttp import web
except ImportError:
    web = None


class Httpd(object):
    def __init__(self):
        if not web:
            print('httpd is specified in conf but aiohttp not available')
            return

        self.app = web.Application()
        self._setup_routes()
        self._run_app()
        self.api_callback = None

    def _run_app(self):
        loop = asyncio.get_event_loop()
        handler = self.app.make_handler()
        f = loop.create_server(handler, 'localhost', 9000)
        srv = loop.run_until_complete(f)
        print('serving on', srv.sockets[0].getsockname())

    def register_api_callback(self, callback):
        self.api_callback = callback

    async def handler_index(self, request):
        data = '''
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta content="width=device-width" name="viewport">
    <meta content="yes" name="apple-mobile-web-app-capable">
    <meta content="IE=edge,chrome=1" http-equiv="X-UA-Compatible">
    <title>DMPR</title>
      <script type="text/javascript" src="static/js/vis.min.js"></script>
      <script type="text/javascript" src="static/js/script.js"></script>

      <link href="static/css/bootstrap-3.3.6.css" rel="stylesheet" />
      <link href="static/css/style.css" rel="stylesheet" />
      <link href="static/css/vis.min.css" rel="stylesheet" type="text/css" />
      <link href="static/css/style.css" rel="stylesheet" type="text/css" />
  </head>
  <body>
		<div class="container-fluid">
			<div class="row">
				<div class="col-sm-3 col-lg-2">
					<nav class="navbar navbar-default navbar-fixed-side">
            <div class="container">
              <div class="navbar-header">
                <button class="navbar-toggle" data-target=".navbar-collapse" data-toggle="collapse">
                  <span class="sr-only">Toggle navigation</span>
                  <span class="icon-bar"></span>
                  <span class="icon-bar"></span>
                  <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="./">DMPR</a>
              </div>
              <div class="collapse navbar-collapse">
                <ul class="nav navbar-nav">
                  <li class="active"><a href="#">Topology</a></li>
                  <li class=""><a href="#">Logging</a></li>
                </ul>
              </div>
            </div>
					</nav>
				</div>
				<div class="col-sm-9 col-lg-10 content">
                    <div id="mynetwork"></div>
				</div>
			</div>
		</div>
    <script src="static/js/bootstrap-3.3.6.js"></script>
  </body>
</html>
        '''
        data = str.encode(data)
        return web.Response(body=data, content_type='text/html')

    async def handle_api(self, request):
        jsonData = await request.json()
        if self.api_callback is not None:
            self.api_callback(jsonData)

        return web.Response()

    def _setup_routes(self):
        absdir = os.path.dirname(os.path.realpath(__file__))
        app_path = os.path.join(absdir, 'www', 'static')
        self.app.router.add_get('/', self.handler_index)
        self.app.router.add_static('/static', app_path, show_index=True)
        self.app.add_routes([web.get('/api/v1/dlep-update', self.handle_api),
                             web.post('/api/v1/dlep-update', self.handle_api)])
